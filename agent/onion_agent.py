"""OMCP ONION Node Agent / Daemon.

Secure node-side daemon responsible for:
- Authenticated HMAC-SHA256 + Bearer communication with central panel
- Real server provisioning (install scripts) & process/container lifecycle
- Real-time stdout/stderr streaming & stdin command execution via WebSockets
- Sandboxed file manager & multi-format archive manager (zip, tar, tar.gz, tgz, tar.bz2, tar.xz)
- Real backup creation, SHA-256 verification, download, and safe restoration
- Host & per-server resource telemetry
"""

import asyncio
import collections
import hashlib
import hmac
import io
import json
import mimetypes
import os
import shlex
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import Response
from pydantic import BaseModel

AGENT_TOKEN = os.environ.get("ONION_AGENT_TOKEN", "onion-dev-node-token")
AGENT_ROOT = Path(os.environ.get("ONION_AGENT_DATA_DIR", str(Path(__file__).resolve().parent.parent / "data" / "agent")))
SERVERS_DIR = AGENT_ROOT / "servers"
BACKUPS_DIR = AGENT_ROOT / "backups"
SERVERS_DIR.mkdir(parents=True, exist_ok=True)
BACKUPS_DIR.mkdir(parents=True, exist_ok=True)

AGENT_START_TIME = time.time()


def configure_agent(token: Optional[str] = None, data_dir: Optional[str] = None) -> None:
    """Allow programmatic configuration (used by CLI & automated tests)."""
    global AGENT_TOKEN, AGENT_ROOT, SERVERS_DIR, BACKUPS_DIR
    if token is not None:
        AGENT_TOKEN = token
    if data_dir is not None:
        AGENT_ROOT = Path(data_dir)
        SERVERS_DIR = AGENT_ROOT / "servers"
        BACKUPS_DIR = AGENT_ROOT / "backups"
        SERVERS_DIR.mkdir(parents=True, exist_ok=True)
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)


def _verify_signature(method: str, path: str, timestamp: str, body: bytes, signature: str) -> bool:
    try:
        if abs(int(time.time()) - int(timestamp)) > 300:
            return False
    except ValueError:
        return False
    body_hash = hashlib.sha256(body).hexdigest()
    payload = f"{method.upper()}:{path}:{timestamp}:{body_hash}".encode("utf-8")
    expected = hmac.new(AGENT_TOKEN.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


async def verify_agent_auth(request: Request) -> bytes:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing node authentication token.")
    token = auth[7:].strip()
    if not hmac.compare_digest(token, AGENT_TOKEN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid node token.")
    body = await request.body()
    ts = request.headers.get("x-onion-timestamp", "")
    sig = request.headers.get("x-onion-signature", "")
    if not ts or not sig or not _verify_signature(request.method, request.url.path, ts, body, sig):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired HMAC request signature.")
    return body


def server_root(server_id: str) -> Path:
    if not server_id or "/" in server_id or "\\" in server_id or ".." in server_id:
        raise HTTPException(status_code=400, detail="Invalid server identifier.")
    p = (SERVERS_DIR / server_id).resolve()
    if not str(p).startswith(str(SERVERS_DIR.resolve())):
        raise HTTPException(status_code=403, detail="Server path escapes sandbox.")
    p.mkdir(parents=True, exist_ok=True)
    return p


def safe_server_path(server_id: str, rel_path: str = "", must_exist: bool = False) -> Path:
    """Resolve a path strictly inside a server's root directory, blocking traversal & symlink escapes."""
    root = server_root(server_id)
    cleaned = (rel_path or "").lstrip("/\\")
    if "\x00" in cleaned:
        raise HTTPException(status_code=400, detail="Null byte in path.")
    candidate = root / cleaned
    # Check intermediate symlink escape before resolving
    resolved = candidate.resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and not str(resolved).startswith(str(root_resolved) + os.sep):
        raise HTTPException(status_code=403, detail="Path traversal or symlink escape denied.")
    if must_exist and not resolved.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {rel_path}")
    return resolved


def dir_size_bytes(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path, followlinks=False):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                if not os.path.islink(fp):
                    total += os.path.getsize(fp)
            except OSError:
                pass
    return total


class ManagedServerProcess:
    """Manages a single live server process, ring-buffered logs, and WS subscribers."""

    def __init__(self, server_id: str) -> None:
        self.server_id = server_id
        self.proc: Optional[subprocess.Popen] = None
        self.status: str = "offline"
        self.started_at: Optional[float] = None
        self.logs: Deque[str] = collections.deque(maxlen=600)
        self.lock = threading.RLock()
        self.subscribers: Set[asyncio.Queue] = set()
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.startup_command: str = ""
        self.env_vars: Dict[str, str] = {}
        self.net_rx_bytes: int = 0
        self.net_tx_bytes: int = 0

    def append_log(self, line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {line.rstrip()}"
        with self.lock:
            self.logs.append(entry)
            self.net_tx_bytes += len(entry.encode("utf-8", errors="ignore"))
            subs = list(self.subscribers)
            loop = self.loop
        if loop and subs:
            for q in subs:
                try:
                    loop.call_soon_threadsafe(q.put_nowait, entry)
                except Exception:
                    pass

    def is_running(self) -> bool:
        with self.lock:
            return self.proc is not None and self.proc.poll() is None

    def start(self, startup_command: str, env_vars: Dict[str, str], port: int = 25565, memory_mb: int = 1024) -> None:
        with self.lock:
            if self.is_running():
                return
            self.startup_command = startup_command
            self.env_vars = dict(env_vars or {})
            cwd = server_root(self.server_id)
            resolved_cmd = startup_command.replace("{{SERVER_MEMORY}}", str(memory_mb)).replace("{{SERVER_PORT}}", str(port))
            for k, v in self.env_vars.items():
                resolved_cmd = resolved_cmd.replace(f"{{{{{k}}}}}", str(v))

            proc_env = os.environ.copy()
            proc_env.update({k: str(v) for k, v in self.env_vars.items()})
            proc_env["SERVER_PORT"] = str(port)
            proc_env["SERVER_MEMORY"] = str(memory_mb)
            proc_env["OMCP_SERVER_ID"] = self.server_id

            self.status = "starting"
            self.append_log(f"[OMCP ONION Daemon] Starting server process: {resolved_cmd}")
            self.proc = subprocess.Popen(
                resolved_cmd,
                shell=True,
                cwd=str(cwd),
                env=proc_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )
            self.started_at = time.time()
            self.status = "running"
            t = threading.Thread(target=self._reader_thread, daemon=True)
            t.start()

    def _reader_thread(self) -> None:
        proc = self.proc
        if not proc or not proc.stdout:
            return
        try:
            for line in iter(proc.stdout.readline, ""):
                if not line:
                    break
                self.append_log(line)
        except Exception as exc:
            self.append_log(f"[OMCP ONION Daemon] Log stream closed: {exc}")
        finally:
            code = proc.wait()
            with self.lock:
                self.status = "offline"
                self.started_at = None
                self.proc = None
            self.append_log(f"[OMCP ONION Daemon] Process exited with code {code}.")

    def send_command(self, command: str) -> None:
        with self.lock:
            if not self.is_running() or not self.proc or not self.proc.stdin:
                raise HTTPException(status_code=409, detail="Server is not running.")
            self.net_rx_bytes += len(command.encode("utf-8", errors="ignore"))
            self.append_log(f"> {command}")
            self.proc.stdin.write(command + "\n")
            self.proc.stdin.flush()

    def stop(self, timeout: float = 5.0) -> None:
        with self.lock:
            if not self.is_running() or not self.proc:
                self.status = "offline"
                return
            self.status = "stopping"
            proc = self.proc
            self.append_log("[OMCP ONION Daemon] Sending graceful stop signal...")
            try:
                if proc.stdin:
                    proc.stdin.write("stop\n")
                    proc.stdin.flush()
            except Exception:
                pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                else:
                    proc.terminate()
                proc.wait(timeout=3.0)
            except Exception:
                self.kill()
        with self.lock:
            self.status = "offline"
            self.started_at = None
            self.proc = None

    def kill(self) -> None:
        with self.lock:
            if not self.is_running() or not self.proc:
                self.status = "offline"
                return
            proc = self.proc
            self.append_log("[OMCP ONION Daemon] Force killing process (SIGKILL)...")
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait(timeout=3.0)
            except Exception:
                pass
            self.status = "offline"
            self.started_at = None
            self.proc = None

    def resources(self) -> Dict[str, Any]:
        root = server_root(self.server_id)
        mem_bytes = 0
        cpu_pct = 0.0
        uptime = 0
        state = "offline"
        with self.lock:
            if self.is_running() and self.proc:
                state = self.status
                uptime = int(time.time() - (self.started_at or time.time()))
                pid = self.proc.pid
                try:
                    status_file = Path(f"/proc/{pid}/status")
                    if status_file.exists():
                        for line in status_file.read_text().splitlines():
                            if line.startswith("VmRSS:"):
                                mem_bytes = int(line.split()[1]) * 1024
                                break
                    stat_file = Path(f"/proc/{pid}/stat")
                    if stat_file.exists():
                        fields = stat_file.read_text().split()
                        utime = int(fields[13])
                        stime = int(fields[14])
                        ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
                        cpu_pct = round(((utime + stime) / ticks) / max(uptime, 1) * 100.0, 2)
                except Exception:
                    pass
        return {
            "state": state,
            "cpu_percent": cpu_pct,
            "memory_bytes": mem_bytes,
            "disk_bytes": dir_size_bytes(root),
            "network_rx_bytes": self.net_rx_bytes,
            "network_tx_bytes": self.net_tx_bytes,
            "uptime_seconds": uptime,
        }


class ProcessRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._servers: Dict[str, ManagedServerProcess] = {}

    def get(self, server_id: str) -> ManagedServerProcess:
        with self._lock:
            if server_id not in self._servers:
                self._servers[server_id] = ManagedServerProcess(server_id)
            return self._servers[server_id]

    def running_count(self) -> int:
        with self._lock:
            return sum(1 for p in self._servers.values() if p.is_running())

    def stop_all(self) -> None:
        with self._lock:
            items = list(self._servers.values())
        for srv in items:
            try:
                srv.stop(timeout=2.0)
            except Exception:
                pass


registry = ProcessRegistry()
app = FastAPI(title="OMCP ONION Node Agent", version="1.0.0")


class ProvisionRequest(BaseModel):
    install_script: str = "#!/bin/sh\necho 'Server directory provisioned.'"
    startup_command: str = "python3 -u server.py"
    env_vars: Dict[str, Any] = {}
    port: int = 25565
    memory_mb: int = 1024


class PowerRequest(BaseModel):
    action: str
    startup_command: str = ""
    env_vars: Dict[str, Any] = {}
    port: int = 25565
    memory_mb: int = 1024


class CommandRequest(BaseModel):
    command: str


class FileWriteRequest(BaseModel):
    path: str
    content: str


class MkdirRequest(BaseModel):
    path: str


class RenameRequest(BaseModel):
    source: str
    destination: str


class CopyMoveRequest(BaseModel):
    source: str
    destination: str


class DeleteFilesRequest(BaseModel):
    paths: List[str]


class ChmodRequest(BaseModel):
    path: str
    mode: str


class ExtractArchiveRequest(BaseModel):
    archive_path: str
    destination: str = ""
    overwrite: bool = False


class CreateArchiveRequest(BaseModel):
    paths: List[str]
    archive_name: str = "archive.zip"
    directory: str = ""


class CreateBackupRequest(BaseModel):
    backup_id: str
    name: str = ""


class RestoreBackupRequest(BaseModel):
    backup_id: str
    truncate: bool = False


def _host_health() -> Dict[str, Any]:
    mem_total = 0
    mem_avail = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                mem_avail = int(line.split()[1]) * 1024
    except Exception:
        pass
    disk = shutil.disk_usage(str(AGENT_ROOT))
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        load1 = load5 = load15 = 0.0
    return {
        "status": "online",
        "version": "1.0.0",
        "uptime_seconds": int(time.time() - AGENT_START_TIME),
        "cpu_cores": os.cpu_count() or 1,
        "load_average": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "memory_total_bytes": mem_total,
        "memory_used_bytes": max(0, mem_total - mem_avail),
        "disk_total_bytes": disk.total,
        "disk_used_bytes": disk.used,
        "running_servers": registry.running_count(),
    }


@app.get("/agent/health")
async def agent_health(request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    return {"status": "ok", "data": _host_health()}


@app.post("/agent/servers/{server_id}/provision")
async def provision_server(server_id: str, payload: ProvisionRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    root = server_root(server_id)
    srv = registry.get(server_id)
    srv.status = "installing"
    srv.append_log("[OMCP ONION Daemon] Starting server installation...")
    script_path = root / ".onion_install.sh"
    script_path.write_text(payload.install_script, encoding="utf-8")
    os.chmod(script_path, 0o700)
    env = os.environ.copy()
    env.update({k: str(v) for k, v in (payload.env_vars or {}).items()})
    env["SERVER_PORT"] = str(payload.port)
    env["SERVER_MEMORY"] = str(payload.memory_mb)
    try:
        proc = subprocess.run(
            ["/bin/sh", str(script_path)],
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        log_output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        for line in log_output.splitlines():
            srv.append_log(f"[Install] {line}")
        if proc.returncode != 0:
            srv.status = "install_failed"
            raise HTTPException(status_code=500, detail=f"Installation script failed (exit {proc.returncode}): {log_output}")
    finally:
        if script_path.exists():
            script_path.unlink(missing_ok=True)
    srv.status = "offline"
    srv.append_log("[OMCP ONION Daemon] Installation completed successfully.")
    return {"status": "ok", "data": {"server_id": server_id, "install_log": log_output.strip(), "state": "offline"}}


@app.delete("/agent/servers/{server_id}")
async def delete_server_files(server_id: str, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    srv = registry.get(server_id)
    srv.kill()
    root = server_root(server_id)
    shutil.rmtree(root, ignore_errors=True)
    bdir = BACKUPS_DIR / server_id
    shutil.rmtree(bdir, ignore_errors=True)
    return {"status": "ok", "message": "Server directory removed."}


@app.post("/agent/servers/{server_id}/power")
async def power_server(server_id: str, payload: PowerRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    srv = registry.get(server_id)
    srv.loop = asyncio.get_running_loop()
    action = payload.action.lower()
    if action == "start":
        srv.start(payload.startup_command, payload.env_vars, payload.port, payload.memory_mb)
    elif action == "stop":
        srv.stop()
    elif action == "restart":
        srv.stop()
        srv.start(payload.startup_command or srv.startup_command, payload.env_vars or srv.env_vars, payload.port, payload.memory_mb)
    elif action == "kill":
        srv.kill()
    else:
        raise HTTPException(status_code=400, detail="Action must be start, stop, restart, or kill.")
    return {"status": "ok", "data": srv.resources()}


@app.post("/agent/servers/{server_id}/command")
async def send_command(server_id: str, payload: CommandRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    srv = registry.get(server_id)
    srv.send_command(payload.command)
    return {"status": "ok", "message": "Command dispatched."}


@app.get("/agent/servers/{server_id}/console")
async def get_console_logs(server_id: str, request: Request, lines: int = 200) -> Dict[str, Any]:
    await verify_agent_auth(request)
    srv = registry.get(server_id)
    with srv.lock:
        recent = list(srv.logs)[-lines:]
    return {"status": "ok", "data": {"state": srv.status, "logs": recent}}


@app.get("/agent/servers/{server_id}/resources")
async def get_resources(server_id: str, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    srv = registry.get(server_id)
    return {"status": "ok", "data": srv.resources()}


@app.websocket("/agent/servers/{server_id}/console/ws")
async def ws_console(websocket: WebSocket, server_id: str, token: str = Query("")):
    if not hmac.compare_digest(token, AGENT_TOKEN):
        await websocket.close(code=4403)
        return
    await websocket.accept()
    srv = registry.get(server_id)
    srv.loop = asyncio.get_running_loop()
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    with srv.lock:
        backlog = list(srv.logs)
        srv.subscribers.add(q)
    try:
        await websocket.send_json({"type": "status", "state": srv.status})
        for line in backlog:
            await websocket.send_json({"type": "log", "line": line})

        async def sender():
            while True:
                line = await q.get()
                await websocket.send_json({"type": "log", "line": line})

        async def receiver():
            while True:
                raw = await websocket.receive_text()
                try:
                    msg = json.loads(raw)
                except Exception:
                    msg = {"type": "command", "command": raw}
                if msg.get("type") == "command" and msg.get("command"):
                    try:
                        srv.send_command(str(msg["command"]))
                    except HTTPException as exc:
                        await websocket.send_json({"type": "error", "detail": exc.detail})
                elif msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})

        send_task = asyncio.create_task(sender())
        recv_task = asyncio.create_task(receiver())
        done, pending = await asyncio.wait([send_task, recv_task], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
    except WebSocketDisconnect:
        pass
    finally:
        with srv.lock:
            srv.subscribers.discard(q)


# ==================== FILE MANAGER ====================

@app.get("/agent/servers/{server_id}/files")
async def list_files(server_id: str, request: Request, directory: str = "", search: str = "") -> Dict[str, Any]:
    await verify_agent_auth(request)
    root = server_root(server_id)
    target = safe_server_path(server_id, directory, must_exist=True)
    if not target.is_dir():
        raise HTTPException(status_code=400, detail="Target path is not a directory.")

    entries = []
    if search:
        q = search.lower()
        for r, dirs, files in os.walk(target, followlinks=False):
            for name in dirs + files:
                if q in name.lower():
                    fp = Path(r) / name
                    rel = fp.relative_to(root).as_posix()
                    st = fp.lstat()
                    entries.append({
                        "name": name,
                        "path": rel,
                        "is_dir": fp.is_dir(),
                        "is_symlink": fp.is_symlink(),
                        "size": 0 if fp.is_dir() else st.st_size,
                        "mode": oct(stat.S_IMODE(st.st_mode))[-3:],
                        "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
                        "mime": "inode/directory" if fp.is_dir() else (mimetypes.guess_type(name)[0] or "application/octet-stream"),
                    })
    else:
        for item in sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            st = item.lstat()
            rel = item.relative_to(root).as_posix()
            entries.append({
                "name": item.name,
                "path": rel,
                "is_dir": item.is_dir(),
                "is_symlink": item.is_symlink(),
                "size": 0 if item.is_dir() else st.st_size,
                "mode": oct(stat.S_IMODE(st.st_mode))[-3:],
                "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
                "mime": "inode/directory" if item.is_dir() else (mimetypes.guess_type(item.name)[0] or "application/octet-stream"),
            })
    return {
        "status": "ok",
        "data": {
            "directory": target.relative_to(root).as_posix() if target != root else "",
            "storage_used_bytes": dir_size_bytes(root),
            "files": entries,
        },
    }


@app.get("/agent/servers/{server_id}/files/read")
async def read_file(server_id: str, request: Request, path: str = Query(...)) -> Dict[str, Any]:
    await verify_agent_auth(request)
    fp = safe_server_path(server_id, path, must_exist=True)
    if fp.is_dir():
        raise HTTPException(status_code=400, detail="Cannot read a directory as a text file.")
    if fp.stat().st_size > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 5MB inline editor limit.")
    content = fp.read_text(encoding="utf-8", errors="replace")
    return {"status": "ok", "data": {"path": path, "content": content, "size": fp.stat().st_size}}


@app.post("/agent/servers/{server_id}/files/write")
async def write_file(server_id: str, payload: FileWriteRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    fp = safe_server_path(server_id, payload.path, must_exist=False)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(payload.content, encoding="utf-8")
    return {"status": "ok", "data": {"path": payload.path, "size": fp.stat().st_size}}


@app.post("/agent/servers/{server_id}/files/mkdir")
async def create_folder(server_id: str, payload: MkdirRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    fp = safe_server_path(server_id, payload.path, must_exist=False)
    fp.mkdir(parents=True, exist_ok=True)
    return {"status": "ok", "data": {"path": payload.path}}


@app.post("/agent/servers/{server_id}/files/upload")
async def upload_file(server_id: str, request: Request, directory: str = "", filename: str = Query(...)) -> Dict[str, Any]:
    body = await verify_agent_auth(request)
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")
    dest_dir = safe_server_path(server_id, directory, must_exist=False)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = safe_server_path(server_id, f"{directory}/{filename}".strip("/"), must_exist=False)
    dest.write_bytes(body)
    return {"status": "ok", "data": {"path": dest.relative_to(server_root(server_id)).as_posix(), "size": len(body)}}


@app.get("/agent/servers/{server_id}/files/download")
async def download_file(server_id: str, request: Request, path: str = Query(...)) -> Response:
    await verify_agent_auth(request)
    fp = safe_server_path(server_id, path, must_exist=True)
    if fp.is_dir():
        raise HTTPException(status_code=400, detail="Cannot download a directory directly; compress it first.")
    mime = mimetypes.guess_type(fp.name)[0] or "application/octet-stream"
    return Response(content=fp.read_bytes(), media_type=mime, headers={"Content-Disposition": f'attachment; filename="{fp.name}"'})


@app.post("/agent/servers/{server_id}/files/rename")
async def rename_file(server_id: str, payload: RenameRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    src = safe_server_path(server_id, payload.source, must_exist=True)
    dst = safe_server_path(server_id, payload.destination, must_exist=False)
    if dst.exists():
        raise HTTPException(status_code=409, detail="Destination already exists.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.rename(dst)
    return {"status": "ok", "data": {"source": payload.source, "destination": payload.destination}}


@app.post("/agent/servers/{server_id}/files/copy")
async def copy_file(server_id: str, payload: CopyMoveRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    src = safe_server_path(server_id, payload.source, must_exist=True)
    dst = safe_server_path(server_id, payload.destination, must_exist=False)
    if dst.exists():
        raise HTTPException(status_code=409, detail="Destination already exists.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, symlinks=False)
    else:
        shutil.copy2(src, dst)
    return {"status": "ok", "data": {"source": payload.source, "destination": payload.destination}}


@app.post("/agent/servers/{server_id}/files/move")
async def move_file(server_id: str, payload: CopyMoveRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    src = safe_server_path(server_id, payload.source, must_exist=True)
    dst = safe_server_path(server_id, payload.destination, must_exist=False)
    if dst.exists():
        raise HTTPException(status_code=409, detail="Destination already exists.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return {"status": "ok", "data": {"source": payload.source, "destination": payload.destination}}


@app.post("/agent/servers/{server_id}/files/delete")
async def delete_files(server_id: str, payload: DeleteFilesRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    root = server_root(server_id)
    deleted = []
    for rel in payload.paths:
        fp = safe_server_path(server_id, rel, must_exist=False)
        if fp == root:
            raise HTTPException(status_code=400, detail="Cannot delete server root directory.")
        if fp.exists() or fp.is_symlink():
            if fp.is_dir() and not fp.is_symlink():
                shutil.rmtree(fp)
            else:
                fp.unlink()
            deleted.append(rel)
    return {"status": "ok", "data": {"deleted": deleted}}


@app.post("/agent/servers/{server_id}/files/chmod")
async def chmod_file(server_id: str, payload: ChmodRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    fp = safe_server_path(server_id, payload.path, must_exist=True)
    try:
        mode_int = int(payload.mode, 8)
    except ValueError:
        raise HTTPException(status_code=400, detail="Mode must be an octal string such as '644' or '755'.")
    os.chmod(fp, mode_int)
    return {"status": "ok", "data": {"path": payload.path, "mode": oct(mode_int)[-3:]}}


# ==================== ARCHIVE MANAGER ====================

def _validate_member_path(dest_root: Path, member_name: str) -> Path:
    if not member_name or member_name.startswith("/") or member_name.startswith("\\"):
        raise HTTPException(status_code=400, detail=f"Unsafe absolute archive member: {member_name}")
    parts = Path(member_name).parts
    if ".." in parts:
        raise HTTPException(status_code=400, detail=f"Path traversal blocked in archive member: {member_name}")
    target = (dest_root / member_name).resolve()
    if target != dest_root.resolve() and not str(target).startswith(str(dest_root.resolve()) + os.sep):
        raise HTTPException(status_code=400, detail=f"Archive member escapes destination: {member_name}")
    return target


@app.post("/agent/servers/{server_id}/files/compress")
async def compress_files(server_id: str, payload: CreateArchiveRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    name = payload.archive_name if payload.archive_name.endswith(".zip") else f"{payload.archive_name}.zip"
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid archive name.")
    out_path = safe_server_path(server_id, f"{payload.directory}/{name}".strip("/"), must_exist=False)
    if out_path.exists():
        raise HTTPException(status_code=409, detail="Archive with that name already exists.")
    root = server_root(server_id)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in payload.paths:
            src = safe_server_path(server_id, rel, must_exist=True)
            if src.is_dir():
                for r, _, files in os.walk(src, followlinks=False):
                    for fn in files:
                        fp = Path(r) / fn
                        if not fp.is_symlink():
                            zf.write(fp, fp.relative_to(root).as_posix())
            elif not src.is_symlink():
                zf.write(src, src.relative_to(root).as_posix())
    return {"status": "ok", "data": {"archive": out_path.relative_to(root).as_posix(), "size": out_path.stat().st_size}}


@app.post("/agent/servers/{server_id}/files/extract")
async def extract_archive(server_id: str, payload: ExtractArchiveRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    archive = safe_server_path(server_id, payload.archive_path, must_exist=True)
    dest_dir = safe_server_path(server_id, payload.destination, must_exist=False)
    dest_dir.mkdir(parents=True, exist_ok=True)
    lower = archive.name.lower()

    extracted_files: List[str] = []
    conflicts: List[str] = []

    if lower.endswith(".zip"):
        try:
            with zipfile.ZipFile(archive, "r") as zf:
                infos = zf.infolist()
                for info in infos:
                    if info.is_dir():
                        _validate_member_path(dest_dir, info.filename)
                        continue
                    # Reject symlinks inside zip (external_attr unix symlink flag 0o120000)
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        raise HTTPException(status_code=400, detail=f"Unsafe symbolic link blocked in archive: {info.filename}")
                    target = _validate_member_path(dest_dir, info.filename)
                    if target.exists() and not payload.overwrite:
                        conflicts.append(info.filename)
                if conflicts:
                    raise HTTPException(status_code=409, detail=f"Extraction aborted to prevent overwriting existing files: {', '.join(conflicts[:10])}")
                for info in infos:
                    target = _validate_member_path(dest_dir, info.filename)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(info, "r") as src_f, open(target, "wb") as dst_f:
                            shutil.copyfileobj(src_f, dst_f)
                        extracted_files.append(info.filename)
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Damaged or invalid ZIP archive.")
    elif any(lower.endswith(ext) for ext in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        try:
            with tarfile.open(archive, "r:*") as tf:
                members = tf.getmembers()
                for m in members:
                    if m.issym() or m.islnk() or m.isdev():
                        raise HTTPException(status_code=400, detail=f"Unsafe symlink/device entry blocked in archive: {m.name}")
                    target = _validate_member_path(dest_dir, m.name)
                    if m.isfile() and target.exists() and not payload.overwrite:
                        conflicts.append(m.name)
                if conflicts:
                    raise HTTPException(status_code=409, detail=f"Extraction aborted to prevent overwriting existing files: {', '.join(conflicts[:10])}")
                for m in members:
                    target = _validate_member_path(dest_dir, m.name)
                    if m.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif m.isfile():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        fobj = tf.extractfile(m)
                        if fobj is not None:
                            with open(target, "wb") as dst_f:
                                shutil.copyfileobj(fobj, dst_f)
                            extracted_files.append(m.name)
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise HTTPException(status_code=400, detail=f"Damaged or unreadable TAR archive: {exc}")
    else:
        raise HTTPException(status_code=400, detail="Unsupported archive format. Supported: zip, tar, tar.gz, tgz, tar.bz2, tar.xz.")

    return {
        "status": "ok",
        "data": {
            "archive": payload.archive_path,
            "extracted_count": len(extracted_files),
            "progress": 100,
        },
    }


# ==================== BACKUPS ====================

@app.post("/agent/servers/{server_id}/backups")
async def create_backup(server_id: str, payload: CreateBackupRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    root = server_root(server_id)
    bdir = BACKUPS_DIR / server_id
    bdir.mkdir(parents=True, exist_ok=True)
    archive_path = bdir / f"{payload.backup_id}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        for item in root.iterdir():
            if not item.is_symlink():
                tf.add(item, arcname=item.name)
    data = archive_path.read_bytes()
    checksum = hashlib.sha256(data).hexdigest()
    return {
        "status": "ok",
        "data": {
            "backup_id": payload.backup_id,
            "archive_path": str(archive_path),
            "size_bytes": len(data),
            "checksum": checksum,
        },
    }


@app.get("/agent/servers/{server_id}/backups/{backup_id}/download")
async def download_backup(server_id: str, backup_id: str, request: Request) -> Response:
    await verify_agent_auth(request)
    archive_path = (BACKUPS_DIR / server_id / f"{backup_id}.tar.gz").resolve()
    if not str(archive_path).startswith(str(BACKUPS_DIR.resolve())) or not archive_path.exists():
        raise HTTPException(status_code=404, detail="Backup archive not found.")
    return Response(
        content=archive_path.read_bytes(),
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{backup_id}.tar.gz"'},
    )


@app.post("/agent/servers/{server_id}/backups/{backup_id}/restore")
async def restore_backup(server_id: str, backup_id: str, payload: RestoreBackupRequest, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    archive_path = (BACKUPS_DIR / server_id / f"{backup_id}.tar.gz").resolve()
    if not str(archive_path).startswith(str(BACKUPS_DIR.resolve())) or not archive_path.exists():
        raise HTTPException(status_code=404, detail="Backup archive not found.")

    srv = registry.get(server_id)
    if srv.is_running():
        srv.stop()

    root = server_root(server_id)
    # Stage into temp dir first to guarantee atomic validation & never destroy unrelated files on failure
    with tempfile.TemporaryDirectory(prefix="onion_restore_") as tmpdir:
        tmp_path = Path(tmpdir)
        try:
            with tarfile.open(archive_path, "r:gz") as tf:
                for m in tf.getmembers():
                    if m.issym() or m.islnk() or m.isdev():
                        raise HTTPException(status_code=400, detail="Unsafe symlink detected in backup archive.")
                    _validate_member_path(tmp_path, m.name)
                tf.extractall(tmp_path)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Backup archive validation failed: {exc}")

        if payload.truncate:
            for item in root.iterdir():
                if item.is_dir() and not item.is_symlink():
                    shutil.rmtree(item)
                else:
                    item.unlink()

        for item in tmp_path.iterdir():
            dst = root / item.name
            if item.is_dir():
                shutil.copytree(item, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dst)

    srv.append_log(f"[OMCP ONION Daemon] Restored backup {backup_id} safely (truncate={payload.truncate}).")
    return {"status": "ok", "message": "Backup restored safely."}


@app.delete("/agent/servers/{server_id}/backups/{backup_id}")
async def delete_backup(server_id: str, backup_id: str, request: Request) -> Dict[str, Any]:
    await verify_agent_auth(request)
    archive_path = (BACKUPS_DIR / server_id / f"{backup_id}.tar.gz").resolve()
    if str(archive_path).startswith(str(BACKUPS_DIR.resolve())) and archive_path.exists():
        archive_path.unlink()
    return {"status": "ok", "message": "Backup removed."}


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("ONION_AGENT_HOST", "0.0.0.0")
    port = int(os.environ.get("ONION_AGENT_PORT", "8443"))
    ssl_cert = os.environ.get("ONION_AGENT_TLS_CERT") or None
    ssl_key = os.environ.get("ONION_AGENT_TLS_KEY") or None
    uvicorn.run(app, host=host, port=port, ssl_certfile=ssl_cert, ssl_keyfile=ssl_key)
