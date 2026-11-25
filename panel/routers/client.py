"""Client & Server Management REST + WebSocket APIs for OMCP ONION."""

import asyncio
import json
import secrets
import socket
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel, Field

from panel.cron_utils import compute_next_run, validate_cron
from panel.daemon_client import DaemonClient
from panel.database import db_session, new_uuid, now_iso, rows_to_list
from panel.security import (
    SERVER_PERMISSIONS,
    generate_token,
    get_client_ip,
    get_current_user,
    get_server_and_permissions,
    hash_password,
    hash_token,
    log_activity,
    require_server_permission,
    sanitize_server_public,
    verify_password,
)

router = APIRouter(prefix="/api/client", tags=["Client & Server API"])


# ==================== SCHEMAS ====================

class AccountUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    language: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class ApiKeyCreateRequest(BaseModel):
    memo: str = Field(..., min_length=1, max_length=120)
    allowed_ips: List[str] = []


class PowerActionRequest(BaseModel):
    action: str = Field(..., description="start, stop, restart, or kill")


class ConsoleCommandRequest(BaseModel):
    command: str = Field(..., min_length=1, max_length=1000)


class FileWritePayload(BaseModel):
    path: str
    content: str


class FilePathPayload(BaseModel):
    path: str


class FileTransferPayload(BaseModel):
    source: str
    destination: str


class FileDeletePayload(BaseModel):
    paths: List[str]


class FileChmodPayload(BaseModel):
    path: str
    mode: str


class FileCompressPayload(BaseModel):
    paths: List[str]
    archive_name: str = "archive.zip"
    directory: str = ""


class FileExtractPayload(BaseModel):
    archive_path: str
    destination: str = ""
    overwrite: bool = False


class BackupCreatePayload(BaseModel):
    name: str = ""
    is_locked: bool = False


class BackupRestorePayload(BaseModel):
    truncate: bool = False


class ScheduleTaskInput(BaseModel):
    action: str  # command | power | backup
    payload: str = ""
    time_offset: int = 0
    continue_on_failure: bool = False


class ScheduleCreatePayload(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    cron_expression: str
    is_active: bool = True
    only_when_online: bool = False
    tasks: List[ScheduleTaskInput] = []


class SubuserPayload(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    permissions: List[str] = []


class SubuserUpdatePayload(BaseModel):
    permissions: List[str]


class DatabaseCreatePayload(BaseModel):
    name: str = Field(..., min_length=2, max_length=48)
    remote_host: str = "%"


class ServerStartupUpdatePayload(BaseModel):
    startup_command: Optional[str] = None
    docker_image: Optional[str] = None
    env_vars: Optional[Dict[str, Any]] = None


class ServerSettingsUpdatePayload(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


# ==================== ACCOUNT ====================

@router.get("/permissions")
def list_available_permissions(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return {"status": "ok", "data": SERVER_PERMISSIONS}


@router.get("/account")
def get_account(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    safe = {k: user.get(k) for k in ("id", "username", "email", "first_name", "last_name", "role", "language", "created_at")}
    return {"status": "ok", "data": safe}


@router.put("/account")
def update_account(payload: AccountUpdateRequest, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    with db_session() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found.")
        fn = payload.first_name if payload.first_name is not None else row["first_name"]
        ln = payload.last_name if payload.last_name is not None else row["last_name"]
        lang = payload.language if payload.language is not None else row["language"]
        pw_hash = row["password_hash"]
        if payload.new_password:
            if not payload.current_password or not verify_password(payload.current_password, row["password_hash"]):
                raise HTTPException(status_code=400, detail="Current password is incorrect.")
            if len(payload.new_password) < 8:
                raise HTTPException(status_code=422, detail="New password must be at least 8 characters.")
            pw_hash = hash_password(payload.new_password)
        conn.execute(
            "UPDATE users SET first_name=?, last_name=?, language=?, password_hash=?, updated_at=? WHERE id=?",
            (fn, ln, lang, pw_hash, now_iso(), user["id"]),
        )
    log_activity("account.updated", actor_id=user["id"], actor_username=user["username"], ip_address=get_client_ip(request))
    return {"status": "ok", "message": "Account updated."}


@router.get("/account/api-keys")
def list_client_api_keys(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = conn.execute(
            "SELECT id, identifier, memo, allowed_ips, last_used_at, created_at FROM api_keys WHERE user_id = ? AND key_type = 'client' ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
    return {"status": "ok", "data": rows_to_list(rows)}


@router.post("/account/api-keys", status_code=201)
def create_client_api_key(payload: ApiKeyCreateRequest, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    raw_key = generate_token("oncl")
    ident = raw_key[:14]
    kid = new_uuid()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO api_keys (id, user_id, key_type, identifier, token_hash, memo, allowed_ips, permissions, created_at)
               VALUES (?, ?, 'client', ?, ?, ?, ?, '[]', ?)""",
            (kid, user["id"], ident, hash_token(raw_key), payload.memo, json.dumps(payload.allowed_ips), now_iso()),
        )
    log_activity("account.api_key_created", actor_id=user["id"], actor_username=user["username"], ip_address=get_client_ip(request))
    return {"status": "ok", "data": {"id": kid, "identifier": ident, "secret_token": raw_key, "memo": payload.memo}}


@router.delete("/account/api-keys/{key_id}")
def delete_client_api_key(key_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    with db_session() as conn:
        cur = conn.execute("DELETE FROM api_keys WHERE id = ? AND user_id = ?", (key_id, user["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="API key not found.")
    return {"status": "ok", "message": "API key revoked."}


# ==================== SERVERS OVERVIEW ====================

@router.get("/servers")
def list_client_servers(
    search: str = "",
    status_filter: str = "",
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    with db_session() as conn:
        if user["role"] == "admin":
            rows = conn.execute(
                """SELECT s.*, n.name AS node_name, n.fqdn AS node_fqdn, n.ip_address AS node_ip,
                          n.scheme AS node_scheme, n.daemon_port, n.daemon_token,
                          e.name AS egg_name, a.ip AS alloc_ip, a.ip_alias AS alloc_alias, a.port AS alloc_port
                   FROM servers s
                   JOIN nodes n ON n.id = s.node_id
                   JOIN eggs e ON e.id = s.egg_id
                   JOIN allocations a ON a.id = s.primary_allocation_id
                   ORDER BY s.created_at DESC"""
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT DISTINCT s.*, n.name AS node_name, n.fqdn AS node_fqdn, n.ip_address AS node_ip,
                          n.scheme AS node_scheme, n.daemon_port, n.daemon_token,
                          e.name AS egg_name, a.ip AS alloc_ip, a.ip_alias AS alloc_alias, a.port AS alloc_port
                   FROM servers s
                   JOIN nodes n ON n.id = s.node_id
                   JOIN eggs e ON e.id = s.egg_id
                   JOIN allocations a ON a.id = s.primary_allocation_id
                   LEFT JOIN subusers su ON su.server_id = s.id AND su.user_id = ?
                   WHERE s.owner_id = ? OR su.user_id = ?
                   ORDER BY s.created_at DESC""",
                (user["id"], user["id"], user["id"]),
            ).fetchall()

    result = []
    for r in rows:
        srv_raw = dict(r)
        if search and search.lower() not in srv_raw["name"].lower() and search.lower() not in srv_raw["egg_name"].lower():
            continue
        live_res = {"state": srv_raw["status"], "cpu_percent": 0.0, "memory_bytes": 0, "disk_bytes": 0, "network_rx_bytes": 0, "network_tx_bytes": 0, "uptime_seconds": 0}
        try:
            dc = DaemonClient(srv_raw, timeout=2.5)
            resp = dc.request("GET", f"/agent/servers/{srv_raw['id']}/resources")
            live_res = resp.get("data", live_res)
        except Exception:
            pass
        if status_filter and live_res.get("state") != status_filter:
            continue
        item = sanitize_server_public(srv_raw)
        item["resources"] = live_res
        result.append(item)

    return {"status": "ok", "data": result}


@router.get("/servers/{server_id}")
def get_client_server(server_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv, perms = get_server_and_permissions(server_id, user)
    out = sanitize_server_public(srv)
    out["permissions"] = perms
    try:
        dc = DaemonClient(srv, timeout=3.0)
        out["resources"] = dc.request("GET", f"/agent/servers/{srv['id']}/resources").get("data", {})
    except Exception:
        out["resources"] = {"state": srv["status"], "cpu_percent": 0.0, "memory_bytes": 0, "disk_bytes": 0, "network_rx_bytes": 0, "network_tx_bytes": 0, "uptime_seconds": 0}
    with db_session() as conn:
        egg = conn.execute("SELECT docker_images, variables FROM eggs WHERE id = ?", (srv["egg_id"],)).fetchone()
        if egg:
            out["available_images"] = json.loads(egg["docker_images"] or "[]")
            out["egg_variables"] = json.loads(egg["variables"] or "[]")
    return {"status": "ok", "data": out}


@router.get("/servers/{server_id}/resources")
def get_server_resources(server_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "console.access")
    dc = DaemonClient(srv)
    res = dc.request("GET", f"/agent/servers/{srv['id']}/resources")
    return {"status": "ok", "data": res["data"]}


@router.get("/servers/{server_id}/activity")
def get_server_activity(server_id: str, limit: int = 50, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "activity.read")
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM activity_logs WHERE server_id = ? ORDER BY created_at DESC LIMIT ?",
            (srv["id"], min(limit, 200)),
        ).fetchall()
    return {"status": "ok", "data": rows_to_list(rows)}


# ==================== POWER & LIVE CONSOLE ====================

@router.post("/servers/{server_id}/power")
def server_power(server_id: str, payload: PowerActionRequest, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "power.control")
    action = payload.action.lower()
    if action not in ("start", "stop", "restart", "kill"):
        raise HTTPException(status_code=422, detail="Power action must be start, stop, restart, or kill.")
    env_vars = json.loads(srv["env_vars"] or "{}") if isinstance(srv["env_vars"], str) else (srv["env_vars"] or {})
    dc = DaemonClient(srv)
    res = dc.request(
        "POST",
        f"/agent/servers/{srv['id']}/power",
        json_body={
            "action": action,
            "startup_command": srv["startup_command"],
            "env_vars": env_vars,
            "port": srv["alloc_port"],
            "memory_mb": srv["memory_mb"],
        },
    )
    new_state = res["data"].get("state", "offline")
    with db_session() as conn:
        conn.execute("UPDATE servers SET status = ?, updated_at = ? WHERE id = ?", (new_state, now_iso(), srv["id"]))
    log_activity(f"server.power.{action}", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request))
    return {"status": "ok", "data": res["data"]}


@router.get("/servers/{server_id}/console")
def get_console_snapshot(server_id: str, lines: int = 200, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "console.access")
    dc = DaemonClient(srv)
    res = dc.request("GET", f"/agent/servers/{srv['id']}/console", params={"lines": lines})
    return {"status": "ok", "data": res["data"]}


@router.post("/servers/{server_id}/command")
def send_console_command(server_id: str, payload: ConsoleCommandRequest, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "console.command")
    dc = DaemonClient(srv)
    dc.request("POST", f"/agent/servers/{srv['id']}/command", json_body={"command": payload.command})
    log_activity("server.console.command", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"command": payload.command[:100]})
    return {"status": "ok", "message": "Command sent to server process."}


@router.websocket("/servers/{server_id}/console/ws")
async def server_console_websocket(websocket: WebSocket, server_id: str, token: str = Query("")):
    """Live WebSocket console endpoint bridging authenticated browser clients to the Node Agent."""
    # Authenticate via cookie or query token
    raw_token = token or websocket.cookies.get("omcp_onion_session", "")
    if not raw_token:
        await websocket.close(code=4401)
        return
    th = hash_token(raw_token)
    with db_session() as conn:
        sess = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
            (th,),
        ).fetchone()
        if not sess:
            sess = conn.execute(
                "SELECT u.* FROM api_keys k JOIN users u ON u.id = k.user_id WHERE k.token_hash = ?",
                (th,),
            ).fetchone()
    if not sess:
        await websocket.close(code=4401)
        return
    user = dict(sess)
    try:
        srv, perms = get_server_and_permissions(server_id, user)
    except HTTPException:
        await websocket.close(code=4403)
        return
    if "console.access" not in perms:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    dc = DaemonClient(srv)
    seen_count = 0

    async def poll_daemon():
        nonlocal seen_count
        while True:
            try:
                snap = await asyncio.to_thread(dc.request, "GET", f"/agent/servers/{srv['id']}/console", None, {"lines": 300})
                data = snap.get("data", {})
                logs = data.get("logs", [])
                await websocket.send_json({"type": "status", "state": data.get("state", "offline")})
                if len(logs) < seen_count:
                    seen_count = 0
                if len(logs) > seen_count:
                    for line in logs[seen_count:]:
                        await websocket.send_json({"type": "log", "line": line})
                    seen_count = len(logs)
            except Exception as exc:
                await websocket.send_json({"type": "error", "detail": str(exc)})
            await asyncio.sleep(0.4)

    async def recv_client():
        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    msg = json.loads(raw)
                except Exception:
                    msg = {"type": "command", "command": raw}
                if msg.get("type") == "command" and msg.get("command"):
                    if "console.command" not in perms:
                        await websocket.send_json({"type": "error", "detail": "Missing console.command permission."})
                        continue
                    try:
                        await asyncio.to_thread(dc.request, "POST", f"/agent/servers/{srv['id']}/command", {"command": str(msg["command"])})
                    except HTTPException as exc:
                        await websocket.send_json({"type": "error", "detail": exc.detail})
                elif msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
        except WebSocketDisconnect:
            return

    poll_task = asyncio.create_task(poll_daemon())
    recv_task = asyncio.create_task(recv_client())
    try:
        done, pending = await asyncio.wait([poll_task, recv_task], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
    except WebSocketDisconnect:
        poll_task.cancel()
        recv_task.cancel()


# ==================== FILE & ARCHIVE MANAGER ====================

@router.get("/servers/{server_id}/files")
def list_server_files(server_id: str, directory: str = "", search: str = "", user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.read")
    dc = DaemonClient(srv)
    return dc.request("GET", f"/agent/servers/{srv['id']}/files", params={"directory": directory, "search": search})


@router.get("/servers/{server_id}/files/read")
def read_server_file(server_id: str, path: str = Query(...), user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.read")
    dc = DaemonClient(srv)
    return dc.request("GET", f"/agent/servers/{srv['id']}/files/read", params={"path": path})


@router.post("/servers/{server_id}/files/write")
def write_server_file(server_id: str, payload: FileWritePayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.write")
    dc = DaemonClient(srv)
    res = dc.request("POST", f"/agent/servers/{srv['id']}/files/write", json_body=payload.dict())
    log_activity("server.file.write", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"path": payload.path})
    return res


@router.post("/servers/{server_id}/files/mkdir")
def mkdir_server_file(server_id: str, payload: FilePathPayload, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.write")
    dc = DaemonClient(srv)
    return dc.request("POST", f"/agent/servers/{srv['id']}/files/mkdir", json_body=payload.dict())


@router.post("/servers/{server_id}/files/upload")
async def upload_server_file(
    server_id: str,
    request: Request,
    file: UploadFile = File(...),
    directory: str = Form(""),
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.upload")
    data = await file.read()
    dc = DaemonClient(srv, timeout=120.0)
    res = dc.upload_file(srv["id"], directory, file.filename or "upload.bin", data)
    log_activity("server.file.upload", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"filename": file.filename, "size": len(data)})
    return res


@router.get("/servers/{server_id}/files/download")
def download_server_file(server_id: str, path: str = Query(...), user: Dict[str, Any] = Depends(get_current_user)) -> Response:
    srv = require_server_permission(server_id, user, "file.read")
    dc = DaemonClient(srv)
    content, mime = dc.download(f"/agent/servers/{srv['id']}/files/download", params={"path": path})
    fname = path.split("/")[-1] or "file"
    return Response(content=content, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.post("/servers/{server_id}/files/rename")
def rename_server_file(server_id: str, payload: FileTransferPayload, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.write")
    return DaemonClient(srv).request("POST", f"/agent/servers/{srv['id']}/files/rename", json_body=payload.dict())


@router.post("/servers/{server_id}/files/copy")
def copy_server_file(server_id: str, payload: FileTransferPayload, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.write")
    return DaemonClient(srv).request("POST", f"/agent/servers/{srv['id']}/files/copy", json_body=payload.dict())


@router.post("/servers/{server_id}/files/move")
def move_server_file(server_id: str, payload: FileTransferPayload, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.write")
    return DaemonClient(srv).request("POST", f"/agent/servers/{srv['id']}/files/move", json_body=payload.dict())


@router.post("/servers/{server_id}/files/delete")
def delete_server_files(server_id: str, payload: FileDeletePayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.delete")
    res = DaemonClient(srv).request("POST", f"/agent/servers/{srv['id']}/files/delete", json_body=payload.dict())
    log_activity("server.file.delete", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"paths": payload.paths})
    return res


@router.post("/servers/{server_id}/files/chmod")
def chmod_server_file(server_id: str, payload: FileChmodPayload, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.write")
    return DaemonClient(srv).request("POST", f"/agent/servers/{srv['id']}/files/chmod", json_body=payload.dict())


@router.post("/servers/{server_id}/files/compress")
def compress_server_files(server_id: str, payload: FileCompressPayload, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.write")
    return DaemonClient(srv, timeout=120.0).request("POST", f"/agent/servers/{srv['id']}/files/compress", json_body=payload.dict())


@router.post("/servers/{server_id}/files/extract")
def extract_server_archive(server_id: str, payload: FileExtractPayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "file.write")
    res = DaemonClient(srv, timeout=120.0).request("POST", f"/agent/servers/{srv['id']}/files/extract", json_body=payload.dict())
    log_activity("server.file.extract", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"archive": payload.archive_path})
    return res


# ==================== BACKUPS ====================

@router.get("/servers/{server_id}/backups")
def list_backups(server_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "backup.manage")
    with db_session() as conn:
        rows = conn.execute("SELECT * FROM backups WHERE server_id = ? ORDER BY created_at DESC", (srv["id"],)).fetchall()
    return {"status": "ok", "data": rows_to_list(rows), "limit": srv["backup_limit"]}


@router.post("/servers/{server_id}/backups", status_code=201)
def create_backup(server_id: str, payload: BackupCreatePayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "backup.manage")
    with db_session() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM backups WHERE server_id = ?", (srv["id"],)).fetchone()["c"]
        if count >= srv["backup_limit"]:
            raise HTTPException(status_code=400, detail=f"Backup limit ({srv['backup_limit']}) reached for this server.")
        bid = new_uuid()
        bname = payload.name.strip() or f"Backup {now_iso()}"
        conn.execute(
            """INSERT INTO backups (id, server_id, name, storage_driver, status, is_locked, created_at)
               VALUES (?, ?, ?, 'local', 'in_progress', ?, ?)""",
            (bid, srv["id"], bname, 1 if payload.is_locked else 0, now_iso()),
        )

    try:
        dc = DaemonClient(srv, timeout=120.0)
        res = dc.request("POST", f"/agent/servers/{srv['id']}/backups", json_body={"backup_id": bid, "name": bname})
        bdata = res["data"]
        with db_session() as conn:
            conn.execute(
                """UPDATE backups SET archive_path=?, size_bytes=?, checksum=?, status='completed', completed_at=? WHERE id=?""",
                (bdata["archive_path"], bdata["size_bytes"], bdata["checksum"], now_iso(), bid),
            )
            row = conn.execute("SELECT * FROM backups WHERE id = ?", (bid,)).fetchone()
        log_activity("server.backup.created", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"backup_id": bid})
        return {"status": "ok", "data": dict(row)}
    except HTTPException as exc:
        with db_session() as conn:
            conn.execute("UPDATE backups SET status='failed', error_message=? WHERE id=?", (str(exc.detail), bid))
        raise


@router.get("/servers/{server_id}/backups/{backup_id}/download")
def download_backup(server_id: str, backup_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Response:
    srv = require_server_permission(server_id, user, "backup.manage")
    with db_session() as conn:
        b = conn.execute("SELECT * FROM backups WHERE id = ? AND server_id = ?", (backup_id, srv["id"])).fetchone()
        if not b:
            raise HTTPException(status_code=404, detail="Backup not found.")
    content, mime = DaemonClient(srv).download(f"/agent/servers/{srv['id']}/backups/{backup_id}/download")
    return Response(content=content, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{backup_id}.tar.gz"'})


@router.post("/servers/{server_id}/backups/{backup_id}/restore")
def restore_backup(server_id: str, backup_id: str, payload: BackupRestorePayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "backup.manage")
    with db_session() as conn:
        b = conn.execute("SELECT * FROM backups WHERE id = ? AND server_id = ?", (backup_id, srv["id"])).fetchone()
        if not b or b["status"] != "completed":
            raise HTTPException(status_code=404, detail="Completed backup not found.")
    res = DaemonClient(srv, timeout=120.0).request(
        "POST",
        f"/agent/servers/{srv['id']}/backups/{backup_id}/restore",
        json_body={"backup_id": backup_id, "truncate": payload.truncate},
    )
    log_activity("server.backup.restored", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"backup_id": backup_id, "truncate": payload.truncate})
    return res


@router.delete("/servers/{server_id}/backups/{backup_id}")
def delete_backup(server_id: str, backup_id: str, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "backup.manage")
    with db_session() as conn:
        b = conn.execute("SELECT * FROM backups WHERE id = ? AND server_id = ?", (backup_id, srv["id"])).fetchone()
        if not b:
            raise HTTPException(status_code=404, detail="Backup not found.")
        if b["is_locked"]:
            raise HTTPException(status_code=400, detail="Backup is locked and cannot be deleted.")
    try:
        DaemonClient(srv).request("DELETE", f"/agent/servers/{srv['id']}/backups/{backup_id}")
    except HTTPException:
        pass
    with db_session() as conn:
        conn.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
    log_activity("server.backup.deleted", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"backup_id": backup_id})
    return {"status": "ok", "message": "Backup deleted."}


# ==================== SCHEDULES ====================

@router.get("/servers/{server_id}/schedules")
def list_schedules(server_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "schedule.manage")
    with db_session() as conn:
        scheds = rows_to_list(conn.execute("SELECT * FROM schedules WHERE server_id = ? ORDER BY created_at DESC", (srv["id"],)).fetchall())
        for s in scheds:
            s["tasks"] = rows_to_list(conn.execute("SELECT * FROM schedule_tasks WHERE schedule_id = ? ORDER BY sequence_id ASC", (s["id"],)).fetchall())
            s["recent_logs"] = rows_to_list(conn.execute("SELECT * FROM schedule_logs WHERE schedule_id = ? ORDER BY executed_at DESC LIMIT 5", (s["id"],)).fetchall())
    return {"status": "ok", "data": scheds}


@router.post("/servers/{server_id}/schedules", status_code=201)
def create_schedule(server_id: str, payload: ScheduleCreatePayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "schedule.manage")
    try:
        validate_cron(payload.cron_expression)
        next_run = compute_next_run(payload.cron_expression)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    sid = new_uuid()
    ts = now_iso()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO schedules (id, server_id, name, cron_expression, is_active, only_when_online, next_run_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (sid, srv["id"], payload.name.strip(), payload.cron_expression.strip(), 1 if payload.is_active else 0, 1 if payload.only_when_online else 0, next_run, ts, ts),
        )
        for idx, t in enumerate(payload.tasks, start=1):
            if t.action not in ("command", "power", "backup"):
                raise HTTPException(status_code=422, detail="Task action must be command, power, or backup.")
            conn.execute(
                """INSERT INTO schedule_tasks (id, schedule_id, sequence_id, action, payload, time_offset, continue_on_failure, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (new_uuid(), sid, idx, t.action, t.payload, t.time_offset, 1 if t.continue_on_failure else 0, ts),
            )
    log_activity("server.schedule.created", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"schedule_id": sid, "name": payload.name})
    return {"status": "ok", "data": {"id": sid, "name": payload.name, "cron_expression": payload.cron_expression, "next_run_at": next_run}}


@router.put("/servers/{server_id}/schedules/{schedule_id}")
def update_schedule(server_id: str, schedule_id: str, payload: ScheduleCreatePayload, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "schedule.manage")
    try:
        validate_cron(payload.cron_expression)
        next_run = compute_next_run(payload.cron_expression)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    ts = now_iso()
    with db_session() as conn:
        cur = conn.execute(
            """UPDATE schedules SET name=?, cron_expression=?, is_active=?, only_when_online=?, next_run_at=?, updated_at=?
               WHERE id=? AND server_id=?""",
            (payload.name.strip(), payload.cron_expression.strip(), 1 if payload.is_active else 0, 1 if payload.only_when_online else 0, next_run, ts, schedule_id, srv["id"]),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        conn.execute("DELETE FROM schedule_tasks WHERE schedule_id = ?", (schedule_id,))
        for idx, t in enumerate(payload.tasks, start=1):
            conn.execute(
                """INSERT INTO schedule_tasks (id, schedule_id, sequence_id, action, payload, time_offset, continue_on_failure, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (new_uuid(), schedule_id, idx, t.action, t.payload, t.time_offset, 1 if t.continue_on_failure else 0, ts),
            )
    return {"status": "ok", "message": "Schedule updated."}


@router.delete("/servers/{server_id}/schedules/{schedule_id}")
def delete_schedule(server_id: str, schedule_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "schedule.manage")
    with db_session() as conn:
        cur = conn.execute("DELETE FROM schedules WHERE id = ? AND server_id = ?", (schedule_id, srv["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Schedule not found.")
    return {"status": "ok", "message": "Schedule deleted."}


@router.post("/servers/{server_id}/schedules/{schedule_id}/execute")
def execute_schedule_now(server_id: str, schedule_id: str, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "schedule.manage")
    with db_session() as conn:
        sched = conn.execute("SELECT * FROM schedules WHERE id = ? AND server_id = ?", (schedule_id, srv["id"])).fetchone()
        if not sched:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        tasks = rows_to_list(conn.execute("SELECT * FROM schedule_tasks WHERE schedule_id = ? ORDER BY sequence_id ASC", (schedule_id,)).fetchall())

    dc = DaemonClient(srv)
    outputs: List[str] = []
    status_str = "success"
    err_msg = ""
    env_vars = json.loads(srv["env_vars"] or "{}") if isinstance(srv["env_vars"], str) else (srv["env_vars"] or {})

    for t in tasks:
        try:
            if t["action"] == "command":
                dc.request("POST", f"/agent/servers/{srv['id']}/command", json_body={"command": t["payload"]})
                outputs.append(f"Executed command: {t['payload']}")
            elif t["action"] == "power":
                dc.request("POST", f"/agent/servers/{srv['id']}/power", json_body={
                    "action": t["payload"] or "restart",
                    "startup_command": srv["startup_command"],
                    "env_vars": env_vars,
                    "port": srv["alloc_port"],
                    "memory_mb": srv["memory_mb"],
                })
                outputs.append(f"Executed power action: {t['payload']}")
            elif t["action"] == "backup":
                bid = new_uuid()
                bname = f"Scheduled: {sched['name']} ({now_iso()})"
                res = dc.request("POST", f"/agent/servers/{srv['id']}/backups", json_body={"backup_id": bid, "name": bname})
                bdata = res["data"]
                with db_session() as conn:
                    conn.execute(
                        """INSERT INTO backups (id, server_id, name, storage_driver, archive_path, size_bytes, checksum, status, completed_at, created_at)
                           VALUES (?, ?, ?, 'local', ?, ?, ?, 'completed', ?, ?)""",
                        (bid, srv["id"], bname, bdata["archive_path"], bdata["size_bytes"], bdata["checksum"], now_iso(), now_iso()),
                    )
                outputs.append(f"Created scheduled backup: {bid}")
        except Exception as exc:
            status_str = "failed"
            err_msg = str(exc)
            outputs.append(f"Task #{t['sequence_id']} failed: {exc}")
            if not t["continue_on_failure"]:
                break

    ts = now_iso()
    with db_session() as conn:
        conn.execute(
            "UPDATE schedules SET last_run_at=?, last_status=?, last_error=?, updated_at=? WHERE id=?",
            (ts, status_str, err_msg, ts, schedule_id),
        )
        conn.execute(
            "INSERT INTO schedule_logs (id, schedule_id, server_id, status, output, error_message, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_uuid(), schedule_id, srv["id"], status_str, "\n".join(outputs), err_msg, ts),
        )
    log_activity("server.schedule.executed", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"schedule_id": schedule_id, "status": status_str})
    return {"status": "ok", "data": {"execution_status": status_str, "output": outputs, "error": err_msg}}


# ==================== SUBUSERS & PERMISSIONS ====================

@router.get("/servers/{server_id}/users")
def list_subusers(server_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "user.manage")
    with db_session() as conn:
        rows = conn.execute(
            """SELECT su.id, su.user_id, su.permissions, su.created_at, u.username, u.email
               FROM subusers su JOIN users u ON u.id = su.user_id
               WHERE su.server_id = ?""",
            (srv["id"],),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["permissions"] = json.loads(d["permissions"] or "[]")
        out.append(d)
    return {"status": "ok", "data": out}


@router.post("/servers/{server_id}/users", status_code=201)
def add_subuser(server_id: str, payload: SubuserPayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "user.manage")
    valid_perms = [p for p in payload.permissions if p in SERVER_PERMISSIONS]
    with db_session() as conn:
        target = None
        if payload.email:
            target = conn.execute("SELECT id, username, email FROM users WHERE LOWER(email) = LOWER(?)", (payload.email.strip(),)).fetchone()
        elif payload.username:
            target = conn.execute("SELECT id, username, email FROM users WHERE LOWER(username) = LOWER(?)", (payload.username.strip(),)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Target user not found.")
        if target["id"] == srv["owner_id"]:
            raise HTTPException(status_code=400, detail="Server owner already has full permissions.")
        suid = new_uuid()
        ts = now_iso()
        try:
            conn.execute(
                "INSERT INTO subusers (id, server_id, user_id, permissions, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (suid, srv["id"], target["id"], json.dumps(valid_perms), ts, ts),
            )
        except Exception:
            raise HTTPException(status_code=409, detail="User is already a subuser on this server.")
    log_activity("server.subuser.added", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"subuser": target["username"], "permissions": valid_perms})
    return {"status": "ok", "data": {"id": suid, "user_id": target["id"], "username": target["username"], "email": target["email"], "permissions": valid_perms}}


@router.put("/servers/{server_id}/users/{subuser_id}")
def update_subuser(server_id: str, subuser_id: str, payload: SubuserUpdatePayload, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "user.manage")
    valid_perms = [p for p in payload.permissions if p in SERVER_PERMISSIONS]
    with db_session() as conn:
        cur = conn.execute(
            "UPDATE subusers SET permissions=?, updated_at=? WHERE id=? AND server_id=?",
            (json.dumps(valid_perms), now_iso(), subuser_id, srv["id"]),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Subuser not found.")
    return {"status": "ok", "data": {"id": subuser_id, "permissions": valid_perms}}


@router.delete("/servers/{server_id}/users/{subuser_id}")
def remove_subuser(server_id: str, subuser_id: str, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "user.manage")
    with db_session() as conn:
        cur = conn.execute("DELETE FROM subusers WHERE id = ? AND server_id = ?", (subuser_id, srv["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Subuser not found.")
    log_activity("server.subuser.removed", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"subuser_id": subuser_id})
    return {"status": "ok", "message": "Subuser access revoked."}


# ==================== DATABASES ====================

@router.get("/servers/{server_id}/databases")
def list_server_databases(server_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "database.manage")
    with db_session() as conn:
        rows = conn.execute(
            """SELECT sd.*, dh.name AS host_name, dh.host, dh.port
               FROM server_databases sd JOIN database_hosts dh ON dh.id = sd.host_id
               WHERE sd.server_id = ? ORDER BY sd.created_at DESC""",
            (srv["id"],),
        ).fetchall()
    return {"status": "ok", "data": rows_to_list(rows), "limit": srv["database_limit"]}


@router.post("/servers/{server_id}/databases", status_code=201)
def create_server_database(server_id: str, payload: DatabaseCreatePayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "database.manage")
    with db_session() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM server_databases WHERE server_id = ?", (srv["id"],)).fetchone()["c"]
        if count >= srv["database_limit"]:
            raise HTTPException(status_code=400, detail=f"Database limit ({srv['database_limit']}) reached.")
        host = conn.execute(
            "SELECT * FROM database_hosts WHERE node_id = ? OR node_id IS NULL ORDER BY CASE WHEN node_id = ? THEN 0 ELSE 1 END LIMIT 1",
            (srv["node_id"], srv["node_id"]),
        ).fetchone()
        if not host:
            raise HTTPException(status_code=400, detail="No database host is configured for this node.")
        safe_name = "".join(c for c in payload.name if c.isalnum() or c == "_")[:32]
        db_name = f"s{srv['uuid_short'][:6]}_{safe_name}"
        db_user = f"u{srv['uuid_short'][:6]}_{secrets.token_hex(3)}"
        db_pass = secrets.token_urlsafe(18)
        did = new_uuid()
        conn.execute(
            """INSERT INTO server_databases (id, server_id, host_id, db_name, db_username, db_password, remote_host, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (did, srv["id"], host["id"], db_name, db_user, db_pass, payload.remote_host.strip() or "%", now_iso()),
        )
    log_activity("server.database.created", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request), metadata={"db_name": db_name})
    return {
        "status": "ok",
        "data": {
            "id": did,
            "db_name": db_name,
            "db_username": db_user,
            "db_password": db_pass,
            "host": host["host"],
            "port": host["port"],
            "remote_host": payload.remote_host.strip() or "%",
        },
    }


@router.delete("/servers/{server_id}/databases/{db_id}")
def delete_server_database(server_id: str, db_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "database.manage")
    with db_session() as conn:
        cur = conn.execute("DELETE FROM server_databases WHERE id = ? AND server_id = ?", (db_id, srv["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Database not found.")
    return {"status": "ok", "message": "Database deleted."}


@router.post("/servers/{server_id}/databases/{db_id}/test")
def test_server_database(server_id: str, db_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "database.manage")
    with db_session() as conn:
        row = conn.execute(
            "SELECT sd.*, dh.host, dh.port FROM server_databases sd JOIN database_hosts dh ON dh.id = sd.host_id WHERE sd.id = ? AND sd.server_id = ?",
            (db_id, srv["id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Database not found.")
    reachable = False
    detail = ""
    try:
        with socket.create_connection((row["host"], int(row["port"])), timeout=2.0):
            reachable = True
            detail = f"TCP connection succeeded to {row['host']}:{row['port']}"
    except OSError as exc:
        detail = f"Host {row['host']}:{row['port']} not listening ({exc})"
    return {"status": "ok", "data": {"reachable": reachable, "detail": detail}}


# ==================== NETWORK ALLOCATIONS ====================

@router.get("/servers/{server_id}/network/allocations")
def list_server_allocations(server_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "network.manage")
    with db_session() as conn:
        rows = conn.execute("SELECT * FROM allocations WHERE server_id = ? ORDER BY port ASC", (srv["id"],)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["is_primary"] = d["id"] == srv["primary_allocation_id"]
        host = d["ip_alias"] or srv["node_fqdn"] or d["ip"]
        d["connection_address"] = f"{host}:{d['port']}"
        out.append(d)
    return {"status": "ok", "data": out, "limit": srv["allocation_limit"]}


@router.post("/servers/{server_id}/network/allocations", status_code=201)
def assign_free_allocation(server_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "network.manage")
    with db_session() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM allocations WHERE server_id = ?", (srv["id"],)).fetchone()["c"]
        if count >= srv["allocation_limit"]:
            raise HTTPException(status_code=400, detail=f"Allocation limit ({srv['allocation_limit']}) reached.")
        free_alloc = conn.execute(
            "SELECT * FROM allocations WHERE node_id = ? AND server_id IS NULL ORDER BY port ASC LIMIT 1",
            (srv["node_id"],),
        ).fetchone()
        if not free_alloc:
            raise HTTPException(status_code=400, detail="No unassigned allocations available on this node.")
        conn.execute("UPDATE allocations SET server_id = ? WHERE id = ?", (srv["id"], free_alloc["id"]))
        d = dict(free_alloc)
        d["server_id"] = srv["id"]
        d["is_primary"] = False
    return {"status": "ok", "data": d}


@router.post("/servers/{server_id}/network/allocations/{alloc_id}/primary")
def set_primary_allocation(server_id: str, alloc_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "network.manage")
    with db_session() as conn:
        alloc = conn.execute("SELECT * FROM allocations WHERE id = ? AND server_id = ?", (alloc_id, srv["id"])).fetchone()
        if not alloc:
            raise HTTPException(status_code=404, detail="Allocation not assigned to this server.")
        conn.execute("UPDATE servers SET primary_allocation_id = ?, updated_at = ? WHERE id = ?", (alloc_id, now_iso(), srv["id"]))
    return {"status": "ok", "message": "Primary allocation updated."}


@router.delete("/servers/{server_id}/network/allocations/{alloc_id}")
def unassign_allocation(server_id: str, alloc_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "network.manage")
    if alloc_id == srv["primary_allocation_id"]:
        raise HTTPException(status_code=400, detail="Cannot remove the primary allocation.")
    with db_session() as conn:
        cur = conn.execute("UPDATE allocations SET server_id = NULL WHERE id = ? AND server_id = ?", (alloc_id, srv["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Allocation not found on this server.")
    return {"status": "ok", "message": "Allocation removed from server."}


# ==================== STARTUP & SETTINGS ====================

@router.put("/servers/{server_id}/startup")
def update_server_startup(server_id: str, payload: ServerStartupUpdatePayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "startup.manage")
    startup = payload.startup_command if payload.startup_command is not None else srv["startup_command"]
    image = payload.docker_image if payload.docker_image is not None else srv["docker_image"]
    env_vars = payload.env_vars if payload.env_vars is not None else json.loads(srv["env_vars"] or "{}")
    with db_session() as conn:
        conn.execute(
            "UPDATE servers SET startup_command=?, docker_image=?, env_vars=?, updated_at=? WHERE id=?",
            (startup, image, json.dumps(env_vars), now_iso(), srv["id"]),
        )
    log_activity("server.startup.updated", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request))
    return {"status": "ok", "message": "Startup configuration updated."}


@router.put("/servers/{server_id}/settings")
def update_server_settings(server_id: str, payload: ServerSettingsUpdatePayload, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "settings.manage")
    name = payload.name.strip() if payload.name else srv["name"]
    desc = payload.description if payload.description is not None else srv["description"]
    with db_session() as conn:
        conn.execute("UPDATE servers SET name=?, description=?, updated_at=? WHERE id=?", (name, desc, now_iso(), srv["id"]))
    log_activity("server.settings.updated", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request))
    return {"status": "ok", "message": "Server settings updated."}


@router.post("/servers/{server_id}/reinstall")
def reinstall_server(server_id: str, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    srv = require_server_permission(server_id, user, "settings.manage")
    with db_session() as conn:
        egg = conn.execute("SELECT * FROM eggs WHERE id = ?", (srv["egg_id"],)).fetchone()
    env_vars = json.loads(srv["env_vars"] or "{}") if isinstance(srv["env_vars"], str) else {}
    res = DaemonClient(srv, timeout=120.0).request(
        "POST",
        f"/agent/servers/{srv['id']}/provision",
        json_body={
            "install_script": egg["install_script"],
            "startup_command": srv["startup_command"],
            "env_vars": env_vars,
            "port": srv["alloc_port"],
            "memory_mb": srv["memory_mb"],
        },
    )
    with db_session() as conn:
        conn.execute("UPDATE servers SET status='offline', install_log=?, updated_at=? WHERE id=?", (res["data"].get("install_log", ""), now_iso(), srv["id"]))
    log_activity("server.reinstalled", actor_id=user["id"], actor_username=user["username"], server_id=srv["id"], ip_address=get_client_ip(request))
    return {"status": "ok", "data": res["data"]}
