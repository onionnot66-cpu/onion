"""Comprehensive End-to-End Automated Test Suite for OMCP ONION."""

import bz2
import gzip
import io
import lzma
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isolate test data directory before importing app modules
TEST_TMP = Path(tempfile.mkdtemp(prefix="omcp_onion_test_"))
os.environ["ONION_DATA_DIR"] = str(TEST_TMP / "panel_data")
os.environ["ONION_DB_PATH"] = str(TEST_TMP / "panel_data" / "test_omcp_onion.db")
os.environ["ONION_AGENT_TOKEN"] = "test-node-secret-token-999"
os.environ["ONION_AGENT_DATA_DIR"] = str(TEST_TMP / "agent_data")

import uvicorn
from starlette.testclient import TestClient

from agent import onion_agent
from panel.database import init_db
from panel.main import app as panel_app


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class OmcpOnionEndToEndTests(unittest.TestCase):
    agent_server = None
    agent_thread = None
    agent_port = None
    client: TestClient = None

    @classmethod
    def setUpClass(cls) -> None:
        init_db()
        cls.agent_port = _find_free_port()
        onion_agent.configure_agent(
            token=os.environ["ONION_AGENT_TOKEN"],
            data_dir=os.environ["ONION_AGENT_DATA_DIR"],
        )
        config = uvicorn.Config(onion_agent.app, host="127.0.0.1", port=cls.agent_port, log_level="error")
        cls.agent_server = uvicorn.Server(config)
        cls.agent_thread = threading.Thread(target=cls.agent_server.run, daemon=True)
        cls.agent_thread.start()
        # Wait for agent to bind
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", cls.agent_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        cls.client = TestClient(panel_app)

    @classmethod
    def tearDownClass(cls) -> None:
        onion_agent.registry.stop_all()
        if cls.agent_server:
            cls.agent_server.should_exit = True
        shutil.rmtree(TEST_TMP, ignore_errors=True)

    def _auth_headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def test_full_platform_lifecycle(self) -> None:
        c = self.client

        # 1. AUTHENTICATION, BOOTSTRAP & SESSION PERSISTENCE
        r = c.get("/api/auth/bootstrap")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["data"]["needs_initial_setup"])
        self.assertEqual(r.json()["data"]["panel_name"], "OMCP ONION")

        # Register initial admin
        r = c.post("/api/auth/register", json={
            "username": "onionadmin",
            "email": "admin@onion.local",
            "password": "AdminPassword123!",
        })
        self.assertEqual(r.status_code, 201, r.text)
        admin_token = r.json()["data"]["token"]
        admin_id = r.json()["data"]["user"]["id"]
        self.assertEqual(r.json()["data"]["user"]["role"], "admin")

        # Verify cookie session persistence across requests
        r = c.get("/api/auth/user")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["username"], "onionadmin")

        # Refresh session
        r = c.post("/api/auth/refresh", headers=self._auth_headers(admin_token))
        self.assertEqual(r.status_code, 200)
        admin_token = r.json()["data"]["token"]

        # Register regular client user + second user (subuser)
        r = c.post("/api/auth/register", json={"username": "player1", "email": "player1@onion.local", "password": "PlayerPassword1!"})
        self.assertEqual(r.status_code, 201)
        player1_token = r.json()["data"]["token"]
        player1_id = r.json()["data"]["user"]["id"]
        self.assertEqual(r.json()["data"]["user"]["role"], "user")

        r = c.post("/api/auth/register", json={"username": "helper1", "email": "helper1@onion.local", "password": "HelperPassword1!"})
        self.assertEqual(r.status_code, 201)
        helper_token = r.json()["data"]["token"]

        # Password reset flow
        r = c.post("/api/auth/forgot-password", json={"email": "helper1@onion.local"})
        self.assertEqual(r.status_code, 200)
        rst_tok = r.json()["data"]["reset_token_preview"]
        self.assertTrue(rst_tok)
        r = c.post("/api/auth/reset-password", json={"token": rst_tok, "new_password": "NewHelperPass123!"})
        self.assertEqual(r.status_code, 200)
        r = c.post("/api/auth/login", json={"identifier": "helper1", "password": "NewHelperPass123!"})
        self.assertEqual(r.status_code, 200)
        helper_token = r.json()["data"]["token"]

        # 2. RBAC ENFORCEMENT (Standard user cannot access Admin API)
        r = c.get("/api/application/overview", headers=self._auth_headers(player1_token))
        self.assertEqual(r.status_code, 403)

        # 3. ADMIN CRUD: LOCATION, NODE, ALLOCATIONS, DB HOST, MOUNT, IMAGE, SETTINGS, API KEY
        ah = self._auth_headers(admin_token)
        r = c.post("/api/application/locations", headers=ah, json={"short_code": "in-agra-1", "description": "Agra Primary DC"})
        self.assertEqual(r.status_code, 201)
        loc_id = r.json()["data"]["id"]

        r = c.post("/api/application/nodes", headers=ah, json={
            "location_id": loc_id,
            "name": "Node-Alpha",
            "fqdn": "node1.onion.local",
            "ip_address": "127.0.0.1",
            "scheme": "http",
            "daemon_port": self.agent_port,
            "daemon_token": os.environ["ONION_AGENT_TOKEN"],
        })
        self.assertEqual(r.status_code, 201)
        node_id = r.json()["data"]["id"]

        # 4. NODE COMMUNICATION & SECURITY TESTS
        r = c.get(f"/api/application/nodes/{node_id}/health", headers=ah)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["status"], "online")

        # Direct unauthenticated call to Node Agent must fail with 401/403
        import httpx
        unauth = httpx.get(f"http://127.0.0.1:{self.agent_port}/agent/health")
        self.assertEqual(unauth.status_code, 401)
        bad_sig = httpx.get(
            f"http://127.0.0.1:{self.agent_port}/agent/health",
            headers={"Authorization": f"Bearer {os.environ['ONION_AGENT_TOKEN']}", "X-Onion-Timestamp": str(int(time.time())), "X-Onion-Signature": "deadbeef"},
        )
        self.assertEqual(bad_sig.status_code, 403)

        # Allocations + Duplicate Prevention
        r = c.post("/api/application/allocations", headers=ah, json={
            "node_id": node_id, "ip": "127.0.0.1", "ip_alias": "play.onion.local", "ports": [25565, 25566]
        })
        self.assertEqual(r.status_code, 201)
        allocs = r.json()["data"]
        self.assertEqual(len(allocs), 2)
        prim_alloc_id = allocs[0]["id"]

        # Duplicate allocation must return 409
        r = c.post("/api/application/allocations", headers=ah, json={
            "node_id": node_id, "ip": "127.0.0.1", "ports": [25565]
        })
        self.assertEqual(r.status_code, 409)

        # Database host, mount, image, settings, maintenance
        r = c.post("/api/application/database-hosts", headers=ah, json={
            "name": "LocalDB", "host": "127.0.0.1", "port": 3306, "username": "root", "password": "secret", "node_id": node_id
        })
        self.assertEqual(r.status_code, 201)
        r = c.post("/api/application/mounts", headers=ah, json={"name": "Maps", "source_path": "/tmp/maps", "target_path": "/maps"})
        self.assertEqual(r.status_code, 201)
        r = c.post("/api/application/images", headers=ah, json={"name": "Custom Py", "image_ref": "python:3.11-alpine", "category": "generic"})
        self.assertEqual(r.status_code, 201)
        r = c.put("/api/application/settings", headers=ah, json={"settings": {"panel_name": "OMCP ONION"}})
        self.assertEqual(r.status_code, 200)
        r = c.post("/api/application/api-keys", headers=ah, json={"memo": "Automation Key"})
        self.assertEqual(r.status_code, 201)

        # 5. SERVER CREATION & REAL PROVISIONING
        r = c.post("/api/application/servers", headers=ah, json={
            "owner_id": player1_id,
            "node_id": node_id,
            "egg_id": "egg-python-runtime",
            "primary_allocation_id": prim_alloc_id,
            "name": "Onion Test Realm",
            "docker_image": "python:3.11-slim",
            "memory_mb": 512,
            "cpu_percent": 100,
            "disk_mb": 2048,
            "env_vars": {"SERVER_MOTD": "Welcome to OMCP ONION"},
        })
        self.assertEqual(r.status_code, 201, r.text)
        server_id = r.json()["data"]["id"]
        self.assertIn("Interactive runtime installed", r.json()["data"]["install_log"])

        # Cross-user isolation: helper1 cannot access player1's server yet
        hh = self._auth_headers(helper_token)
        ph = self._auth_headers(player1_token)
        self.assertEqual(c.get(f"/api/client/servers/{server_id}", headers=hh).status_code, 403)
        self.assertEqual(c.get(f"/api/client/servers/{server_id}", headers=ph).status_code, 200)

        # 6. LIVE POWER & WEBSOCKET CONSOLE TESTS (Real Process + Real Stdout!)
        r = c.post(f"/api/client/servers/{server_id}/power", headers=ph, json={"action": "start"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["state"], "running")

        with c.websocket_connect(f"/api/client/servers/{server_id}/console/ws?token={player1_token}") as ws:
            ws.send_json({"type": "command", "command": "say Hello from OMCP ONION"})
            seen_broadcast = False
            for _ in range(25):
                msg = ws.receive_json()
                if msg.get("type") == "log" and "[Broadcast] Hello from OMCP ONION" in msg.get("line", ""):
                    seen_broadcast = True
                    break
            self.assertTrue(seen_broadcast, "Expected real stdout broadcast over WebSocket console")

        # Verify resources endpoint reports live running state
        r = c.get(f"/api/client/servers/{server_id}/resources", headers=ph)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["state"], "running")

        # 7. FILE MANAGER & SECURITY (Traversal + Symlink Escape)
        r = c.post(f"/api/client/servers/{server_id}/files/write", headers=ph, json={"path": "config/world.yml", "content": "difficulty: hard\n"})
        self.assertEqual(r.status_code, 200)
        r = c.get(f"/api/client/servers/{server_id}/files/read?path=config/world.yml", headers=ph)
        self.assertEqual(r.status_code, 200)
        self.assertIn("difficulty: hard", r.json()["data"]["content"])

        # Path traversal must be rejected (403)
        r = c.get(f"/api/client/servers/{server_id}/files/read?path=../../etc/passwd", headers=ph)
        self.assertEqual(r.status_code, 403)

        # Upload & Download
        r = c.post(
            f"/api/client/servers/{server_id}/files/upload",
            headers=ph,
            files={"file": ("motd.txt", b"OMCP ONION Live Upload", "text/plain")},
            data={"directory": ""},
        )
        self.assertEqual(r.status_code, 200)
        dl = c.get(f"/api/client/servers/{server_id}/files/download?path=motd.txt", headers=ph)
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.content, b"OMCP ONION Live Upload")

        # Copy, Rename, Move, Chmod
        self.assertEqual(c.post(f"/api/client/servers/{server_id}/files/copy", headers=ph, json={"source": "motd.txt", "destination": "motd_copy.txt"}).status_code, 200)
        self.assertEqual(c.post(f"/api/client/servers/{server_id}/files/rename", headers=ph, json={"source": "motd_copy.txt", "destination": "motd_renamed.txt"}).status_code, 200)
        self.assertEqual(c.post(f"/api/client/servers/{server_id}/files/chmod", headers=ph, json={"path": "motd_renamed.txt", "mode": "644"}).status_code, 200)

        # 8. ARCHIVE MANAGER (ZIP, TAR.GZ, TAR.BZ2, TAR.XZ, Damaged, Traversal, Overwrite Protection)
        r = c.post(f"/api/client/servers/{server_id}/files/compress", headers=ph, json={"paths": ["motd.txt"], "archive_name": "pack.zip"})
        self.assertEqual(r.status_code, 200)

        # Extracting pack.zip into root where motd.txt already exists MUST return 409 (no silent overwrite)
        r = c.post(f"/api/client/servers/{server_id}/files/extract", headers=ph, json={"archive_path": "pack.zip", "destination": "", "overwrite": False})
        self.assertEqual(r.status_code, 409)

        # Extracting into a new folder succeeds
        r = c.post(f"/api/client/servers/{server_id}/files/extract", headers=ph, json={"archive_path": "pack.zip", "destination": "unpacked_zip", "overwrite": False})
        self.assertEqual(r.status_code, 200)

        # Test TAR.GZ, TAR.BZ2, TAR.XZ extraction
        for ext, mode in [("sample.tar.gz", "w:gz"), ("sample.tar.bz2", "w:bz2"), ("sample.tar.xz", "w:xz")]:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode=mode) as tf:
                payload = f"content for {ext}".encode()
                ti = tarfile.TarInfo(name=f"file_{ext}.txt")
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
            c.post(f"/api/client/servers/{server_id}/files/upload", headers=ph, files={"file": (ext, buf.getvalue(), "application/octet-stream")}, data={"directory": ""})
            ex = c.post(f"/api/client/servers/{server_id}/files/extract", headers=ph, json={"archive_path": ext, "destination": "unpacked_tar"})
            self.assertEqual(ex.status_code, 200, f"Failed extracting {ext}: {ex.text}")

        # Damaged archive must return 400
        c.post(f"/api/client/servers/{server_id}/files/upload", headers=ph, files={"file": ("broken.zip", b"NOT_A_VALID_ZIP", "application/zip")}, data={"directory": ""})
        r = c.post(f"/api/client/servers/{server_id}/files/extract", headers=ph, json={"archive_path": "broken.zip", "destination": "unpacked_broken"})
        self.assertEqual(r.status_code, 400)

        # Malicious path traversal zip must be blocked (400)
        evil_buf = io.BytesIO()
        with zipfile.ZipFile(evil_buf, "w") as zf:
            zf.writestr("../../pwned.txt", "evil")
        c.post(f"/api/client/servers/{server_id}/files/upload", headers=ph, files={"file": ("evil.zip", evil_buf.getvalue(), "application/zip")}, data={"directory": ""})
        r = c.post(f"/api/client/servers/{server_id}/files/extract", headers=ph, json={"archive_path": "evil.zip", "destination": "unpacked_evil"})
        self.assertEqual(r.status_code, 400)

        # 9. BACKUPS & SAFE RESTORATION
        r = c.post(f"/api/client/servers/{server_id}/backups", headers=ph, json={"name": "Pre-Change Snapshot"})
        self.assertEqual(r.status_code, 201)
        backup_id = r.json()["data"]["id"]
        self.assertEqual(r.json()["data"]["status"], "completed")

        # Download backup
        bdl = c.get(f"/api/client/servers/{server_id}/backups/{backup_id}/download", headers=ph)
        self.assertEqual(bdl.status_code, 200)
        self.assertGreater(len(bdl.content), 20)

        # Modify motd.txt & add an unrelated file, then safely restore (truncate=False)
        c.post(f"/api/client/servers/{server_id}/files/write", headers=ph, json={"path": "motd.txt", "content": "CORRUPTED"})
        c.post(f"/api/client/servers/{server_id}/files/write", headers=ph, json={"path": "unrelated_keep.txt", "content": "KEEP_ME"})
        r = c.post(f"/api/client/servers/{server_id}/backups/{backup_id}/restore", headers=ph, json={"truncate": False})
        self.assertEqual(r.status_code, 200)

        # motd.txt restored AND unrelated_keep.txt preserved!
        self.assertEqual(c.get(f"/api/client/servers/{server_id}/files/read?path=motd.txt", headers=ph).json()["data"]["content"], "OMCP ONION Live Upload")
        self.assertEqual(c.get(f"/api/client/servers/{server_id}/files/read?path=unrelated_keep.txt", headers=ph).json()["data"]["content"], "KEEP_ME")

        # 10. SCHEDULES & EXECUTION
        # Restart server so command task runs cleanly
        c.post(f"/api/client/servers/{server_id}/power", headers=ph, json={"action": "start"})
        r = c.post(f"/api/client/servers/{server_id}/schedules", headers=ph, json={
            "name": "Status & Backup",
            "cron_expression": "*/15 * * * *",
            "is_active": True,
            "tasks": [
                {"action": "command", "payload": "status"},
                {"action": "backup", "payload": ""},
            ],
        })
        self.assertEqual(r.status_code, 201)
        sched_id = r.json()["data"]["id"]
        r = c.post(f"/api/client/servers/{server_id}/schedules/{sched_id}/execute", headers=ph)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["execution_status"], "success")

        # 11. GRANULAR SUBUSER PERMISSIONS
        r = c.post(f"/api/client/servers/{server_id}/users", headers=ph, json={
            "email": "helper1@onion.local",
            "permissions": ["console.access", "file.read"],
        })
        self.assertEqual(r.status_code, 201)
        # helper1 can read files & console, but CANNOT write files or delete backups
        self.assertEqual(c.get(f"/api/client/servers/{server_id}/files", headers=hh).status_code, 200)
        self.assertEqual(c.post(f"/api/client/servers/{server_id}/files/write", headers=hh, json={"path": "x.txt", "content": "no"}).status_code, 403)
        self.assertEqual(c.get(f"/api/client/servers/{server_id}/backups", headers=hh).status_code, 403)

        # 12. DATABASES & NETWORK ALLOCATIONS
        r = c.post(f"/api/client/servers/{server_id}/databases", headers=ph, json={"name": "game_stats"})
        self.assertEqual(r.status_code, 201)
        db_id = r.json()["data"]["id"]
        r = c.post(f"/api/client/servers/{server_id}/databases/{db_id}/test", headers=ph)
        self.assertEqual(r.status_code, 200)

        r = c.post(f"/api/client/servers/{server_id}/network/allocations", headers=ph)
        self.assertEqual(r.status_code, 201)
        second_alloc_id = r.json()["data"]["id"]
        self.assertEqual(c.post(f"/api/client/servers/{server_id}/network/allocations/{second_alloc_id}/primary", headers=ph).status_code, 200)
        # Old primary can now be removed
        self.assertEqual(c.delete(f"/api/client/servers/{server_id}/network/allocations/{prim_alloc_id}", headers=ph).status_code, 200)

        # Stop server cleanly
        r = c.post(f"/api/client/servers/{server_id}/power", headers=ph, json={"action": "stop"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["state"], "offline")

        # 13. UPDATER & ROLLBACK VERIFICATION
        upd_tmp = TEST_TMP / "update_sim"
        inst_dir = upd_tmp / "install"
        data_dir = upd_tmp / "data"
        bkp_dir = upd_tmp / "backups"
        world_file = data_dir / "agent" / "servers" / "srv1" / "world.dat"
        world_file.parent.mkdir(parents=True, exist_ok=True)
        world_file.write_text("PRECIOUS_WORLD_DATA")

        env = os.environ.copy()
        env["ONION_INSTALL_DIR"] = str(inst_dir)
        env["ONION_DATA_DIR"] = str(data_dir)
        env["ONION_UPDATE_BACKUP_DIR"] = str(bkp_dir)
        res_upd = subprocess.run(["bash", str(ROOT / "scripts" / "update.sh"), str(ROOT)], env=env, capture_output=True, text=True)
        self.assertEqual(res_upd.returncode, 0, res_upd.stderr + res_upd.stdout)
        self.assertEqual(world_file.read_text(), "PRECIOUS_WORLD_DATA")

        res_rb = subprocess.run(["bash", str(ROOT / "scripts" / "rollback.sh")], env=env, capture_output=True, text=True)
        self.assertEqual(res_rb.returncode, 0, res_rb.stderr + res_rb.stdout)
        self.assertEqual(world_file.read_text(), "PRECIOUS_WORLD_DATA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
