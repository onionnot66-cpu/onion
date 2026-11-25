"""Administrator Panel REST APIs covering all 17 admin sections of OMCP ONION."""

import json
import secrets
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from panel.config import UPLOAD_DIR, settings
from panel.daemon_client import DaemonClient
from panel.database import db_session, new_uuid, now_iso, rows_to_list
from panel.security import (
    generate_token,
    get_client_ip,
    hash_password,
    hash_token,
    log_activity,
    require_admin,
    sanitize_server_public,
)

router = APIRouter(prefix="/api/application", tags=["Administrator API"])


# ==================== SCHEMAS ====================

class AdminUserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: str
    password: str = Field(..., min_length=8)
    first_name: str = ""
    last_name: str = ""
    role: str = "user"


class AdminUserUpdate(BaseModel):
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None


class LocationCreate(BaseModel):
    short_code: str = Field(..., min_length=2, max_length=32)
    description: str = ""


class NodeCreate(BaseModel):
    location_id: str
    name: str
    description: str = ""
    fqdn: str
    ip_address: str
    scheme: str = "http"
    daemon_port: int = 8443
    sftp_port: int = 2022
    memory_mb: int = 8192
    memory_overallocate: int = 0
    disk_mb: int = 51200
    disk_overallocate: int = 0
    cpu_limit: int = 400
    daemon_token: Optional[str] = None
    is_public: bool = True
    maintenance_mode: bool = False


class AllocationCreate(BaseModel):
    node_id: str
    ip: str
    ip_alias: str = ""
    ports: List[int] = Field(..., min_items=1)
    notes: str = ""


class NestCreate(BaseModel):
    name: str
    description: str = ""
    author: str = "OMCP ONION"


class EggCreate(BaseModel):
    nest_id: str
    name: str
    description: str = ""
    docker_images: List[str] = ["python:3.11-slim"]
    startup_command: str
    install_script: str = "#!/bin/sh\necho 'Installed'"
    install_container: str = "alpine:3.19"
    default_memory_mb: int = 1024
    default_cpu_percent: int = 100
    default_disk_mb: int = 5120
    supported_ports: List[int] = [25565]
    variables: List[Dict[str, Any]] = []


class ServerCreate(BaseModel):
    owner_id: str
    node_id: str
    egg_id: str
    primary_allocation_id: str
    name: str = Field(..., min_length=2, max_length=120)
    description: str = ""
    docker_image: str
    startup_command: Optional[str] = None
    env_vars: Dict[str, Any] = {}
    memory_mb: int = Field(1024, ge=64)
    cpu_percent: int = Field(100, ge=10)
    disk_mb: int = Field(2048, ge=128)
    backup_limit: int = Field(5, ge=0)
    database_limit: int = Field(2, ge=0)
    allocation_limit: int = Field(3, ge=1)


class ServerAdminUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    owner_id: Optional[str] = None
    node_id: Optional[str] = None
    primary_allocation_id: Optional[str] = None
    memory_mb: Optional[int] = None
    cpu_percent: Optional[int] = None
    disk_mb: Optional[int] = None
    backup_limit: Optional[int] = None
    database_limit: Optional[int] = None
    allocation_limit: Optional[int] = None
    startup_command: Optional[str] = None
    docker_image: Optional[str] = None
    env_vars: Optional[Dict[str, Any]] = None


class DatabaseHostCreate(BaseModel):
    name: str
    host: str
    port: int = 3306
    username: str
    password: str
    max_databases: int = 50
    node_id: Optional[str] = None


class MountCreate(BaseModel):
    name: str
    description: str = ""
    source_path: str
    target_path: str
    read_only: bool = True
    user_mountable: bool = False
    node_ids: List[str] = []
    egg_ids: List[str] = []


class ServerImageCreate(BaseModel):
    name: str
    image_ref: str
    category: str = "game"
    description: str = ""
    is_default: bool = False


class AdminApiKeyCreate(BaseModel):
    memo: str
    permissions: List[str] = ["*"]


class SettingsUpdate(BaseModel):
    settings: Dict[str, str]


# ==================== OVERVIEW DASHBOARD ====================

@router.get("/overview")
def admin_overview(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        total_users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        total_servers = conn.execute("SELECT COUNT(*) AS c FROM servers").fetchone()["c"]
        nodes = rows_to_list(conn.execute("SELECT * FROM nodes ORDER BY created_at DESC").fetchall())
        recent_activity = rows_to_list(conn.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 12").fetchall())
        recent_servers = rows_to_list(conn.execute(
            """SELECT s.id, s.name, s.status, s.created_at, u.username AS owner_username, n.name AS node_name, e.name AS egg_name
               FROM servers s JOIN users u ON u.id=s.owner_id JOIN nodes n ON n.id=s.node_id JOIN eggs e ON e.id=s.egg_id
               ORDER BY s.created_at DESC LIMIT 8"""
        ).fetchall())

    online_servers = 0
    node_health_list = []
    total_cpu_cores = 0
    total_mem_used = 0
    total_mem_total = 0
    total_disk_used = 0
    total_disk_total = 0

    for n in nodes:
        health = {"status": "offline", "running_servers": 0, "cpu_cores": 0, "memory_used_bytes": 0, "memory_total_bytes": 0, "disk_used_bytes": 0, "disk_total_bytes": 0}
        try:
            res = DaemonClient(n, timeout=2.0).request("GET", "/agent/health")
            health = res.get("data", health)
            online_servers += int(health.get("running_servers", 0))
            total_cpu_cores += int(health.get("cpu_cores", 0))
            total_mem_used += int(health.get("memory_used_bytes", 0))
            total_mem_total += int(health.get("memory_total_bytes", 0))
            total_disk_used += int(health.get("disk_used_bytes", 0))
            total_disk_total += int(health.get("disk_total_bytes", 0))
        except Exception as exc:
            health["error"] = str(exc)
        node_health_list.append({
            "id": n["id"],
            "name": n["name"],
            "fqdn": n["fqdn"],
            "health": health,
        })

    return {
        "status": "ok",
        "data": {
            "stats": {
                "total_users": total_users,
                "total_servers": total_servers,
                "online_servers": online_servers,
                "offline_servers": max(0, total_servers - online_servers),
                "total_nodes": len(nodes),
                "online_nodes": sum(1 for nh in node_health_list if nh["health"].get("status") == "online"),
                "cpu_cores": total_cpu_cores,
                "memory_used_bytes": total_mem_used,
                "memory_total_bytes": total_mem_total,
                "disk_used_bytes": total_disk_used,
                "disk_total_bytes": total_disk_total,
            },
            "nodes": node_health_list,
            "recent_activity": recent_activity,
            "recent_installations": recent_servers,
            "system_health": {"panel_version": settings.VERSION, "database": "healthy"},
        },
    }


# ==================== USERS ====================

@router.get("/users")
def admin_list_users(search: str = "", admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        if search:
            like = f"%{search}%"
            rows = conn.execute(
                "SELECT id, username, email, first_name, last_name, role, is_suspended, language, created_at FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY created_at DESC",
                (like, like),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, username, email, first_name, last_name, role, is_suspended, language, created_at FROM users ORDER BY created_at DESC"
            ).fetchall()
        users = rows_to_list(rows)
        for u in users:
            u["server_count"] = conn.execute("SELECT COUNT(*) AS c FROM servers WHERE owner_id = ?", (u["id"],)).fetchone()["c"]
    return {"status": "ok", "data": users}


@router.post("/users", status_code=201)
def admin_create_user(payload: AdminUserCreate, request: Request, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    if payload.role not in ("user", "admin"):
        raise HTTPException(status_code=422, detail="Role must be 'user' or 'admin'.")
    uid = new_uuid()
    ts = now_iso()
    with db_session() as conn:
        exists = conn.execute("SELECT id FROM users WHERE LOWER(username)=LOWER(?) OR LOWER(email)=LOWER(?)", (payload.username, payload.email)).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="Username or email already exists.")
        conn.execute(
            """INSERT INTO users (id, username, email, password_hash, first_name, last_name, role, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (uid, payload.username.strip(), payload.email.strip().lower(), hash_password(payload.password), payload.first_name, payload.last_name, payload.role, ts, ts),
        )
    log_activity("admin.user.created", actor_id=admin["id"], actor_username=admin["username"], ip_address=get_client_ip(request), metadata={"created_user": payload.username})
    return {"status": "ok", "data": {"id": uid, "username": payload.username, "email": payload.email, "role": payload.role}}


@router.put("/users/{user_id}")
def admin_update_user(user_id: str, payload: AdminUserUpdate, request: Request, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not u:
            raise HTTPException(status_code=404, detail="User not found.")
        email = payload.email.strip().lower() if payload.email else u["email"]
        fn = payload.first_name if payload.first_name is not None else u["first_name"]
        ln = payload.last_name if payload.last_name is not None else u["last_name"]
        role = payload.role if payload.role in ("user", "admin") else u["role"]
        pw_hash = hash_password(payload.password) if payload.password else u["password_hash"]
        conn.execute(
            "UPDATE users SET email=?, first_name=?, last_name=?, role=?, password_hash=?, updated_at=? WHERE id=?",
            (email, fn, ln, role, pw_hash, now_iso(), user_id),
        )
    log_activity("admin.user.updated", actor_id=admin["id"], actor_username=admin["username"], ip_address=get_client_ip(request), metadata={"user_id": user_id})
    return {"status": "ok", "message": "User updated."}


@router.post("/users/{user_id}/suspend")
def admin_suspend_user(user_id: str, request: Request, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot suspend your own administrator account.")
    with db_session() as conn:
        conn.execute("UPDATE users SET is_suspended = 1, updated_at = ? WHERE id = ?", (now_iso(), user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    log_activity("admin.user.suspended", actor_id=admin["id"], actor_username=admin["username"], ip_address=get_client_ip(request), metadata={"user_id": user_id})
    return {"status": "ok", "message": "User suspended."}


@router.post("/users/{user_id}/unsuspend")
def admin_unsuspend_user(user_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        conn.execute("UPDATE users SET is_suspended = 0, updated_at = ? WHERE id = ?", (now_iso(), user_id))
    return {"status": "ok", "message": "User unsuspended."}


@router.delete("/users/{user_id}")
def admin_delete_user(user_id: str, request: Request, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own administrator account.")
    with db_session() as conn:
        owned = conn.execute("SELECT COUNT(*) AS c FROM servers WHERE owner_id = ?", (user_id,)).fetchone()["c"]
        if owned > 0:
            raise HTTPException(status_code=400, detail="Reassign or delete the user's servers before deleting the account.")
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found.")
    log_activity("admin.user.deleted", actor_id=admin["id"], actor_username=admin["username"], ip_address=get_client_ip(request), metadata={"user_id": user_id})
    return {"status": "ok", "message": "User deleted."}


# ==================== LOCATIONS ====================

@router.get("/locations")
def admin_list_locations(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM locations ORDER BY short_code ASC").fetchall())
        for loc in rows:
            loc["node_count"] = conn.execute("SELECT COUNT(*) AS c FROM nodes WHERE location_id = ?", (loc["id"],)).fetchone()["c"]
    return {"status": "ok", "data": rows}


@router.post("/locations", status_code=201)
def admin_create_location(payload: LocationCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    lid = new_uuid()
    ts = now_iso()
    with db_session() as conn:
        try:
            conn.execute("INSERT INTO locations (id, short_code, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", (lid, payload.short_code.strip(), payload.description, ts, ts))
        except Exception:
            raise HTTPException(status_code=409, detail="Location short code already exists.")
    return {"status": "ok", "data": {"id": lid, "short_code": payload.short_code.strip(), "description": payload.description}}


@router.put("/locations/{loc_id}")
def admin_update_location(loc_id: str, payload: LocationCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        cur = conn.execute("UPDATE locations SET short_code=?, description=?, updated_at=? WHERE id=?", (payload.short_code.strip(), payload.description, now_iso(), loc_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Location not found.")
    return {"status": "ok", "message": "Location updated."}


@router.delete("/locations/{loc_id}")
def admin_delete_location(loc_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        nodes = conn.execute("SELECT COUNT(*) AS c FROM nodes WHERE location_id = ?", (loc_id,)).fetchone()["c"]
        if nodes > 0:
            raise HTTPException(status_code=400, detail="Remove nodes from this location before deleting it.")
        conn.execute("DELETE FROM locations WHERE id = ?", (loc_id,))
    return {"status": "ok", "message": "Location deleted."}


# ==================== NODES ====================

@router.get("/nodes")
def admin_list_nodes(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = rows_to_list(conn.execute(
            """SELECT n.*, l.short_code AS location_code
               FROM nodes n JOIN locations l ON l.id = n.location_id
               ORDER BY n.created_at DESC"""
        ).fetchall())
        for n in rows:
            n["server_count"] = conn.execute("SELECT COUNT(*) AS c FROM servers WHERE node_id = ?", (n["id"],)).fetchone()["c"]
            n["allocation_count"] = conn.execute("SELECT COUNT(*) AS c FROM allocations WHERE node_id = ?", (n["id"],)).fetchone()["c"]
    return {"status": "ok", "data": rows}


@router.post("/nodes", status_code=201)
def admin_create_node(payload: NodeCreate, request: Request, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    nid = new_uuid()
    ts = now_iso()
    token = payload.daemon_token or generate_token("node")
    with db_session() as conn:
        loc = conn.execute("SELECT id FROM locations WHERE id = ?", (payload.location_id,)).fetchone()
        if not loc:
            raise HTTPException(status_code=404, detail="Location not found.")
        conn.execute(
            """INSERT INTO nodes (
                id, location_id, name, description, fqdn, ip_address, scheme, daemon_port, sftp_port,
                memory_mb, memory_overallocate, disk_mb, disk_overallocate, cpu_limit, daemon_token,
                is_public, maintenance_mode, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                nid, payload.location_id, payload.name.strip(), payload.description, payload.fqdn.strip(),
                payload.ip_address.strip(), payload.scheme, payload.daemon_port, payload.sftp_port,
                payload.memory_mb, payload.memory_overallocate, payload.disk_mb, payload.disk_overallocate,
                payload.cpu_limit, token, 1 if payload.is_public else 0, 1 if payload.maintenance_mode else 0, ts, ts,
            ),
        )
    log_activity("admin.node.created", actor_id=admin["id"], actor_username=admin["username"], ip_address=get_client_ip(request), metadata={"node_id": nid, "name": payload.name})
    return {"status": "ok", "data": {"id": nid, "name": payload.name, "fqdn": payload.fqdn, "daemon_token": token}}


@router.put("/nodes/{node_id}")
def admin_update_node(node_id: str, payload: NodeCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        existing = conn.execute("SELECT daemon_token FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Node not found.")
        token = payload.daemon_token or existing["daemon_token"]
        conn.execute(
            """UPDATE nodes SET location_id=?, name=?, description=?, fqdn=?, ip_address=?, scheme=?, daemon_port=?,
               sftp_port=?, memory_mb=?, memory_overallocate=?, disk_mb=?, disk_overallocate=?, cpu_limit=?,
               daemon_token=?, is_public=?, maintenance_mode=?, updated_at=? WHERE id=?""",
            (
                payload.location_id, payload.name.strip(), payload.description, payload.fqdn.strip(),
                payload.ip_address.strip(), payload.scheme, payload.daemon_port, payload.sftp_port,
                payload.memory_mb, payload.memory_overallocate, payload.disk_mb, payload.disk_overallocate,
                payload.cpu_limit, token, 1 if payload.is_public else 0, 1 if payload.maintenance_mode else 0, now_iso(), node_id,
            ),
        )
    return {"status": "ok", "message": "Node updated."}


@router.delete("/nodes/{node_id}")
def admin_delete_node(node_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        srvs = conn.execute("SELECT COUNT(*) AS c FROM servers WHERE node_id = ?", (node_id,)).fetchone()["c"]
        if srvs > 0:
            raise HTTPException(status_code=400, detail="Migrate or delete servers on this node first.")
        conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
    return {"status": "ok", "message": "Node deleted."}


@router.get("/nodes/{node_id}/health")
def admin_node_health(node_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if not node:
            raise HTTPException(status_code=404, detail="Node not found.")
        nd = dict(node)
    try:
        res = DaemonClient(nd, timeout=3.0).request("GET", "/agent/health")
        with db_session() as conn:
            conn.execute("UPDATE nodes SET status='online', last_heartbeat_at=?, last_error='' WHERE id=?", (now_iso(), node_id))
        return {"status": "ok", "data": res["data"]}
    except HTTPException as exc:
        with db_session() as conn:
            conn.execute("UPDATE nodes SET status='offline', last_error=? WHERE id=?", (str(exc.detail), node_id))
        return {"status": "error", "data": {"status": "offline", "error": exc.detail}}


# ==================== ALLOCATIONS ====================

@router.get("/allocations")
def admin_list_allocations(node_id: Optional[str] = None, unassigned_only: bool = False, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    query = """SELECT a.*, n.name AS node_name, n.fqdn AS node_fqdn, s.name AS server_name
               FROM allocations a
               JOIN nodes n ON n.id = a.node_id
               LEFT JOIN servers s ON s.id = a.server_id
               WHERE 1=1"""
    params: List[Any] = []
    if node_id:
        query += " AND a.node_id = ?"
        params.append(node_id)
    if unassigned_only:
        query += " AND a.server_id IS NULL"
    query += " ORDER BY a.port ASC"
    with db_session() as conn:
        rows = rows_to_list(conn.execute(query, params).fetchall())
    return {"status": "ok", "data": rows}


@router.post("/allocations", status_code=201)
def admin_create_allocations(payload: AllocationCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    created = []
    ts = now_iso()
    with db_session() as conn:
        node = conn.execute("SELECT id FROM nodes WHERE id = ?", (payload.node_id,)).fetchone()
        if not node:
            raise HTTPException(status_code=404, detail="Node not found.")
        for port in payload.ports:
            if port < 1024 or port > 65535:
                raise HTTPException(status_code=422, detail=f"Port {port} must be between 1024 and 65535.")
            dup = conn.execute("SELECT id FROM allocations WHERE node_id=? AND ip=? AND port=?", (payload.node_id, payload.ip.strip(), port)).fetchone()
            if dup:
                raise HTTPException(status_code=409, detail=f"Allocation {payload.ip}:{port} already exists on this node.")
            aid = new_uuid()
            conn.execute(
                "INSERT INTO allocations (id, node_id, ip, ip_alias, port, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (aid, payload.node_id, payload.ip.strip(), payload.ip_alias.strip(), port, payload.notes, ts),
            )
            created.append({"id": aid, "node_id": payload.node_id, "ip": payload.ip.strip(), "ip_alias": payload.ip_alias.strip(), "port": port})
    return {"status": "ok", "data": created}


@router.delete("/allocations/{alloc_id}")
def admin_delete_allocation(alloc_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        a = conn.execute("SELECT server_id FROM allocations WHERE id = ?", (alloc_id,)).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Allocation not found.")
        if a["server_id"]:
            raise HTTPException(status_code=400, detail="Cannot delete an allocation assigned to a server.")
        conn.execute("DELETE FROM allocations WHERE id = ?", (alloc_id,))
    return {"status": "ok", "message": "Allocation deleted."}


# ==================== NESTS & EGGS ====================

@router.get("/nests")
def admin_list_nests(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        nests = rows_to_list(conn.execute("SELECT * FROM nests ORDER BY name ASC").fetchall())
        for n in nests:
            n["egg_count"] = conn.execute("SELECT COUNT(*) AS c FROM eggs WHERE nest_id = ?", (n["id"],)).fetchone()["c"]
    return {"status": "ok", "data": nests}


@router.post("/nests", status_code=201)
def admin_create_nest(payload: NestCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    nid = new_uuid()
    ts = now_iso()
    with db_session() as conn:
        try:
            conn.execute("INSERT INTO nests (id, name, description, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (nid, payload.name.strip(), payload.description, payload.author, ts, ts))
        except Exception:
            raise HTTPException(status_code=409, detail="Nest with that name already exists.")
    return {"status": "ok", "data": {"id": nid, "name": payload.name.strip()}}


@router.delete("/nests/{nest_id}")
def admin_delete_nest(nest_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        conn.execute("DELETE FROM nests WHERE id = ?", (nest_id,))
    return {"status": "ok", "message": "Nest deleted."}


@router.get("/eggs")
def admin_list_eggs(nest_id: Optional[str] = None, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        if nest_id:
            rows = rows_to_list(conn.execute("SELECT * FROM eggs WHERE nest_id = ? ORDER BY name ASC", (nest_id,)).fetchall())
        else:
            rows = rows_to_list(conn.execute("SELECT e.*, n.name AS nest_name FROM eggs e JOIN nests n ON n.id = e.nest_id ORDER BY e.name ASC").fetchall())
    for r in rows:
        r["docker_images"] = json.loads(r["docker_images"] or "[]")
        r["supported_ports"] = json.loads(r["supported_ports"] or "[]")
        r["variables"] = json.loads(r["variables"] or "[]")
    return {"status": "ok", "data": rows}


@router.post("/eggs", status_code=201)
def admin_create_egg(payload: EggCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    eid = new_uuid()
    ts = now_iso()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO eggs (
                id, nest_id, name, description, docker_images, startup_command, install_script,
                install_container, default_memory_mb, default_cpu_percent, default_disk_mb,
                supported_ports, variables, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                eid, payload.nest_id, payload.name.strip(), payload.description, json.dumps(payload.docker_images),
                payload.startup_command, payload.install_script, payload.install_container,
                payload.default_memory_mb, payload.default_cpu_percent, payload.default_disk_mb,
                json.dumps(payload.supported_ports), json.dumps(payload.variables), ts, ts,
            ),
        )
    return {"status": "ok", "data": {"id": eid, "name": payload.name.strip()}}


@router.put("/eggs/{egg_id}")
def admin_update_egg(egg_id: str, payload: EggCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        cur = conn.execute(
            """UPDATE eggs SET nest_id=?, name=?, description=?, docker_images=?, startup_command=?,
               install_script=?, install_container=?, default_memory_mb=?, default_cpu_percent=?,
               default_disk_mb=?, supported_ports=?, variables=?, updated_at=? WHERE id=?""",
            (
                payload.nest_id, payload.name.strip(), payload.description, json.dumps(payload.docker_images),
                payload.startup_command, payload.install_script, payload.install_container,
                payload.default_memory_mb, payload.default_cpu_percent, payload.default_disk_mb,
                json.dumps(payload.supported_ports), json.dumps(payload.variables), now_iso(), egg_id,
            ),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Egg not found.")
    return {"status": "ok", "message": "Egg updated."}


@router.delete("/eggs/{egg_id}")
def admin_delete_egg(egg_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        used = conn.execute("SELECT COUNT(*) AS c FROM servers WHERE egg_id = ?", (egg_id,)).fetchone()["c"]
        if used > 0:
            raise HTTPException(status_code=400, detail="Cannot delete an egg currently used by servers.")
        conn.execute("DELETE FROM eggs WHERE id = ?", (egg_id,))
    return {"status": "ok", "message": "Egg deleted."}


# ==================== SERVERS (REAL PROVISIONING) ====================

@router.get("/servers")
def admin_list_servers(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = conn.execute(
            """SELECT s.*, u.username AS owner_username, n.name AS node_name, n.fqdn AS node_fqdn,
                      e.name AS egg_name, a.ip AS alloc_ip, a.ip_alias AS alloc_alias, a.port AS alloc_port
               FROM servers s
               JOIN users u ON u.id = s.owner_id
               JOIN nodes n ON n.id = s.node_id
               JOIN eggs e ON e.id = s.egg_id
               JOIN allocations a ON a.id = s.primary_allocation_id
               ORDER BY s.created_at DESC"""
        ).fetchall()
    return {"status": "ok", "data": [sanitize_server_public(dict(r)) for r in rows]}


@router.post("/servers", status_code=201)
def admin_create_server(payload: ServerCreate, request: Request, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Create server record AND genuinely provision it on the target Node Agent."""
    sid = new_uuid()
    uuid_short = sid.split("-")[0]
    ts = now_iso()

    with db_session() as conn:
        owner = conn.execute("SELECT id FROM users WHERE id = ?", (payload.owner_id,)).fetchone()
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (payload.node_id,)).fetchone()
        egg = conn.execute("SELECT * FROM eggs WHERE id = ?", (payload.egg_id,)).fetchone()
        alloc = conn.execute("SELECT * FROM allocations WHERE id = ? AND node_id = ?", (payload.primary_allocation_id, payload.node_id)).fetchone()
        if not owner:
            raise HTTPException(status_code=404, detail="Owner user not found.")
        if not node:
            raise HTTPException(status_code=404, detail="Target node not found.")
        if not egg:
            raise HTTPException(status_code=404, detail="Selected egg not found.")
        if not alloc:
            raise HTTPException(status_code=404, detail="Allocation not found on the selected node.")
        if alloc["server_id"] is not None:
            raise HTTPException(status_code=409, detail="Selected allocation is already assigned to another server.")

        startup_cmd = payload.startup_command or egg["startup_command"]
        conn.execute(
            """INSERT INTO servers (
                id, uuid_short, owner_id, node_id, egg_id, primary_allocation_id, name, description,
                docker_image, startup_command, env_vars, memory_mb, cpu_percent, disk_mb,
                backup_limit, database_limit, allocation_limit, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'installing', ?, ?)""",
            (
                sid, uuid_short, payload.owner_id, payload.node_id, payload.egg_id, payload.primary_allocation_id,
                payload.name.strip(), payload.description, payload.docker_image, startup_cmd,
                json.dumps(payload.env_vars), payload.memory_mb, payload.cpu_percent, payload.disk_mb,
                payload.backup_limit, payload.database_limit, payload.allocation_limit, ts, ts,
            ),
        )
        conn.execute("UPDATE allocations SET server_id = ? WHERE id = ?", (sid, payload.primary_allocation_id))
        node_dict = dict(node)
        egg_dict = dict(egg)
        alloc_port = alloc["port"]

    # Provision directly on the Node Agent
    try:
        res = DaemonClient(node_dict, timeout=120.0).request(
            "POST",
            f"/agent/servers/{sid}/provision",
            json_body={
                "install_script": egg_dict["install_script"],
                "startup_command": startup_cmd,
                "env_vars": payload.env_vars,
                "port": alloc_port,
                "memory_mb": payload.memory_mb,
            },
        )
        install_log = res["data"].get("install_log", "")
        with db_session() as conn:
            conn.execute("UPDATE servers SET status='offline', install_log=?, updated_at=? WHERE id=?", (install_log, now_iso(), sid))
    except HTTPException as exc:
        with db_session() as conn:
            conn.execute("UPDATE servers SET status='install_failed', install_log=?, updated_at=? WHERE id=?", (str(exc.detail), now_iso(), sid))
        raise HTTPException(status_code=502, detail=f"Server created in DB but node provisioning failed: {exc.detail}")

    log_activity("admin.server.created", actor_id=admin["id"], actor_username=admin["username"], server_id=sid, ip_address=get_client_ip(request), metadata={"name": payload.name, "node": node_dict["name"]})
    return {
        "status": "ok",
        "data": {
            "id": sid,
            "uuid_short": uuid_short,
            "name": payload.name.strip(),
            "status": "offline",
            "install_log": install_log,
        },
    }


@router.put("/servers/{server_id}")
def admin_update_server(server_id: str, payload: ServerAdminUpdate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        s = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not s:
            raise HTTPException(status_code=404, detail="Server not found.")
        updates = {
            "name": payload.name if payload.name is not None else s["name"],
            "description": payload.description if payload.description is not None else s["description"],
            "owner_id": payload.owner_id if payload.owner_id is not None else s["owner_id"],
            "node_id": payload.node_id if payload.node_id is not None else s["node_id"],
            "primary_allocation_id": payload.primary_allocation_id if payload.primary_allocation_id is not None else s["primary_allocation_id"],
            "memory_mb": payload.memory_mb if payload.memory_mb is not None else s["memory_mb"],
            "cpu_percent": payload.cpu_percent if payload.cpu_percent is not None else s["cpu_percent"],
            "disk_mb": payload.disk_mb if payload.disk_mb is not None else s["disk_mb"],
            "backup_limit": payload.backup_limit if payload.backup_limit is not None else s["backup_limit"],
            "database_limit": payload.database_limit if payload.database_limit is not None else s["database_limit"],
            "allocation_limit": payload.allocation_limit if payload.allocation_limit is not None else s["allocation_limit"],
            "startup_command": payload.startup_command if payload.startup_command is not None else s["startup_command"],
            "docker_image": payload.docker_image if payload.docker_image is not None else s["docker_image"],
            "env_vars": json.dumps(payload.env_vars) if payload.env_vars is not None else s["env_vars"],
        }
        conn.execute(
            """UPDATE servers SET name=?, description=?, owner_id=?, node_id=?, primary_allocation_id=?,
               memory_mb=?, cpu_percent=?, disk_mb=?, backup_limit=?, database_limit=?, allocation_limit=?,
               startup_command=?, docker_image=?, env_vars=?, updated_at=? WHERE id=?""",
            (*updates.values(), now_iso(), server_id),
        )
    return {"status": "ok", "message": "Server updated."}


@router.post("/servers/{server_id}/suspend")
def admin_suspend_server(server_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        s = conn.execute("SELECT s.*, n.ip_address AS node_ip, n.scheme AS node_scheme, n.daemon_port, n.daemon_token FROM servers s JOIN nodes n ON n.id = s.node_id WHERE s.id = ?", (server_id,)).fetchone()
        if not s:
            raise HTTPException(status_code=404, detail="Server not found.")
        conn.execute("UPDATE servers SET is_suspended = 1, status = 'suspended', updated_at = ? WHERE id = ?", (now_iso(), server_id))
    try:
        DaemonClient(dict(s)).request("POST", f"/agent/servers/{server_id}/power", json_body={"action": "stop"})
    except Exception:
        pass
    return {"status": "ok", "message": "Server suspended."}


@router.post("/servers/{server_id}/unsuspend")
def admin_unsuspend_server(server_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        conn.execute("UPDATE servers SET is_suspended = 0, status = 'offline', updated_at = ? WHERE id = ?", (now_iso(), server_id))
    return {"status": "ok", "message": "Server unsuspended."}


@router.delete("/servers/{server_id}")
def admin_delete_server(server_id: str, request: Request, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        s = conn.execute("SELECT s.*, n.ip_address AS node_ip, n.scheme AS node_scheme, n.daemon_port, n.daemon_token FROM servers s JOIN nodes n ON n.id = s.node_id WHERE s.id = ?", (server_id,)).fetchone()
        if not s:
            raise HTTPException(status_code=404, detail="Server not found.")
        node_info = dict(s)
    try:
        DaemonClient(node_info).request("DELETE", f"/agent/servers/{server_id}")
    except Exception:
        pass
    with db_session() as conn:
        conn.execute("UPDATE allocations SET server_id = NULL WHERE server_id = ?", (server_id,))
        conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
    log_activity("admin.server.deleted", actor_id=admin["id"], actor_username=admin["username"], server_id=server_id, ip_address=get_client_ip(request))
    return {"status": "ok", "message": "Server permanently deleted."}


# ==================== DATABASE HOSTS ====================

@router.get("/database-hosts")
def admin_list_db_hosts(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = rows_to_list(conn.execute("SELECT id, name, host, port, username, max_databases, node_id, created_at FROM database_hosts ORDER BY created_at DESC").fetchall())
        for h in rows:
            h["database_count"] = conn.execute("SELECT COUNT(*) AS c FROM server_databases WHERE host_id = ?", (h["id"],)).fetchone()["c"]
    return {"status": "ok", "data": rows}


@router.post("/database-hosts", status_code=201)
def admin_create_db_host(payload: DatabaseHostCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    hid = new_uuid()
    ts = now_iso()
    with db_session() as conn:
        try:
            conn.execute(
                """INSERT INTO database_hosts (id, name, host, port, username, password_enc, max_databases, node_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (hid, payload.name.strip(), payload.host.strip(), payload.port, payload.username.strip(), payload.password, payload.max_databases, payload.node_id, ts, ts),
            )
        except Exception:
            raise HTTPException(status_code=409, detail="Database host name already exists.")
    return {"status": "ok", "data": {"id": hid, "name": payload.name.strip(), "host": payload.host.strip(), "port": payload.port}}


@router.delete("/database-hosts/{host_id}")
def admin_delete_db_host(host_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        conn.execute("DELETE FROM database_hosts WHERE id = ?", (host_id,))
    return {"status": "ok", "message": "Database host deleted."}


@router.post("/database-hosts/{host_id}/test")
def admin_test_db_host(host_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        h = conn.execute("SELECT host, port FROM database_hosts WHERE id = ?", (host_id,)).fetchone()
        if not h:
            raise HTTPException(status_code=404, detail="Database host not found.")
    try:
        with socket.create_connection((h["host"], int(h["port"])), timeout=2.0):
            return {"status": "ok", "data": {"reachable": True, "detail": "Connection established."}}
    except OSError as exc:
        return {"status": "ok", "data": {"reachable": False, "detail": str(exc)}}


# ==================== MOUNTS & SERVER IMAGES ====================

@router.get("/mounts")
def admin_list_mounts(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM mounts ORDER BY name ASC").fetchall())
    for r in rows:
        r["node_ids"] = json.loads(r["node_ids"] or "[]")
        r["egg_ids"] = json.loads(r["egg_ids"] or "[]")
    return {"status": "ok", "data": rows}


@router.post("/mounts", status_code=201)
def admin_create_mount(payload: MountCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    mid = new_uuid()
    ts = now_iso()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO mounts (id, name, description, source_path, target_path, read_only, user_mountable, node_ids, egg_ids, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (mid, payload.name.strip(), payload.description, payload.source_path, payload.target_path, 1 if payload.read_only else 0, 1 if payload.user_mountable else 0, json.dumps(payload.node_ids), json.dumps(payload.egg_ids), ts, ts),
        )
    return {"status": "ok", "data": {"id": mid, "name": payload.name.strip()}}


@router.delete("/mounts/{mount_id}")
def admin_delete_mount(mount_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        conn.execute("DELETE FROM mounts WHERE id = ?", (mount_id,))
    return {"status": "ok", "message": "Mount deleted."}


@router.get("/images")
def admin_list_images(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM server_images ORDER BY name ASC").fetchall())
    return {"status": "ok", "data": rows}


@router.post("/images", status_code=201)
def admin_create_image(payload: ServerImageCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    iid = new_uuid()
    with db_session() as conn:
        conn.execute(
            "INSERT INTO server_images (id, name, image_ref, category, description, is_default, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (iid, payload.name.strip(), payload.image_ref.strip(), payload.category, payload.description, 1 if payload.is_default else 0, now_iso()),
        )
    return {"status": "ok", "data": {"id": iid, "name": payload.name.strip(), "image_ref": payload.image_ref.strip()}}


@router.delete("/images/{image_id}")
def admin_delete_image(image_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        conn.execute("DELETE FROM server_images WHERE id = ?", (image_id,))
    return {"status": "ok", "message": "Image removed."}


# ==================== ACTIVITY, SETTINGS, BRANDING, API KEYS, SECURITY, MAINTENANCE ====================

@router.get("/activity")
def admin_activity_logs(limit: int = 100, event: str = "", admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        if event:
            rows = rows_to_list(conn.execute("SELECT * FROM activity_logs WHERE event LIKE ? ORDER BY created_at DESC LIMIT ?", (f"%{event}%", min(limit, 500))).fetchall())
        else:
            rows = rows_to_list(conn.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT ?", (min(limit, 500),)).fetchall())
    return {"status": "ok", "data": rows}


@router.get("/settings")
def admin_get_settings(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = conn.execute("SELECT key, value FROM system_settings").fetchall()
    return {"status": "ok", "data": {r["key"]: r["value"] for r in rows}}


@router.put("/settings")
def admin_update_settings(payload: SettingsUpdate, request: Request, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    ts = now_iso()
    with db_session() as conn:
        for k, v in payload.settings.items():
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (k, str(v), ts),
            )
    log_activity("admin.settings.updated", actor_id=admin["id"], actor_username=admin["username"], ip_address=get_client_ip(request), metadata={"keys": list(payload.settings.keys())})
    return {"status": "ok", "message": "Settings saved."}


@router.post("/settings/upload-brand")
async def admin_upload_brand_asset(
    asset_type: str = Form(...),  # "logo" or "favicon"
    file: UploadFile = File(...),
    admin: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    if asset_type not in ("logo", "favicon"):
        raise HTTPException(status_code=422, detail="asset_type must be 'logo' or 'favicon'.")
    ext = Path(file.filename or "asset.png").suffix.lower()
    if ext not in (".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp"):
        raise HTTPException(status_code=422, detail="Unsupported image format.")
    data = await file.read()
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Brand asset must be under 5MB.")
    fname = f"brand_{asset_type}_{secrets.token_hex(4)}{ext}"
    out = UPLOAD_DIR / fname
    out.write_bytes(data)
    url = f"/uploads/{fname}"
    key = "panel_logo" if asset_type == "logo" else "panel_favicon"
    with db_session() as conn:
        conn.execute(
            "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, url, now_iso()),
        )
    return {"status": "ok", "data": {"key": key, "url": url}}


@router.get("/api-keys")
def admin_list_api_keys(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = rows_to_list(conn.execute(
            "SELECT k.id, k.identifier, k.key_type, k.memo, k.permissions, k.last_used_at, k.created_at, u.username FROM api_keys k JOIN users u ON u.id = k.user_id ORDER BY k.created_at DESC"
        ).fetchall())
    return {"status": "ok", "data": rows}


@router.post("/api-keys", status_code=201)
def admin_create_api_key(payload: AdminApiKeyCreate, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    raw_key = generate_token("onap")
    ident = raw_key[:14]
    kid = new_uuid()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO api_keys (id, user_id, key_type, identifier, token_hash, memo, permissions, created_at)
               VALUES (?, ?, 'application', ?, ?, ?, ?, ?)""",
            (kid, admin["id"], ident, hash_token(raw_key), payload.memo, json.dumps(payload.permissions), now_iso()),
        )
    return {"status": "ok", "data": {"id": kid, "identifier": ident, "secret_token": raw_key, "memo": payload.memo}}


@router.delete("/api-keys/{key_id}")
def admin_delete_api_key(key_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    return {"status": "ok", "message": "API key revoked."}


@router.get("/security/sessions")
def admin_list_sessions(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        rows = rows_to_list(conn.execute(
            "SELECT s.id, s.user_id, s.ip_address, s.user_agent, s.expires_at, s.created_at, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC"
        ).fetchall())
    return {"status": "ok", "data": rows}


@router.delete("/security/sessions/{session_id}")
def admin_revoke_session(session_id: str, admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    return {"status": "ok", "message": "Session revoked."}


@router.get("/maintenance/status")
def admin_maintenance_status(admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    with db_session() as conn:
        row = conn.execute("SELECT value FROM system_settings WHERE key = 'maintenance_mode'").fetchone()
        msg = conn.execute("SELECT value FROM system_settings WHERE key = 'maintenance_message'").fetchone()
    return {
        "status": "ok",
        "data": {
            "maintenance_mode": (row["value"].lower() == "true") if row else False,
            "maintenance_message": msg["value"] if msg else "",
            "panel_version": settings.VERSION,
        },
    }


@router.post("/maintenance/toggle")
def admin_toggle_maintenance(enabled: bool, message: str = "", admin: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    ts = now_iso()
    with db_session() as conn:
        conn.execute(
            "INSERT INTO system_settings (key, value, updated_at) VALUES ('maintenance_mode', ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            ("true" if enabled else "false", ts),
        )
        if message:
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at) VALUES ('maintenance_message', ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (message, ts),
            )
    return {"status": "ok", "data": {"maintenance_mode": enabled}}
