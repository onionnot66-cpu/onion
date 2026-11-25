"""Authentication, password hashing, RBAC, rate limiting, and audit logging."""

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from fastapi import Depends, HTTPException, Request, status

from panel.config import settings
from panel.database import db_session, new_uuid, now_iso, row_to_dict

# Complete granular server-level permissions
SERVER_PERMISSIONS: List[str] = [
    "console.access",
    "console.command",
    "power.control",
    "file.read",
    "file.write",
    "file.upload",
    "file.delete",
    "backup.manage",
    "schedule.manage",
    "database.manage",
    "network.manage",
    "startup.manage",
    "settings.manage",
    "user.manage",
    "activity.read",
]


def hash_password(password: str) -> str:
    """Hash password with scrypt + 16-byte random salt."""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4])
        expected = base64.b64decode(parts[5])
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(f"{settings.SECRET_KEY}:{raw_token}".encode("utf-8")).hexdigest()


def generate_token(prefix: str = "onion") -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def sign_daemon_request(node_token: str, method: str, path: str, timestamp: str, body: bytes = b"") -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    payload = f"{method.upper()}:{path}:{timestamp}:{body_hash}".encode("utf-8")
    return hmac.new(node_token.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_daemon_signature(node_token: str, method: str, path: str, timestamp: str, body: bytes, signature: str) -> bool:
    try:
        ts_int = int(timestamp)
        if abs(int(time.time()) - ts_int) > 300:
            return False
    except ValueError:
        return False
    expected = sign_daemon_request(node_token, method, path, timestamp, body)
    return hmac.compare_digest(expected, signature)


class RateLimiter:
    """In-memory sliding window rate limiter keyed by IP/route."""

    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def check(self, key: str, max_requests: int, window_sec: int) -> None:
        now = time.time()
        q = self._hits[key]
        while q and now - q[0] > window_sec:
            q.popleft()
        if len(q) >= max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again shortly.",
            )
        q.append(now)

    def reset(self) -> None:
        self._hits.clear()


rate_limiter = RateLimiter()


def log_activity(
    event: str,
    actor_id: Optional[str] = None,
    actor_username: str = "system",
    server_id: Optional[str] = None,
    ip_address: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    with db_session() as conn:
        conn.execute(
            """INSERT INTO activity_logs (id, actor_id, actor_username, server_id, event, ip_address, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                new_uuid(),
                actor_id,
                actor_username,
                server_id,
                event,
                ip_address,
                json.dumps(metadata or {}),
                now_iso(),
            ),
        )


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def create_user_session(user_id: str, ip_address: str = "", user_agent: str = "") -> Tuple[str, str, int]:
    raw_token = generate_token("sess")
    csrf_token = secrets.token_urlsafe(24)
    expires_at = int(time.time()) + settings.SESSION_TTL_SECONDS
    with db_session() as conn:
        conn.execute(
            """INSERT INTO sessions (id, user_id, token_hash, csrf_token, ip_address, user_agent, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (new_uuid(), user_id, hash_token(raw_token), csrf_token, ip_address, user_agent[:255], expires_at, now_iso()),
        )
    return raw_token, csrf_token, expires_at


def _resolve_auth(request: Request) -> Optional[Dict[str, Any]]:
    auth_header = request.headers.get("authorization", "")
    cookie_token = request.cookies.get(settings.COOKIE_NAME)
    raw_token = None
    auth_via = None

    if auth_header.lower().startswith("bearer "):
        raw_token = auth_header[7:].strip()
        auth_via = "bearer"
    elif cookie_token:
        raw_token = cookie_token
        auth_via = "cookie"

    if not raw_token:
        return None

    th = hash_token(raw_token)
    now_ts = int(time.time())
    with db_session() as conn:
        # 1. Check session table
        sess = conn.execute(
            """SELECT s.id AS session_id, s.csrf_token, s.expires_at, u.*
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token_hash = ?""",
            (th,),
        ).fetchone()
        if sess:
            if sess["expires_at"] < now_ts:
                conn.execute("DELETE FROM sessions WHERE id = ?", (sess["session_id"],))
                return None
            if sess["is_suspended"]:
                raise HTTPException(status_code=403, detail="Account is suspended.")
            user = dict(sess)
            user.pop("password_hash", None)
            user["_auth_via"] = auth_via
            return user

        # 2. Check API keys
        api_key = conn.execute(
            """SELECT k.id AS api_key_id, k.key_type, k.permissions AS key_permissions, u.*
               FROM api_keys k JOIN users u ON u.id = k.user_id
               WHERE k.token_hash = ?""",
            (th,),
        ).fetchone()
        if api_key:
            if api_key["is_suspended"]:
                raise HTTPException(status_code=403, detail="Account is suspended.")
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now_iso(), api_key["api_key_id"]))
            user = dict(api_key)
            user.pop("password_hash", None)
            user["_auth_via"] = "api_key"
            return user

    return None


def get_current_user(request: Request) -> Dict[str, Any]:
    user = _resolve_auth(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    return user


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required.")
    return user


def get_server_and_permissions(server_id: str, user: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Verify user access to a server and return (server_dict, granted_permissions)."""
    with db_session() as conn:
        srv = conn.execute(
            """SELECT s.*, n.name AS node_name, n.fqdn AS node_fqdn, n.ip_address AS node_ip,
                      n.scheme AS node_scheme, n.daemon_port, n.sftp_port, n.daemon_token,
                      e.name AS egg_name, e.nest_id, a.ip AS alloc_ip, a.ip_alias AS alloc_alias, a.port AS alloc_port
               FROM servers s
               JOIN nodes n ON n.id = s.node_id
               JOIN eggs e ON e.id = s.egg_id
               JOIN allocations a ON a.id = s.primary_allocation_id
               WHERE s.id = ? OR s.uuid_short = ?""",
            (server_id, server_id),
        ).fetchone()
        if not srv:
            raise HTTPException(status_code=404, detail="Server not found.")
        srv_dict = dict(srv)

        if user["role"] == "admin" or srv_dict["owner_id"] == user["id"]:
            return srv_dict, list(SERVER_PERMISSIONS)

        sub = conn.execute(
            "SELECT permissions FROM subusers WHERE server_id = ? AND user_id = ?",
            (srv_dict["id"], user["id"]),
        ).fetchone()
        if not sub:
            raise HTTPException(status_code=403, detail="You do not have permission to access this server.")
        perms = json.loads(sub["permissions"] or "[]")
        return srv_dict, perms


def require_server_permission(server_id: str, user: Dict[str, Any], permission: str) -> Dict[str, Any]:
    srv, perms = get_server_and_permissions(server_id, user)
    if srv["is_suspended"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="This server is currently suspended.")
    if permission not in perms:
        raise HTTPException(status_code=403, detail=f"Missing required permission: {permission}")
    return srv


def sanitize_server_public(srv: Dict[str, Any]) -> Dict[str, Any]:
    """Strip sensitive node credentials before returning server JSON to clients."""
    out = dict(srv)
    out.pop("daemon_token", None)
    host = out.get("alloc_alias") or out.get("node_fqdn") or out.get("alloc_ip")
    out["connection_address"] = f"{host}:{out.get('alloc_port')}"
    try:
        out["env_vars"] = json.loads(out["env_vars"]) if isinstance(out.get("env_vars"), str) else (out.get("env_vars") or {})
    except Exception:
        out["env_vars"] = {}
    return out
