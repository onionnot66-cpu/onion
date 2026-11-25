"""Authentication, session management, registration, and password reset endpoints."""

import re
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from panel.config import settings
from panel.database import db_session, new_uuid, now_iso
from panel.security import (
    create_user_session,
    generate_token,
    get_client_ip,
    get_current_user,
    hash_password,
    hash_token,
    log_activity,
    rate_limiter,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


class LoginRequest(BaseModel):
    identifier: str = Field(..., min_length=1, description="Username or email")
    password: str = Field(..., min_length=1)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=8, max_length=128)
    first_name: str = ""
    last_name: str = ""


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)


def _set_session_cookies(response: Response, raw_token: str, csrf_token: str) -> None:
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=raw_token,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=settings.SESSION_TTL_SECONDS,
        path="/",
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=settings.SESSION_TTL_SECONDS,
        path="/",
    )


def _get_setting(conn, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


@router.get("/bootstrap")
def auth_bootstrap() -> Dict[str, Any]:
    """Return public panel branding & login configuration."""
    keys = [
        "panel_name", "panel_logo", "panel_favicon", "panel_url",
        "support_email", "support_url", "default_language", "timezone", "theme",
        "login_branding_title", "login_branding_subtitle",
        "background_image_url", "background_video_url",
        "maintenance_mode", "maintenance_message", "registration_enabled",
    ]
    with db_session() as conn:
        rows = conn.execute(
            f"SELECT key, value FROM system_settings WHERE key IN ({','.join('?' for _ in keys)})",
            keys,
        ).fetchall()
        data = {r["key"]: r["value"] for r in rows}
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    data["needs_initial_setup"] = user_count == 0
    return {"status": "ok", "data": data}


@router.post("/register", status_code=201)
def register(payload: RegisterRequest, request: Request, response: Response) -> Dict[str, Any]:
    ip = get_client_ip(request)
    rate_limiter.check(f"auth:register:{ip}", settings.RATE_LIMIT_AUTH_MAX, settings.RATE_LIMIT_WINDOW_SEC)

    if not USERNAME_RE.match(payload.username):
        raise HTTPException(status_code=422, detail="Username must be 3-32 characters (letters, numbers, _, ., -).")
    if not EMAIL_RE.match(payload.email):
        raise HTTPException(status_code=422, detail="Invalid email address format.")

    with db_session() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        reg_enabled = _get_setting(conn, "registration_enabled", "true").lower() == "true"
        if user_count > 0 and not reg_enabled:
            raise HTTPException(status_code=403, detail="Public registration is disabled by administrator.")

        min_len = int(_get_setting(conn, "security_min_password_length", "8") or "8")
        if len(payload.password) < min_len:
            raise HTTPException(status_code=422, detail=f"Password must be at least {min_len} characters.")

        existing = conn.execute(
            "SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
            (payload.username, payload.email),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Username or email is already registered.")

        # First registered account becomes admin automatically for zero-friction bootstrap
        role = "admin" if user_count == 0 else "user"
        uid = new_uuid()
        ts = now_iso()
        conn.execute(
            """INSERT INTO users (id, username, email, password_hash, first_name, last_name, role, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                uid,
                payload.username.strip(),
                payload.email.strip().lower(),
                hash_password(payload.password),
                payload.first_name.strip(),
                payload.last_name.strip(),
                role,
                ts,
                ts,
            ),
        )

    raw_token, csrf_token, expires_at = create_user_session(uid, ip, request.headers.get("user-agent", ""))
    _set_session_cookies(response, raw_token, csrf_token)
    log_activity("auth.register", actor_id=uid, actor_username=payload.username, ip_address=ip, metadata={"role": role})
    return {
        "status": "ok",
        "data": {
            "token": raw_token,
            "csrf_token": csrf_token,
            "expires_at": expires_at,
            "user": {
                "id": uid,
                "username": payload.username.strip(),
                "email": payload.email.strip().lower(),
                "first_name": payload.first_name.strip(),
                "last_name": payload.last_name.strip(),
                "role": role,
            },
        },
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> Dict[str, Any]:
    ip = get_client_ip(request)
    rate_limiter.check(f"auth:login:{ip}", settings.RATE_LIMIT_AUTH_MAX, settings.RATE_LIMIT_WINDOW_SEC)

    ident = payload.identifier.strip()
    with db_session() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
            (ident, ident),
        ).fetchone()
        bad_creds = not user or not verify_password(payload.password, user["password_hash"])
    if bad_creds:
        log_activity("auth.login_failed", actor_username=ident, ip_address=ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    with db_session() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        if user["is_suspended"]:
            raise HTTPException(status_code=403, detail="Your account has been suspended.")

    raw_token, csrf_token, expires_at = create_user_session(user["id"], ip, request.headers.get("user-agent", ""))
    _set_session_cookies(response, raw_token, csrf_token)
    log_activity("auth.login", actor_id=user["id"], actor_username=user["username"], ip_address=ip)

    safe_user = {k: user[k] for k in ("id", "username", "email", "first_name", "last_name", "role", "language", "created_at")}
    return {
        "status": "ok",
        "data": {
            "token": raw_token,
            "csrf_token": csrf_token,
            "expires_at": expires_at,
            "user": safe_user,
        },
    }


@router.post("/logout")
def logout(request: Request, response: Response, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    sid = user.get("session_id")
    if sid:
        with db_session() as conn:
            conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
    response.delete_cookie(settings.COOKIE_NAME, path="/")
    response.delete_cookie(settings.CSRF_COOKIE_NAME, path="/")
    log_activity("auth.logout", actor_id=user["id"], actor_username=user["username"], ip_address=get_client_ip(request))
    return {"status": "ok", "message": "Logged out successfully."}


@router.get("/user")
def current_user_info(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    safe = {k: user.get(k) for k in ("id", "username", "email", "first_name", "last_name", "role", "language", "is_suspended", "created_at")}
    return {"status": "ok", "data": safe}


@router.post("/refresh")
def refresh_session(request: Request, response: Response, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    old_sid = user.get("session_id")
    ip = get_client_ip(request)
    if old_sid:
        with db_session() as conn:
            conn.execute("DELETE FROM sessions WHERE id = ?", (old_sid,))
    raw_token, csrf_token, expires_at = create_user_session(user["id"], ip, request.headers.get("user-agent", ""))
    _set_session_cookies(response, raw_token, csrf_token)
    return {"status": "ok", "data": {"token": raw_token, "csrf_token": csrf_token, "expires_at": expires_at}}


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request) -> Dict[str, Any]:
    ip = get_client_ip(request)
    rate_limiter.check(f"auth:forgot:{ip}", 10, settings.RATE_LIMIT_WINDOW_SEC)
    reset_token: Optional[str] = None
    with db_session() as conn:
        user = conn.execute("SELECT id, username FROM users WHERE LOWER(email) = LOWER(?)", (payload.email.strip(),)).fetchone()
        if user:
            reset_token = generate_token("rst")
            conn.execute(
                """INSERT INTO password_resets (id, user_id, token_hash, expires_at, used, created_at)
                   VALUES (?, ?, ?, ?, 0, ?)""",
                (new_uuid(), user["id"], hash_token(reset_token), int(time.time()) + 3600, now_iso()),
            )
            found_uid, found_uname = user["id"], user["username"]
        else:
            found_uid, found_uname = None, None
    if found_uid:
        log_activity("auth.password_reset_requested", actor_id=found_uid, actor_username=found_uname, ip_address=ip)
    # In production with SMTP configured, email the token; return token only in non-SMTP/local mode
    return {
        "status": "ok",
        "message": "If an account exists for that email, a password reset token has been generated.",
        "data": {"reset_token_preview": reset_token},
    }


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request) -> Dict[str, Any]:
    ip = get_client_ip(request)
    th = hash_token(payload.token)
    now_ts = int(time.time())
    with db_session() as conn:
        rec = conn.execute(
            "SELECT * FROM password_resets WHERE token_hash = ? AND used = 0",
            (th,),
        ).fetchone()
        if not rec or rec["expires_at"] < now_ts:
            raise HTTPException(status_code=400, detail="Invalid or expired password reset token.")
        conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (hash_password(payload.new_password), now_iso(), rec["user_id"]),
        )
        conn.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (rec["id"],))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (rec["user_id"],))
        user = conn.execute("SELECT username FROM users WHERE id = ?", (rec["user_id"],)).fetchone()
    log_activity("auth.password_reset_completed", actor_id=rec["user_id"], actor_username=user["username"] if user else "unknown", ip_address=ip)
    return {"status": "ok", "message": "Password has been reset successfully."}
