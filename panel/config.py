"""Configuration management for OMCP ONION Panel."""

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ONION_DATA_DIR", str(BASE_DIR / "data")))
UPLOAD_DIR = DATA_DIR / "uploads"
LOG_DIR = DATA_DIR / "logs"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _load_or_create_secret() -> str:
    env_secret = os.environ.get("ONION_SECRET_KEY")
    if env_secret:
        return env_secret
    secret_file = DATA_DIR / ".panel_secret"
    if secret_file.exists():
        return secret_file.read_text(encoding="utf-8").strip()
    token = secrets.token_hex(32)
    secret_file.write_text(token, encoding="utf-8")
    try:
        os.chmod(secret_file, 0o600)
    except OSError:
        pass
    return token


class Settings:
    APP_NAME: str = "OMCP ONION"
    VERSION: str = "1.0.0"
    SECRET_KEY: str = _load_or_create_secret()
    DATABASE_PATH: str = os.environ.get("ONION_DB_PATH", str(DATA_DIR / "omcp_onion.db"))
    DATABASE_URL: str = os.environ.get("ONION_DATABASE_URL", "")
    PANEL_URL: str = os.environ.get("ONION_PANEL_URL", "http://127.0.0.1:8080")
    SESSION_TTL_SECONDS: int = int(os.environ.get("ONION_SESSION_TTL", str(60 * 60 * 24 * 7)))
    COOKIE_NAME: str = "omcp_onion_session"
    CSRF_COOKIE_NAME: str = "omcp_onion_csrf"
    COOKIE_SECURE: bool = os.environ.get("ONION_COOKIE_SECURE", "false").lower() == "true"
    RATE_LIMIT_AUTH_MAX: int = int(os.environ.get("ONION_RATE_LIMIT_AUTH", "30"))
    RATE_LIMIT_WINDOW_SEC: int = int(os.environ.get("ONION_RATE_LIMIT_WINDOW", "60"))
    ALLOW_SELF_REGISTRATION: bool = os.environ.get("ONION_ALLOW_REGISTRATION", "true").lower() == "true"


settings = Settings()
