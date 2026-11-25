"""Database connection, migrations, and default seed data for OMCP ONION."""

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from panel.config import settings

_DB_LOCK = threading.RLock()


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_uuid() -> str:
    return str(uuid.uuid4())


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or settings.DATABASE_PATH
    conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


@contextmanager
def db_session(db_path: Optional[str] = None):
    with _DB_LOCK:
        conn = get_connection(db_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT DEFAULT '',
    last_name TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    is_suspended INTEGER NOT NULL DEFAULT 0,
    language TEXT NOT NULL DEFAULT 'en',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    csrf_token TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_resets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'client',
    identifier TEXT UNIQUE NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    memo TEXT DEFAULT '',
    allowed_ips TEXT DEFAULT '[]',
    permissions TEXT DEFAULT '[]',
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS locations (
    id TEXT PRIMARY KEY,
    short_code TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    location_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    fqdn TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    scheme TEXT NOT NULL DEFAULT 'http',
    daemon_port INTEGER NOT NULL DEFAULT 8443,
    sftp_port INTEGER NOT NULL DEFAULT 2022,
    memory_mb INTEGER NOT NULL DEFAULT 8192,
    memory_overallocate INTEGER NOT NULL DEFAULT 0,
    disk_mb INTEGER NOT NULL DEFAULT 51200,
    disk_overallocate INTEGER NOT NULL DEFAULT 0,
    cpu_limit INTEGER NOT NULL DEFAULT 400,
    daemon_token TEXT NOT NULL,
    is_public INTEGER NOT NULL DEFAULT 1,
    maintenance_mode INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_heartbeat_at TEXT,
    last_error TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS allocations (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    ip_alias TEXT DEFAULT '',
    port INTEGER NOT NULL,
    notes TEXT DEFAULT '',
    server_id TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(node_id, ip, port),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nests (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    author TEXT DEFAULT 'OMCP ONION',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS eggs (
    id TEXT PRIMARY KEY,
    nest_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    docker_images TEXT NOT NULL DEFAULT '[]',
    startup_command TEXT NOT NULL,
    install_script TEXT NOT NULL DEFAULT '#!/bin/sh\necho "Installed"',
    install_container TEXT NOT NULL DEFAULT 'alpine:3.19',
    default_memory_mb INTEGER NOT NULL DEFAULT 1024,
    default_cpu_percent INTEGER NOT NULL DEFAULT 100,
    default_disk_mb INTEGER NOT NULL DEFAULT 5120,
    supported_ports TEXT NOT NULL DEFAULT '[25565]',
    variables TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (nest_id) REFERENCES nests(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    uuid_short TEXT UNIQUE NOT NULL,
    owner_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    egg_id TEXT NOT NULL,
    primary_allocation_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    docker_image TEXT NOT NULL,
    startup_command TEXT NOT NULL,
    env_vars TEXT NOT NULL DEFAULT '{}',
    memory_mb INTEGER NOT NULL DEFAULT 1024,
    cpu_percent INTEGER NOT NULL DEFAULT 100,
    disk_mb INTEGER NOT NULL DEFAULT 5120,
    backup_limit INTEGER NOT NULL DEFAULT 5,
    database_limit INTEGER NOT NULL DEFAULT 2,
    allocation_limit INTEGER NOT NULL DEFAULT 3,
    status TEXT NOT NULL DEFAULT 'installing',
    is_suspended INTEGER NOT NULL DEFAULT 0,
    install_log TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE RESTRICT,
    FOREIGN KEY (egg_id) REFERENCES eggs(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS subusers (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    permissions TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(server_id, user_id),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS backups (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    storage_driver TEXT NOT NULL DEFAULT 'local',
    archive_path TEXT DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    checksum TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'in_progress',
    is_locked INTEGER NOT NULL DEFAULT 0,
    error_message TEXT DEFAULT '',
    completed_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    cron_expression TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    only_when_online INTEGER NOT NULL DEFAULT 0,
    last_run_at TEXT,
    next_run_at TEXT,
    last_status TEXT DEFAULT 'idle',
    last_error TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS schedule_tasks (
    id TEXT PRIMARY KEY,
    schedule_id TEXT NOT NULL,
    sequence_id INTEGER NOT NULL DEFAULT 1,
    action TEXT NOT NULL,
    payload TEXT DEFAULT '',
    time_offset INTEGER NOT NULL DEFAULT 0,
    continue_on_failure INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS schedule_logs (
    id TEXT PRIMARY KEY,
    schedule_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    status TEXT NOT NULL,
    output TEXT DEFAULT '',
    error_message TEXT DEFAULT '',
    executed_at TEXT NOT NULL,
    FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS database_hosts (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 3306,
    username TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    max_databases INTEGER NOT NULL DEFAULT 50,
    node_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_databases (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    db_name TEXT UNIQUE NOT NULL,
    db_username TEXT UNIQUE NOT NULL,
    db_password TEXT NOT NULL,
    remote_host TEXT NOT NULL DEFAULT '%',
    created_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES database_hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mounts (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    source_path TEXT NOT NULL,
    target_path TEXT NOT NULL,
    read_only INTEGER NOT NULL DEFAULT 1,
    user_mountable INTEGER NOT NULL DEFAULT 0,
    node_ids TEXT NOT NULL DEFAULT '[]',
    egg_ids TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_images (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    image_ref TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'game',
    description TEXT DEFAULT '',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id TEXT PRIMARY KEY,
    actor_id TEXT,
    actor_username TEXT DEFAULT 'system',
    server_id TEXT,
    event TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_servers_owner ON servers(owner_id);
CREATE INDEX IF NOT EXISTS idx_servers_node ON servers(node_id);
CREATE INDEX IF NOT EXISTS idx_allocations_node ON allocations(node_id);
CREATE INDEX IF NOT EXISTS idx_allocations_server ON allocations(server_id);
CREATE INDEX IF NOT EXISTS idx_activity_server ON activity_logs(server_id);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_logs(created_at DESC);
"""

DEFAULT_SETTINGS: Dict[str, str] = {
    "panel_name": "OMCP ONION",
    "panel_url": "http://127.0.0.1:8080",
    "panel_logo": "",
    "panel_favicon": "",
    "support_email": "support@omcp-onion.local",
    "support_url": "",
    "default_language": "en",
    "timezone": "UTC",
    "theme": "onion-dark",
    "login_branding_title": "OMCP ONION Control Panel",
    "login_branding_subtitle": "Next-generation multi-node game server orchestration",
    "background_image_url": "",
    "background_video_url": "",
    "maintenance_mode": "false",
    "maintenance_message": "OMCP ONION is currently undergoing scheduled maintenance.",
    "registration_enabled": "true",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_username": "",
    "smtp_from": "noreply@omcp-onion.local",
    "storage_driver": "local",
    "backup_driver": "local",
    "backup_remote_endpoint": "",
    "backup_max_size_mb": "2048",
    "security_min_password_length": "8",
    "security_session_ttl_hours": "168",
    "security_rate_limit_rpm": "120",
}


def init_db(db_path: Optional[str] = None) -> None:
    """Apply schema migrations and seed baseline catalog & settings."""
    with db_session(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        cur = conn.execute("SELECT version FROM schema_migrations WHERE version = 1")
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (1, now_iso()),
            )
        ts = now_iso()
        for k, v in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)",
                (k, v, ts),
            )
        _seed_default_catalog(conn, ts)


def _seed_default_catalog(conn: sqlite3.Connection, ts: str) -> None:
    """Seed default nests, eggs, and server images if empty."""
    count = conn.execute("SELECT COUNT(*) AS c FROM nests").fetchone()["c"]
    if count > 0:
        return

    nests = [
        ("nest-minecraft", "Minecraft", "Java & Bedrock Minecraft server runtimes"),
        ("nest-fps", "Source & FPS", "Counter-Strike 2, TF2, and Source-based dedicated servers"),
        ("nest-sandbox", "Sandbox & Survival", "Terraria, Valheim, Rust, and survival servers"),
        ("nest-generic", "Generic Runtimes", "Python, Node.js, and custom container workloads"),
    ]
    for nid, name, desc in nests:
        conn.execute(
            "INSERT INTO nests (id, name, description, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (nid, name, desc, "OMCP ONION", ts, ts),
        )

    eggs = [
        (
            "egg-mc-paper",
            "nest-minecraft",
            "PaperMC (Java)",
            "High-performance Minecraft Java server powered by Paper",
            json.dumps(["ghcr.io/onion-images/java:21", "ghcr.io/onion-images/java:17"]),
            "java -Xms128M -Xmx{{SERVER_MEMORY}}M -jar {{SERVER_JARFILE}} nogui",
            "#!/bin/sh\necho 'eula=true' > eula.txt\necho 'PaperMC environment initialized.'",
            "alpine:3.19",
            2048,
            200,
            10240,
            json.dumps([25565]),
            json.dumps([
                {"name": "Server Jar File", "env": "SERVER_JARFILE", "default": "server.jar", "rules": "required|string"},
                {"name": "Minecraft Version", "env": "MINECRAFT_VERSION", "default": "1.21.1", "rules": "required|string"},
            ]),
        ),
        (
            "egg-cs2",
            "nest-fps",
            "Counter-Strike 2",
            "Dedicated Counter-Strike 2 Linux game server",
            json.dumps(["ghcr.io/onion-images/steamcmd:latest"]),
            "./game/bin/linuxsteamrt64/cs2 -dedicated +map {{SRCDS_MAP}} -port {{SERVER_PORT}}",
            "#!/bin/sh\necho 'CS2 dedicated server manifest initialized.'",
            "alpine:3.19",
            4096,
            300,
            35840,
            json.dumps([27015]),
            json.dumps([
                {"name": "Starting Map", "env": "SRCDS_MAP", "default": "de_dust2", "rules": "required|string"},
                {"name": "Max Players", "env": "MAX_PLAYERS", "default": "16", "rules": "required|integer"},
            ]),
        ),
        (
            "egg-terraria",
            "nest-sandbox",
            "Terraria Dedicated",
            "Official Terraria Linux dedicated server",
            json.dumps(["ghcr.io/onion-images/mono:latest"]),
            "./TerrariaServer.bin.x86_64 -port {{SERVER_PORT}} -maxplayers {{MAX_PLAYERS}}",
            "#!/bin/sh\necho 'Terraria server directory initialized.'",
            "alpine:3.19",
            1024,
            100,
            4096,
            json.dumps([7777]),
            json.dumps([
                {"name": "World Name", "env": "WORLD_NAME", "default": "OnionWorld", "rules": "required|string"},
                {"name": "Max Players", "env": "MAX_PLAYERS", "default": "8", "rules": "required|integer"},
            ]),
        ),
        (
            "egg-python-runtime",
            "nest-generic",
            "Interactive Game / Python Runtime",
            "Lightweight live interactive server process (works natively with or without Docker)",
            json.dumps(["python:3.11-slim", "ghcr.io/onion-images/python:3.11"]),
            "python3 -u server.py",
            "#!/bin/sh\ncat << 'PYEOF' > server.py\nimport sys, time, os\nprint('[OMCP ONION] Game server runtime booted on port ' + os.environ.get('SERVER_PORT', '25565'), flush=True)\nfor line in sys.stdin:\n    cmd = line.strip()\n    if not cmd:\n        continue\n    if cmd in ('stop', 'exit', 'quit'):\n        print('[OMCP ONION] Graceful shutdown requested. Saving world...', flush=True)\n        break\n    elif cmd == 'status':\n        print('[OMCP ONION] Status: ONLINE | Players: 0/20 | TPS: 20.0', flush=True)\n    elif cmd.startswith('say '):\n        print('[Broadcast] ' + cmd[4:], flush=True)\n    else:\n        print('[Server] Executed command: ' + cmd, flush=True)\nPYEOF\necho 'Interactive runtime installed.'",
            "python:3.11-slim",
            512,
            100,
            2048,
            json.dumps([25565, 27015]),
            json.dumps([
                {"name": "MOTD", "env": "SERVER_MOTD", "default": "Powered by OMCP ONION", "rules": "string"},
            ]),
        ),
    ]
    for e in eggs:
        conn.execute(
            """INSERT INTO eggs (
                id, nest_id, name, description, docker_images, startup_command,
                install_script, install_container, default_memory_mb, default_cpu_percent,
                default_disk_mb, supported_ports, variables, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (*e, ts, ts),
        )

    images = [
        ("img-java-21", "Java 21 (Temurin)", "ghcr.io/onion-images/java:21", "minecraft", "OpenJDK 21 for modern Minecraft servers", 1),
        ("img-steamcmd", "SteamCMD Linux", "ghcr.io/onion-images/steamcmd:latest", "fps", "SteamCMD runtime for Source & CS2 servers", 0),
        ("img-python-311", "Python 3.11 Slim", "python:3.11-slim", "generic", "Lightweight Python runtime for bots & custom game servers", 0),
        ("img-node-20", "Node.js 20 LTS", "node:20-alpine", "generic", "Node.js LTS runtime for web/game backends", 0),
    ]
    for img in images:
        conn.execute(
            "INSERT INTO server_images (id, name, image_ref, category, description, is_default, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (*img, ts),
        )


def row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(r) for r in rows]
