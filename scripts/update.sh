#!/usr/bin/env bash
# OMCP ONION — Safe Updater (preserves server files, worlds, plugins, backups, users, DB & settings)
set -euo pipefail

INSTALL_DIR="${ONION_INSTALL_DIR:-/opt/omcp-onion}"
DATA_DIR="${ONION_DATA_DIR:-/var/lib/omcp-onion}"
BACKUP_ROOT="${ONION_UPDATE_BACKUP_DIR:-/var/backups/omcp-onion}"
SOURCE_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SNAP_DIR="${BACKUP_ROOT}/${STAMP}"

echo "[OMCP ONION Updater] Starting safe update at ${STAMP}..."
mkdir -p "$SNAP_DIR"

# 1. Back up current application code + SQLite database (never touches game server worlds/backups)
if [[ -d "$INSTALL_DIR" ]]; then
  tar -czf "$SNAP_DIR/app_code.tar.gz" -C "$INSTALL_DIR" panel agent frontend scripts deploy requirements.txt 2>/dev/null || true
fi
if [[ -f "$DATA_DIR/omcp_onion.db" ]]; then
  cp -a "$DATA_DIR/omcp_onion.db" "$SNAP_DIR/omcp_onion.db"
fi
echo "$STAMP" > "$BACKUP_ROOT/LATEST_BACKUP"
echo "[OMCP ONION Updater] Pre-update snapshot saved to $SNAP_DIR"

# 2. Deploy new application code without touching DATA_DIR/agent/servers or DATA_DIR/agent/backups
mkdir -p "$INSTALL_DIR"
cp -a "$SOURCE_DIR/panel" "$SOURCE_DIR/agent" "$SOURCE_DIR/frontend" "$SOURCE_DIR/scripts" "$SOURCE_DIR/deploy" "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"

# 3. Run idempotent migrations
PYTHON_BIN="${INSTALL_DIR}/venv/bin/python3"
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN="python3"
ONION_DATA_DIR="$DATA_DIR" ONION_DB_PATH="$DATA_DIR/omcp_onion.db" "$PYTHON_BIN" -c "import sys; sys.path.insert(0, '$INSTALL_DIR'); from panel.database import init_db; init_db()"

# 4. Restart systemd services if running
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet omcp-onion-panel 2>/dev/null; then
  systemctl restart omcp-onion-panel
  systemctl is-active --quiet omcp-onion-agent 2>/dev/null && systemctl restart omcp-onion-agent || true
  sleep 2
  if ! curl -fsS http://127.0.0.1:8080/api/health >/dev/null; then
    echo "[ERROR] Health check failed! Triggering automatic rollback..."
    bash "$INSTALL_DIR/scripts/rollback.sh" "$STAMP"
    exit 1
  fi
fi

echo "[OMCP ONION Updater] Update completed safely. All server data, worlds, plugins, backups, and users preserved."
