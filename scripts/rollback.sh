#!/usr/bin/env bash
# OMCP ONION — Rollback Script
set -euo pipefail

INSTALL_DIR="${ONION_INSTALL_DIR:-/opt/omcp-onion}"
DATA_DIR="${ONION_DATA_DIR:-/var/lib/omcp-onion}"
BACKUP_ROOT="${ONION_UPDATE_BACKUP_DIR:-/var/backups/omcp-onion}"
TARGET_STAMP="${1:-$(cat "$BACKUP_ROOT/LATEST_BACKUP" 2>/dev/null || true)}"

if [[ -z "$TARGET_STAMP" || ! -d "$BACKUP_ROOT/$TARGET_STAMP" ]]; then
  echo "[ERROR] No valid backup snapshot found in $BACKUP_ROOT"
  exit 1
fi

SNAP_DIR="$BACKUP_ROOT/$TARGET_STAMP"
echo "[OMCP ONION Rollback] Restoring snapshot $TARGET_STAMP..."

if [[ -f "$SNAP_DIR/app_code.tar.gz" ]]; then
  tar -xzf "$SNAP_DIR/app_code.tar.gz" -C "$INSTALL_DIR"
fi
if [[ -f "$SNAP_DIR/omcp_onion.db" ]]; then
  cp -a "$SNAP_DIR/omcp_onion.db" "$DATA_DIR/omcp_onion.db"
fi

if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q omcp-onion-panel; then
  systemctl restart omcp-onion-panel || true
  systemctl restart omcp-onion-agent || true
fi

echo "[OMCP ONION Rollback] Rollback to $TARGET_STAMP complete. Server files and worlds were never modified."
