#!/usr/bin/env bash
# OMCP ONION — One-Command Ubuntu Linux VPS Installer
set -euo pipefail

INSTALL_DIR="/opt/omcp-onion"
DATA_DIR="/var/lib/omcp-onion"
ETC_DIR="/etc/omcp-onion"
SERVICE_USER="onion"
SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================="
echo "  OMCP ONION — Ubuntu VPS Installer v1.0  "
echo "=========================================="

if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Please run this installer as root (sudo bash scripts/install.sh)."
  exit 1
fi

if [[ -d "$DATA_DIR" && -f "$DATA_DIR/omcp_onion.db" ]]; then
  echo "[WARNING] Existing OMCP ONION data detected at $DATA_DIR."
  read -r -p "Preserve existing database and server files? (Y/n): " PRESERVE
  PRESERVE="${PRESERVE:-Y}"
  if [[ "$PRESERVE" =~ ^[Nn]$ ]]; then
    read -r -p "Type 'CONFIRM-OVERWRITE' to permanently erase existing data: " CONFIRM
    if [[ "$CONFIRM" != "CONFIRM-OVERWRITE" ]]; then
      echo "Aborted without modifying existing data."
      exit 1
    fi
    rm -rf "$DATA_DIR"
  fi
fi

read -r -p "Panel Domain or Public IP (e.g. panel.example.com): " PANEL_DOMAIN
PANEL_DOMAIN="${PANEL_DOMAIN:-127.0.0.1}"
read -r -p "Enable Let's Encrypt SSL via Certbot? (y/N): " ENABLE_SSL
ENABLE_SSL="${ENABLE_SSL:-N}"
read -r -p "Install local Node Agent on this server? (Y/n): " INSTALL_AGENT
INSTALL_AGENT="${INSTALL_AGENT:-Y}"

echo "[1/7] Checking & installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx sqlite3 tar unzip curl openssl

echo "[2/7] Creating least-privilege system user & directories..."
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
mkdir -p "$INSTALL_DIR" "$DATA_DIR/agent/servers" "$DATA_DIR/agent/backups" "$DATA_DIR/uploads" "$DATA_DIR/logs" "$ETC_DIR"

echo "[3/7] Copying application files..."
cp -a "$SCRIPT_SRC/panel" "$SCRIPT_SRC/agent" "$SCRIPT_SRC/frontend" "$SCRIPT_SRC/scripts" "$SCRIPT_SRC/deploy" "$SCRIPT_SRC/requirements.txt" "$INSTALL_DIR/"

echo "[4/7] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

echo "[5/7] Writing secure environment files..."
if [[ ! -f "$ETC_DIR/panel.env" ]]; then
  PANEL_SECRET="$(openssl rand -hex 32)"
  cat > "$ETC_DIR/panel.env" <<EOF
ONION_SECRET_KEY=${PANEL_SECRET}
ONION_DATA_DIR=${DATA_DIR}
ONION_DB_PATH=${DATA_DIR}/omcp_onion.db
ONION_PANEL_URL=http://${PANEL_DOMAIN}
ONION_COOKIE_SECURE=false
EOF
  chmod 600 "$ETC_DIR/panel.env"
fi

if [[ ! -f "$ETC_DIR/agent.env" ]]; then
  AGENT_TOKEN="node_$(openssl rand -hex 24)"
  cat > "$ETC_DIR/agent.env" <<EOF
ONION_AGENT_HOST=0.0.0.0
ONION_AGENT_PORT=8443
ONION_AGENT_TOKEN=${AGENT_TOKEN}
ONION_AGENT_DATA_DIR=${DATA_DIR}/agent
EOF
  chmod 600 "$ETC_DIR/agent.env"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" "$DATA_DIR" "$ETC_DIR"

echo "[6/7] Running database migrations..."
sudo -u "$SERVICE_USER" env ONION_DATA_DIR="$DATA_DIR" ONION_DB_PATH="$DATA_DIR/omcp_onion.db" \
  "$INSTALL_DIR/venv/bin/python3" -c "from panel.database import init_db; init_db()"

echo "[7/7] Configuring Nginx & systemd services..."
sed "s/__PANEL_DOMAIN__/${PANEL_DOMAIN}/g" "$INSTALL_DIR/deploy/nginx/omcp-onion.conf" > /etc/nginx/sites-available/omcp-onion.conf
ln -sf /etc/nginx/sites-available/omcp-onion.conf /etc/nginx/sites-enabled/omcp-onion.conf
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

cp "$INSTALL_DIR/deploy/systemd/omcp-onion-panel.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now omcp-onion-panel

if [[ "$INSTALL_AGENT" =~ ^[Yy]$ ]]; then
  cp "$INSTALL_DIR/deploy/systemd/omcp-onion-agent.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now omcp-onion-agent
fi

if [[ "$ENABLE_SSL" =~ ^[Yy]$ ]]; then
  apt-get install -y -qq certbot python3-certbot-nginx
  certbot --nginx -d "$PANEL_DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email || true
fi

sleep 2
echo "Running health check..."
curl -fsS http://127.0.0.1:8080/api/health && echo ""
echo "=========================================="
echo "  OMCP ONION Installation Complete!"
echo "  Panel URL: http://${PANEL_DOMAIN}"
echo "  Visit the URL above to create your initial Admin account."
echo "=========================================="
