# OMCP ONION — Game Server Hosting Control Panel

**OMCP ONION** is an independent, production-ready multi-node Game Server Hosting Control Panel built completely from scratch with an original architecture, design system, secure Node Agent daemon, live WebSocket console, file & archive manager, backups, cron scheduler, RBAC, and 17-section Administrator Panel.

## Architecture

1. **Central Panel Backend (`panel/`)**: Python 3.11 + FastAPI + Starlette WebSockets + SQLite (WAL mode) with full REST API, scrypt password hashing, HMAC-signed sessions & API tokens, sliding-window rate limiting, and audit logging.
2. **Node Agent / Daemon (`agent/onion_agent.py`)**: Independent node-side service authenticated with Bearer + HMAC-SHA256 request signatures (300s replay window) and optional TLS. Provisions real server directories, runs egg installation scripts, spawns & controls real server processes, streams live console output over WebSockets, enforces sandboxed file/archive operations, and manages SHA-256 verified backups.
3. **Frontend SPA (`frontend/`)**: Original obsidian-violet-amber commercial hosting dashboard with zero external build-step blockers — full Client Panel and independent 17-section Administrator Panel.

## Quick Start (Local / Development)

```bash
# 1. Start the Node Agent (Terminal 1)
ONION_AGENT_TOKEN=onion-dev-node-token ONION_AGENT_PORT=8443 python3 -m agent.onion_agent

# 2. Start the OMCP ONION Panel (Terminal 2)
ONION_PORT=8080 python3 -m panel.main

# 3. Open http://127.0.0.1:8080 in your browser to create the first Administrator account.
```

## Ubuntu Linux VPS Installation

```bash
sudo bash scripts/install.sh
```

The installer checks dependencies, creates a least-privilege `onion` system user, generates cryptographic secrets, initializes database migrations, configures Nginx (with WebSocket upgrade support and optional Let's Encrypt SSL), installs systemd services (`omcp-onion-panel` and `omcp-onion-agent`), and runs a live health check.

## Safe Updates & Rollback

```bash
# Update while preserving all server files, worlds, plugins, backups, users, DB, and settings:
sudo bash scripts/update.sh

# Roll back to the previous snapshot if needed:
sudo bash scripts/rollback.sh
```

## Automated Test Suite

Run the end-to-end automated test suite (spins up a live Node Agent + Panel TestClient and tests Auth, RBAC, Admin CRUD, Real Provisioning, Live WebSocket Console, File/Archive Manager security, Backups, Schedules, Databases, Allocations, Session Persistence, and Update/Rollback):

```bash
python3 tests/run_tests.py
```

## REST API Route Groups

- **Auth**: `/api/auth/{bootstrap,register,login,logout,user,refresh,forgot-password,reset-password}`
- **Client & Server**: `/api/client/{account,servers,permissions}` and `/api/client/servers/{id}/{resources,activity,power,console,console/ws,command,files/*,backups/*,schedules/*,users/*,databases/*,network/allocations/*,startup,settings,reinstall}`
- **Administrator**: `/api/application/{overview,users,servers,nodes,locations,nests,eggs,allocations,database-hosts,mounts,images,activity,settings,api-keys,security/sessions,maintenance/*}`
- **Interactive OpenAPI Docs**: `GET /api/docs`
