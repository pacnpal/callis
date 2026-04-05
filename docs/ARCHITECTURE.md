# Callis — Architecture

## 1. System Overview

Callis runs as a single unified container (`python:3.12-slim`) managed by supervisord, with an optional fail2ban sidecar. The container runs both the FastAPI application and OpenSSH server as supervised processes.

```
┌──────────────────────────────────────────────────────────┐
│                     Docker Network                        │
│                                                          │
│  ┌────────────────────────────────────────────────┐      │
│  │  callis (unified container)                    │      │
│  │  supervisord                                   │      │
│  │  ├── sshd (OpenSSH)         :22 → host :2222  │      │
│  │  │   ├── auth-keys.sh → http://localhost:8081  │      │
│  │  │   └── callis-cmd.sh (ForceCommand)          │      │
│  │  └── api (FastAPI + Uvicorn)                   │      │
│  │      ├── :8080 — web UI      → host :8080      │      │
│  │      └── :8081 — internal API (localhost only)  │      │
│  └────────────────────────────────────────────────┘      │
│         │                                                │
│  ┌──────┴──────┐                                         │
│  │  fail2ban   │                                         │
│  │  (optional) │                                         │
│  └─────────────┘                                         │
└──────────────────────────────────────────────────────────┘

External access:
  :2222 → sshd (SSH jump connections + CLI resolve/list)
  :8080 → api  (web UI, or via reverse proxy)
```

---

## 2. Components

### 2.1 sshd Process

**Managed by:** supervisord (within the unified container)
**Purpose:** Hardened OpenSSH server. Accepts SSH connections for jump/ProxyJump and CLI commands (`resolve`, `list`).

Key behaviours:
- On first start, generates an Ed25519 host key and persists it to a named volume.
- Runs `sshd` with a hardened configuration (see Security document).
- `AuthorizedKeysCommand` is set to `/etc/ssh/auth-keys.sh %u`, which makes an HTTP request to `http://localhost:8081/internal/keys/{username}` (with `X-Internal-Secret` header) and returns the active public keys for that user.
- OS user accounts are created on-the-fly by `auth-keys.sh` during SSH authentication — only when the API returns valid keys for that username. Accounts are not pre-created.
- When a user is deactivated, the API stops returning keys, so the next SSH auth attempt fails. The OS account is not explicitly removed.
- OS user accounts use the system `nologin` shell (path resolved dynamically). They exist solely to satisfy OpenSSH's per-user key lookup.

Key files:
- `/etc/ssh/sshd_config` — hardened configuration, templated from environment at startup
- `/etc/ssh/auth-keys.sh` — the `AuthorizedKeysCommand` script
- `/etc/ssh/callis-cmd.sh` — the `ForceCommand` script: routes `resolve <tag>` and `list` commands, denies all other shell access
- `/etc/ssh/host_keys/ssh_host_ed25519_key` — persisted host key (volume-mounted)

### 2.2 api Process

**Managed by:** supervisord (within the unified container)
**Purpose:** FastAPI application serving both the web UI and the internal API.

The application is split across two listeners:
- **Port 8080** — public-facing web UI and all authenticated routes
- **Port 8081** — internal-only listener. Serves `/internal/keys/{username}`, `/internal/resolve/{username}/{tag}`, and `/internal/hosts/{username}`. The Uvicorn process binds to `0.0.0.0`; isolation is enforced by not exposing this port in `docker-compose.yml` (Docker network boundary) combined with the mandatory `X-Internal-Secret` header for every request. This port MUST NOT be published in `docker-compose.yml`.

**Framework stack:**
- FastAPI — routing, dependency injection, request handling
- Jinja2 — server-side HTML templating
- htmx (CDN) — partial page updates without JavaScript files
- Pico CSS (CDN) — classless styling
- SQLAlchemy — ORM, supports SQLite (default) and PostgreSQL
- `python-jose` — JWT creation and validation
- `passlib[bcrypt]` — password hashing
- `pyotp` — TOTP generation and validation
- `slowapi` — rate limiting
- `uv` — dependency management

**Directory layout:**
```
api/
├── Dockerfile               # Standalone API image (for split deploys)
├── pyproject.toml
├── main.py                  # App factory, mounts routers, middleware
├── core.py                  # Config, DB session, security utilities
├── models.py                # All SQLAlchemy models
├── dependencies.py          # get_current_user, require_role, require_totp
├── middleware/
│   ├── security_headers.py  # CSP, HSTS, X-Frame-Options, etc.
│   ├── session.py           # JWT cookie validation
│   ├── setup_guard.py       # Redirects to /setup when DB has no users
│   └── totp_guard.py        # Enforces TOTP enrollment before access
├── routers/
│   ├── auth.py              # /login, /logout, /totp/setup, /totp/verify
│   ├── setup.py             # /setup — first-run setup wizard
│   ├── users.py             # /users — CRUD, key management
│   ├── hosts.py             # /hosts — jump target management
│   ├── audit.py             # /audit — log viewer
│   └── internal.py          # /internal/keys, /resolve, /hosts — sshd endpoints
├── static/
│   ├── app.js               # Dialog open/close, htmx helpers
│   └── style.css            # Custom styles (extends Pico CSS)
└── templates/
    ├── base.html            # Nav, CDN links, flash messages
    ├── login.html
    ├── setup.html           # First-run setup wizard (admin account)
    ├── setup_totp.html      # First-run setup wizard (TOTP enrollment)
    ├── totp_setup.html      # Mandatory TOTP enrollment (existing users)
    ├── dashboard.html
    ├── users.html
    ├── user_detail.html
    ├── hosts.html
    ├── audit.html
    ├── 500.html             # Generic error page
    └── partials/            # htmx fragment responses
        ├── user_row.html
        ├── key_list.html
        ├── host_row.html
        ├── ssh_config.html
        └── audit_rows.html
```

### 2.3 fail2ban Sidecar (Optional)

**Base image:** `crazymax/fail2ban:1.1.0`
**Purpose:** Watches sshd logs and bans IPs that repeatedly fail authentication.

- Activated via Docker Compose profile: `docker compose --profile fail2ban up -d`
- Runs with `network_mode: host` and `NET_ADMIN` + `NET_RAW` capabilities to issue iptables bans.
- Reads logs from a shared Docker volume mounted from the callis container (`callis_sshd_logs`).
- Configuration in `fail2ban/jail.local` and `fail2ban/filter.d/sshd.conf`.

---

## 3. Data Model

```
User
├── id (UUID)
├── username (unique)
├── display_name
├── email
├── hashed_password
├── totp_secret (encrypted)
├── totp_enrolled (bool)
├── role (admin | operator | readonly)
├── is_active (bool)
├── created_at
└── last_login_at

SSHKey
├── id (UUID)
├── user_id (FK → User)
├── label
├── public_key_text
├── fingerprint (SHA-256)
├── key_type (ed25519 | rsa)
├── is_active (bool)
├── created_at
└── last_used_at

Host
├── id (UUID)
├── label
├── hostname
├── port (default: 22)
├── description
├── is_active (bool)
└── created_at

UserHostAssignment
├── user_id (FK → User)
└── host_id (FK → Host)

AuditLog
├── id (UUID)
├── timestamp
├── actor_id (FK → User, nullable for system events)
├── action (enum)
├── target_type (user | key | host | session)
├── target_id (UUID)
├── source_ip
└── detail (JSON, action-specific metadata)
```

---

## 4. Request Flow

### First-run setup (no users in DB)
```
Browser → api:8080
  → SecurityHeadersMiddleware
  → SessionMiddleware (no cookie → user = None)
  → SetupGuardMiddleware (zero users → redirect /setup)
  → GET /setup → setup wizard form
  → POST /setup → create admin + session cookie → redirect /setup/totp
  → POST /setup/totp → verify TOTP → mark enrolled → redirect /dashboard
```

### Web UI request (authenticated page)
```
Browser
  → Caddy (TLS, optional)
  → api:8080
  → SecurityHeadersMiddleware (attach headers)
  → SessionMiddleware (validate JWT cookie → attach user to request.state)
  → SetupGuardMiddleware (users exist → pass through, cached)
  → TOTPGuardMiddleware (if user.totp_enrolled is False → redirect /totp/setup)
  → RateLimitMiddleware (slowapi, IP-keyed)
  → Route handler
  → require_role dependency (if applicable)
  → Jinja2 template render
  → HTML response
```

### SSH connection (ProxyJump — manual config)
```
SSH client (ssh -J user@callis:2222 user@target)
  → sshd container:2222
  → OpenSSH: look up user OS account
  → AuthorizedKeysCommand: /etc/ssh/auth-keys.sh username
    → HTTP GET api:8081/internal/keys/username (with X-Internal-Secret)
    → Returns active public keys for user
  → OpenSSH: verify client key against returned keys
  → If match: allow TCP forwarding to target (via permitopen)
```

### SSH connection (Callis CLI — tag-based)
```
callis <tag>
  → ssh user@bastion "resolve <tag>"
  → sshd: ForceCommand → /etc/ssh/callis-cmd.sh
    → reads SSH_ORIGINAL_COMMAND="resolve <tag>"
    → HTTP GET api:8081/internal/resolve/username/tag (with X-Internal-Secret)
    → returns: hostname port
  → client parses "hostname port"
  → ssh -J user@bastion:2222 user@hostname -p port
    → ProxyJump: permitopen="hostname:port" ✓ → connected
```

### Key revocation
```
Admin clicks "Revoke" in web UI
  → POST /users/{id}/keys/{key_id}/revoke
  → SSHKey.is_active = False in database
  → AuditLog entry written
  → Next SSH auth attempt: AuthorizedKeysCommand returns empty
  → OpenSSH: no matching key → connection rejected
```

---

## 5. Network Isolation

The internal API (`api:8081`) MUST NOT be exposed in `docker-compose.yml`. It is only reachable from within the Docker network — specifically from the sshd container making HTTP requests to `http://api:8081`. All internal API requests require a valid `X-Internal-Secret` header (HMAC-SHA256 derived from `SECRET_KEY`) as defense-in-depth.

The public web UI port (`api:8080`) is exposed to the host and optionally fronted by Caddy or an external reverse proxy.

The SSH port (`sshd:2222`) is exposed directly to the host. It does not pass through the API or Caddy.

---

## 6. File Structure (Repository Root)

```
callis/
├── Dockerfile                  # Unified container (API + sshd via supervisord)
├── docker-compose.yml
├── .env.example
├── entrypoint.sh               # Unified container entrypoint (key gen, secret derivation)
├── supervisord.conf            # Manages api + sshd processes
├── README.md
├── .github/
│   └── workflows/
│       └── release.yml         # GitHub Actions: build + push to GHCR on tag
├── docs/
│   ├── REQUIREMENTS.md
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── DEPLOYMENT.md
│   └── DEVELOPMENT.md
├── scripts/
│   └── callis.sh               # Client-side CLI (source into shell)
├── sshd/
│   ├── Dockerfile              # Standalone sshd image (Alpine, for split deploys)
│   ├── sshd_config
│   ├── auth-keys.sh            # AuthorizedKeysCommand script
│   ├── callis-cmd.sh           # ForceCommand script (resolve/list/deny)
│   ├── banner.txt
│   └── entrypoint.sh           # Standalone sshd entrypoint
├── api/
│   ├── Dockerfile              # Standalone API image (for split deploys)
│   ├── pyproject.toml
│   ├── main.py
│   ├── core.py
│   ├── models.py
│   ├── dependencies.py
│   ├── middleware/
│   │   ├── security_headers.py
│   │   ├── session.py
│   │   ├── setup_guard.py
│   │   └── totp_guard.py
│   ├── routers/
│   │   ├── auth.py
│   │   ├── setup.py
│   │   ├── users.py
│   │   ├── hosts.py
│   │   ├── audit.py
│   │   └── internal.py
│   ├── static/
│   │   ├── app.js
│   │   └── style.css
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── setup.html
│       ├── setup_totp.html
│       ├── totp_setup.html
│       ├── dashboard.html
│       ├── users.html
│       ├── user_detail.html
│       ├── hosts.html
│       ├── audit.html
│       ├── 500.html
│       └── partials/
│           ├── user_row.html
│           ├── key_list.html
│           ├── host_row.html
│           ├── ssh_config.html
│           └── audit_rows.html
└── fail2ban/
    ├── jail.local
    └── filter.d/
        └── sshd.conf
```
