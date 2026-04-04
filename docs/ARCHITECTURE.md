# Callis — Architecture

## 1. System Overview

Callis consists of two required containers and two optional sidecars, orchestrated via Docker Compose.

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Network                       │
│                                                         │
│  ┌─────────────┐        ┌─────────────────────────┐    │
│  │  sshd       │◄───────│  api                    │    │
│  │  (Alpine +  │  keys  │  (FastAPI + Jinja2)     │    │
│  │   OpenSSH)  │        │                         │    │
│  │             │        │  :8080 — web UI         │    │
│  │  :2222      │        │  :8081 — internal only  │    │
│  └─────────────┘        └─────────────────────────┘    │
│         │                          │                    │
│  ┌──────┴──────┐        ┌──────────┴──────────┐        │
│  │  fail2ban   │        │  caddy (optional)    │        │
│  │  (sidecar)  │        │  (sidecar, profile)  │        │
│  └─────────────┘        └─────────────────────-┘        │
└─────────────────────────────────────────────────────────┘

External access:
  :2222 → sshd (SSH jump connections)
  :8080 → api  (web UI, or via reverse proxy)
```

---

## 2. Components

### 2.1 sshd Container

**Base image:** `alpine:latest`
**Purpose:** Hardened OpenSSH server. Pure jump point — no shell, no services beyond sshd.

Key behaviours:
- On first start, generates an Ed25519 host key and persists it to a named volume.
- Runs `sshd` with a hardened configuration (see Security document).
- `AuthorizedKeysCommand` is set to `/etc/ssh/auth-keys.sh %u`, which makes an HTTP request to `http://api:8081/internal/keys/{username}` and returns the active public keys for that user.
- When a Callis user is created, a corresponding OS user account is created in the container. When deleted or deactivated, the OS account is removed or locked.
- OS user accounts have `/sbin/nologin` as their shell. They exist solely to satisfy OpenSSH's per-user key lookup.

Key files:
- `/etc/ssh/sshd_config` — hardened configuration, templated from environment at startup
- `/etc/ssh/auth-keys.sh` — the `AuthorizedKeysCommand` script
- `/etc/ssh/callis-cmd.sh` — the `ForceCommand` script: routes `resolve <tag>` and `list` commands, denies all other shell access
- `/etc/ssh/host_keys/ssh_host_ed25519_key` — persisted host key (volume-mounted)

### 2.2 api Container

**Base image:** `python:3.12-slim`
**Purpose:** FastAPI application serving both the web UI and the internal key endpoint.

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
├── Dockerfile
├── pyproject.toml
├── uv.lock
├── main.py                  # App factory, mounts routers, middleware
├── core.py                  # Config, DB session, security utilities
├── models.py                # All SQLAlchemy models
├── dependencies.py          # get_current_user, require_role, require_totp
├── middleware/
│   ├── security_headers.py  # CSP, HSTS, X-Frame-Options, etc.
│   ├── session.py           # JWT cookie validation
│   └── totp_guard.py        # Enforces TOTP enrollment before access
├── routers/
│   ├── auth.py              # /login, /logout, /totp/setup, /totp/verify
│   ├── users.py             # /users — CRUD, key management
│   ├── hosts.py             # /hosts — jump target management
│   ├── audit.py             # /audit — log viewer
│   └── internal.py          # /internal/keys, /resolve, /hosts — sshd endpoints
└── templates/
    ├── base.html            # Nav, CDN links, flash messages
    ├── login.html
    ├── totp_setup.html      # Mandatory TOTP enrollment
    ├── dashboard.html
    ├── users.html
    ├── user_detail.html
    ├── hosts.html
    ├── audit.html
    └── partials/            # htmx fragment responses
        ├── user_row.html
        ├── key_list.html
        ├── host_row.html
        └── audit_rows.html
```

### 2.3 fail2ban Sidecar (Optional)

**Base image:** `crazymax/fail2ban:latest`
**Purpose:** Watches sshd logs and bans IPs that repeatedly fail authentication.

- Runs with `network_mode: host` and `NET_ADMIN` + `NET_RAW` capabilities to issue iptables bans.
- Reads logs from a shared Docker volume mounted from the sshd container.
- Configuration in `fail2ban/jail.local` and `fail2ban/filter.d/sshd.conf`.

### 2.4 Caddy Sidecar (Optional)

**Base image:** `caddy:latest`
**Purpose:** Automatic TLS termination for users who don't have an existing reverse proxy.

- Activated via Docker Compose profile: `docker compose --profile caddy up -d`
- Reads `CALLIS_DOMAIN` from environment to configure the virtual host.
- Proxies HTTPS to the api container on port 8080.
- Does NOT proxy the SSH port — that must be handled at the network/firewall level.

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

### Web UI request (authenticated page)
```
Browser
  → Caddy (TLS, optional)
  → api:8080
  → SecurityHeadersMiddleware (attach headers)
  → SessionMiddleware (validate JWT cookie → attach user to request.state)
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
├── docker-compose.yml
├── docker-compose.override.yml    # Caddy sidecar (opt-in)
├── .env.example
├── README.md
├── docs/
│   ├── REQUIREMENTS.md
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── DEPLOYMENT.md
│   └── DEVELOPMENT.md
├── scripts/
│   └── callis.sh               # Client-side CLI (source into shell)
├── sshd/
│   ├── Dockerfile
│   ├── sshd_config
│   ├── auth-keys.sh
│   ├── callis-cmd.sh           # ForceCommand script (resolve/list/deny)
│   └── entrypoint.sh
├── api/
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── uv.lock
│   ├── main.py
│   ├── core.py
│   ├── models.py
│   ├── dependencies.py
│   ├── middleware/
│   │   ├── security_headers.py
│   │   ├── session.py
│   │   └── totp_guard.py
│   ├── routers/
│   │   ├── auth.py
│   │   ├── users.py
│   │   ├── hosts.py
│   │   ├── audit.py
│   │   └── internal.py
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── totp_setup.html
│       ├── dashboard.html
│       ├── users.html
│       ├── user_detail.html
│       ├── hosts.html
│       ├── audit.html
│       └── partials/
│           ├── user_row.html
│           ├── key_list.html
│           ├── host_row.html
│           └── audit_rows.html
├── caddy/
│   └── Caddyfile
└── fail2ban/
    ├── jail.local
    └── filter.d/
        └── sshd.conf
```
