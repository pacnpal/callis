# Callis — Architecture

## 1. System Overview

Callis runs as a single unified container (`python:3.12-slim` plus a bare Node runtime binary) managed by supervisord, with an optional fail2ban sidecar. The container runs three supervised processes: the SvelteKit SSR web server (the only public HTTP entrypoint), the FastAPI JSON API (the single source of truth for all data and business logic), and OpenSSH.

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
│  │  ├── web (SvelteKit SSR, Node)                 │      │
│  │  │   └── :8080 — web UI      → host :8080      │      │
│  │  │       proxies /install.sh /callis.sh        │      │
│  │  │       /health → api:8000                    │      │
│  │  └── api (FastAPI + Uvicorn)                   │      │
│  │      ├── :8000 — JSON API (localhost only)     │      │
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
  :8080 → web  (SSR web UI, or via reverse proxy)
```

---

## 2. Components

### 2.1 sshd Process

**Managed by:** supervisord (within the unified container)
**Purpose:** Hardened OpenSSH server. Accepts SSH connections for jump/ProxyJump and CLI commands (`resolve`, `list`).

Key behaviours:
- On first start, generates an Ed25519 host key and persists it to a named volume.
- Runs `sshd` with a hardened configuration (see Security document).
- `AuthorizedKeysCommand` is set to `/etc/ssh/auth-keys.sh %u %f`, which makes an HTTP request to `http://localhost:8081/internal/keys/{username}` (with `X-Internal-Secret` header) and returns the active public keys for that user. The `%f` token carries the offered key's SHA-256 fingerprint, which the API uses to stamp the key's last-used time and write a `key_used` audit entry.
- OS user accounts are created on-the-fly by `auth-keys.sh` during SSH authentication — only when the API returns valid keys for that username. Accounts are not pre-created.
- When a user is deactivated, the API stops returning keys, so the next SSH auth attempt fails. The OS account is not explicitly removed.
- OS user accounts use the system `nologin` shell (path resolved dynamically). They exist solely to satisfy OpenSSH's per-user key lookup.

Key files:
- `/etc/ssh/sshd_config` — hardened configuration, templated from environment at startup
- `/etc/ssh/auth-keys.sh` — the `AuthorizedKeysCommand` script
- `/etc/ssh/callis-cmd.sh` — the `ForceCommand` script: routes `resolve <tag>` and `list` commands, denies all other shell access
- `/etc/ssh/host_keys/ssh_host_ed25519_key` — persisted host key (volume-mounted)

### 2.2 web Process (SvelteKit SSR)

**Managed by:** supervisord (within the unified container)
**Purpose:** Server-side-rendered web UI. The only public HTTP listener.

- **Svelte 5 + SvelteKit 2** with `adapter-node`; compiled at Docker build time into a self-contained bundle (`/app/web`) executed by the bare `node` binary — no npm or `node_modules` at runtime.
- Every page is rendered on the server; forms are native HTML form posts to SvelteKit actions (progressively enhanced when JS is available), so the UI works without JavaScript.
- All data comes from the JSON API on `127.0.0.1:8000` via server-side fetch. The web layer holds no business logic and no database access — the API is the single source of truth.
- Forwards the browser's `callis_session` cookie to the API and replays the API's `Set-Cookie` responses (login, refresh, logout) back to the browser, so the API also stays the single source of truth for session cookie attributes.
- Forwards the client address chain (`X-Forwarded-For`) so API rate limiting and audit source IPs see real client addresses.
- Transparently proxies `/install.sh`, `/callis.sh`, and `/health` to the API so the CLI installer flow keeps its historical URLs.
- Applies a strict CSP (`'self'` everywhere, hash-allowlisted hydration scripts) plus the standard security headers, and performs a host-based CSRF origin check on all form posts.
- Auth guard errors from the API (`authentication_required`, `totp_enrollment_required`, `setup_required`) are translated into redirects to `/login`, `/totp/setup`, and `/setup`.

### 2.3 api Process

**Managed by:** supervisord (within the unified container)
**Purpose:** FastAPI application serving the versioned JSON API (`/api/v1`) and the internal sshd-facing API. Single source of truth for all data, validation, authorization, and audit logging.

The application is split across two listeners:
- **Port 8000** — JSON API consumed exclusively by the SSR web server over loopback. Not published outside the container.
- **Port 8081** — internal-only listener. Serves `/internal/keys/{username}`, `/internal/resolve/{username}/{tag}`, and `/internal/hosts/{username}`. The Uvicorn process binds to `0.0.0.0`; isolation is enforced by not exposing this port in `docker-compose.yml` (Docker network boundary) combined with the mandatory `X-Internal-Secret` header for every request. This port MUST NOT be published in `docker-compose.yml`.

**Framework stack:**
- FastAPI — routing, dependency injection, request handling
- Pydantic — typed request/response schemas (`schemas.py`) for every endpoint
- SQLAlchemy — ORM, supports SQLite (default) and PostgreSQL
- `PyJWT` — JWT creation and validation
- `bcrypt` — password hashing
- `pyotp` — TOTP generation and validation
- `cryptography` — TOTP secret encryption (Fernet), SSH keypair generation
- `slowapi` — rate limiting
- `uv` — dependency management (locked via `uv.lock`, installed with `--frozen`)

The api process also runs a **session tracker** (started in the FastAPI lifespan): it tails the sshd log (`/var/log/callis/auth.log`, the same file the fail2ban sidecar reads) and records accepted connections and disconnects as `SshSession` rows with `session_opened`/`session_closed` audit entries. The tracker persists its read position so an API-only restart resumes where it stopped, and the startup sweep only closes records whose connection is no longer established. In the unified container, admins can terminate a session from the web UI — the tracker locates the per-connection sshd child via `/proc/net/tcp{,6}` socket-inode matching and signals it (api and sshd share a PID namespace).

**Directory layout:**
```
api/
├── Dockerfile               # Standalone API image (for split deploys)
├── pyproject.toml
├── uv.lock                  # Locked dependency versions (installed with --frozen)
├── main.py                  # App factory, mounts /api/v1 routers, middleware
├── core.py                  # Config, DB session, security utilities, effective-host resolution
├── models.py                # All SQLAlchemy models
├── schemas.py               # Pydantic response/request schemas for /api/v1
├── dependencies.py          # get_current_user, require_role, require_totp
├── session_tracker.py       # Tails the sshd log into SshSession rows; /proc-based termination
├── middleware/
│   ├── security_headers.py  # CSP, HSTS, X-Frame-Options, etc.
│   ├── session.py           # JWT cookie validation, session-expiry auditing
│   ├── setup_guard.py       # 409 setup_required when DB has no users
│   └── totp_guard.py        # 403 totp_enrollment_required before enrollment
├── routers/
│   ├── auth.py              # /api/v1/auth — login, logout, me, TOTP enrollment
│   ├── setup.py             # /api/v1/setup — first-run wizard endpoints
│   ├── users.py             # /api/v1/users — CRUD, roles, key management, recovery codes
│   ├── hosts.py             # /api/v1/hosts — jump targets, assignments, deploy key
│   ├── groups.py            # /api/v1/groups — host groups (bulk access assignment)
│   ├── sessions.py          # /api/v1/sessions — live SSH session view + admin terminate
│   ├── audit.py             # /api/v1/audit — filterable, paginated log
│   ├── settings.py          # /api/v1/settings — runtime configuration
│   ├── dashboard.py         # /api/v1/dashboard — stats + recent activity
│   ├── meta.py              # /api/v1/meta — public instance metadata
│   └── internal.py          # /internal/keys, /resolve, /hosts — sshd endpoints
├── static/
│   └── callis.sh            # The Callis CLI (served at /callis.sh)
└── tests/                   # Pytest suite (run with `uv run pytest`)

frontend/
├── package.json             # Pinned toolchain; package-lock.json committed
├── svelte.config.js         # adapter-node + strict CSP configuration
├── src/
│   ├── hooks.server.ts      # Security headers, CSRF origin check, API proxy
│   ├── lib/
│   │   ├── server/api.ts    # Server-side API client (cookie + XFF forwarding)
│   │   ├── types.ts         # Typed mirror of api/schemas.py
│   │   ├── format.ts        # Deterministic UTC date formatting
│   │   ├── actions/         # Svelte actions (confirm-before-submit)
│   │   ├── components/      # Dialog, CopyButton, ThemeToggle, TotpEnroll, …
│   │   └── styles/app.css   # App styles (extends bundled Pico CSS)
│   └── routes/              # One directory per page (SSR load + form actions)
│       ├── login/  setup/  setup/totp/  totp/setup/
│       ├── dashboard/  users/  users/[id]/  hosts/  audit/  settings/
│       └── logout/
└── static/                  # theme.js (FOUC-free theme init), favicon
```

### 2.4 fail2ban Sidecar (Optional)

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

HostGroup
├── id (UUID)
├── name (unique)
├── description
└── created_at
    (membership via HostGroupHosts [group_id, host_id] and
     HostGroupUsers [group_id, user_id]; a user's effective host access
     is direct assignments ∪ group memberships — core.get_effective_hosts,
     the single source of truth used by the internal API and the web UI)

RecoveryCode
├── id (UUID)
├── user_id (FK → User)
├── code_digest (HMAC-SHA256, keyed by SECRET_KEY)
├── used_at (null = unused)
└── created_at

SshSession
├── id (UUID)
├── user_id (FK → User, SET NULL on user deletion)
├── username (denormalized)
├── source_ip / source_port
├── key_fingerprint
├── started_at / ended_at
└── close_reason (disconnected | terminated | server_restart)

SessionTrackerState (single row)
├── log_inode / log_offset (BigInteger — resume point in the sshd log)
└── updated_at

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
Browser → web:8080 (SvelteKit SSR)
  → layout load: GET api:8000/api/v1/meta → setup_needed: true → redirect /setup
  → GET /setup → SSR setup wizard form
  → POST /setup (form action) → POST api:8000/api/v1/setup
      → create admin + Set-Cookie replayed to browser → redirect /setup/totp
  → POST /setup/totp (form action) → POST api:8000/api/v1/setup/totp/verify
      → verify TOTP → mark enrolled → redirect /dashboard
(Server-side, SetupGuardMiddleware rejects every other API endpoint with
409 setup_required until an admin account exists.)
```

### Web UI request (authenticated page)
```
Browser
  → Caddy (TLS, optional)
  → web:8080 (SvelteKit SSR)
  → hooks.server.ts (CSRF origin check, security headers)
  → page load → server-side fetch api:8000/api/v1/… (cookie + XFF forwarded)
      → SecurityHeadersMiddleware (attach headers)
      → SessionMiddleware (validate JWT cookie → attach user to request.state)
      → SetupGuardMiddleware (users exist → pass through, cached)
      → TOTPGuardMiddleware (not enrolled → 403 totp_enrollment_required)
      → RateLimitMiddleware (slowapi, IP-keyed via forwarded client address)
      → Route handler + require_role dependency → Pydantic JSON response
  → SSR render (session-refresh Set-Cookie replayed to browser)
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
  → form action → POST api:8000/api/v1/users/{id}/keys/{key_id}/revoke
  → SSHKey.is_active = False in database
  → AuditLog entry written
  → Next SSH auth attempt: AuthorizedKeysCommand returns empty
  → OpenSSH: no matching key → connection rejected
```

---

## 5. Network Isolation

The internal API (`api:8081`) MUST NOT be exposed in `docker-compose.yml`. It is only reachable from within the Docker network — specifically from the sshd container making HTTP requests to `http://api:8081`. All internal API requests require a valid `X-Internal-Secret` header (HMAC-SHA256 derived from `SECRET_KEY`) as defense-in-depth.

The JSON API (`api:8000`) binds to loopback inside the container and is reachable only through the SSR web server. The public web UI port (`web:8080`) is exposed to the host and optionally fronted by Caddy or an external reverse proxy.

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
│       ├── ci.yml              # GitHub Actions: pytest + Docker build on push/PR
│       └── release.yml         # GitHub Actions: build + push to GHCR on tag
├── docs/
│   ├── REQUIREMENTS.md
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── DEPLOYMENT.md
│   ├── DEVELOPMENT.md
│   └── SVELTE_MIGRATION.md     # Proposed future frontend migration plan
├── sshd/
│   ├── Dockerfile              # Standalone sshd image (Alpine, for split deploys)
│   ├── sshd_config
│   ├── auth-keys.sh            # AuthorizedKeysCommand script
│   ├── callis-cmd.sh           # ForceCommand script (resolve/list/deny)
│   ├── banner.txt
│   └── entrypoint.sh           # Standalone sshd entrypoint
├── api/                        # See §2.2 for the full API directory layout
└── fail2ban/
    ├── jail.local
    └── filter.d/
        └── sshd.conf
```
