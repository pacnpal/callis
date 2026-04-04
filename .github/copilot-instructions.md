# Copilot Instructions — Callis

## 1. Project Overview

Callis is a self-hosted SSH jump server (bastion host) with a web UI for managing users, SSH keys, hosts, and audit logs. It is deployed via Docker Compose as a multi-container stack: a hardened OpenSSH server, a FastAPI web application, and optional Caddy/fail2ban sidecars.

**Languages & frameworks:** Python 3.12+, FastAPI, Jinja2, htmx (CDN), Pico CSS (CDN), SQLAlchemy (SQLite default, PostgreSQL optional).
**Dependency management:** `uv` (not pip). Always commit both `pyproject.toml` and `uv.lock`.
**No frontend build step.** No Node.js, no npm, and no project JavaScript files. Implement interactivity in Jinja2 templates using htmx attributes and native HTML behavior.

## 2. Build & Validation Commands

> **Note:** The repo is currently in the design/documentation phase. The source files (`api/`, `sshd/`, `docker-compose.yml`, `.env.example`, etc.) described in `docs/ARCHITECTURE.md` and `docs/DEVELOPMENT.md` have not been committed yet. The commands below apply to the **intended** project layout and will work once the source code is added.

### Full stack (Docker)

```bash
cp .env.example .env        # Set SECRET_KEY and ADMIN_PASSWORD
docker compose up -d         # Starts api (8080), sshd (2222), optional sidecars
docker compose down          # Teardown
```

### API development (outside Docker)

```bash
cd api
uv sync                      # Install/sync Python dependencies
uv run uvicorn main:app --reload --port 8080   # Run API with hot reload
```

Always run `uv sync` before `uv run`. The sshd container must still be running via Docker Compose for the SSH flow to work.

### Testing

```bash
cd api
uv run pytest                # Run test suite from api/ directory
```

Once the source tree is added, tests should live in `api/tests/` (that directory does not exist yet in the current documentation-only checkout). Every route needs: unauthenticated access test (redirect to login), insufficient role test (403), and happy-path test.

### Dependency management

```bash
uv add <package>             # Add a dependency
uv lock                      # Update lockfile
uv sync                      # Sync environment
```

Always commit both `pyproject.toml` and `uv.lock` together.

### Environment variables

Set `DEV_MODE=true` and `LOG_LEVEL=debug` in `.env` for local development. `DEV_MODE=true` disables the `Secure` cookie flag for plain HTTP. Never use in production.

## 3. Project Layout & Architecture

The following is the **target project structure** as described in `docs/ARCHITECTURE.md`. Not all directories and files exist yet — verify against the actual repo contents before referencing specific paths.

```
callis/
├── api/                        # FastAPI application (main codebase)
│   ├── main.py                 # App factory, mounts routers and middleware
│   ├── core.py                 # Config, DB session, security utilities, audit logging
│   ├── models.py               # All SQLAlchemy models (User, SSHKey, Host, AuditLog)
│   ├── dependencies.py         # Auth dependencies: require_role(), require_totp (aka require_totp_complete)
│   ├── middleware/
│   │   ├── security_headers.py # CSP, HSTS, X-Frame-Options
│   │   ├── session.py          # JWT cookie validation
│   │   └── totp_guard.py       # Enforces TOTP enrollment before access
│   ├── routers/
│   │   ├── auth.py             # /login, /logout, /totp/setup, /totp/verify
│   │   ├── users.py            # /users — CRUD, key management
│   │   ├── hosts.py            # /hosts — jump target management
│   │   ├── audit.py            # /audit — log viewer
│   │   └── internal.py         # /internal/keys/{username} — sshd key lookup (port 8081)
│   └── templates/              # Jinja2 templates (base.html, partials/)
├── sshd/                       # Hardened OpenSSH container
│   ├── Dockerfile, sshd_config, auth-keys.sh, entrypoint.sh
├── caddy/                      # Optional TLS sidecar (Caddyfile)
├── fail2ban/                   # Optional brute-force protection (jail.local, filter.d/)
├── docs/                       # REQUIREMENTS, ARCHITECTURE, SECURITY, DEPLOYMENT, DEVELOPMENT
├── docker-compose.yml
├── docker-compose.override.yml # Caddy sidecar (opt-in via --profile caddy)
└── .env.example
```

**Dual-port architecture:** The API runs two Uvicorn servers — port 8080 (public web UI) and port 8081 (internal key endpoint for sshd only, never exposed outside Docker network).

### Key conventions

- **Route protection:** Always use approved dependencies such as `Depends(require_totp_complete)` (or `Depends(require_totp)` if that is the alias/canonical name in the current code/docs), `Depends(require_role("operator"))`, or `Depends(require_role("admin"))`, as appropriate for the route. Verify the exact TOTP dependency name against the repository and documentation before using it. Never check roles inline or access `request.state.user` directly.
- **Database access:** Use `Depends(get_db)` for sessions.
- **Audit logging:** Every admin action and security event must call `write_audit_log()` from `core.py`.
- **Templates:** 2-space indent, semantic HTML. No inline styles (use Pico classes or `static/style.css`). No inline JS — CSP blocks `unsafe-inline`. Use htmx attributes and native HTML behavior for interactivity.
- **Adding a page:** One route function in `routers/`, one template in `templates/`, one nav link in `base.html`.
- **Code style:** PEP 8, type hints everywhere.

### SSH key handling

Preserve valid OpenSSH public-key formatting when storing or serving keys via AuthorizedKeysCommand. Only Ed25519 and RSA (4096-bit minimum) keys are accepted.

## 4. File Reference

> Files marked with † are described in the documentation but not yet committed to the repository.

| File | Purpose |
|---|---|
| `README.md` | Quick start and feature summary |
| `.env.example` † | All environment variables with defaults |
| `docker-compose.yml` † | Primary stack definition (api + sshd) |
| `docker-compose.override.yml` † | Optional Caddy sidecar profile |
| `docs/REQUIREMENTS.md` | Full functional and security requirements |
| `docs/ARCHITECTURE.md` | System design, data model, request flows |
| `docs/SECURITY.md` | Security contracts, SSH hardening, threat model |
| `docs/DEPLOYMENT.md` | Deployment modes and env var reference |
| `docs/DEVELOPMENT.md` | Local dev setup and contribution conventions |

### Key environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SECRET_KEY` | Yes | — | `openssl rand -hex 32` |
| `ADMIN_PASSWORD` | Yes | — | Initial admin password |
| `DATABASE_URL` | No | `sqlite:///./callis.db` | PostgreSQL via `postgresql://...` |
| `AUTH_MODE` | No | `local` | `local` or `oidc` |
| `DEV_MODE` | No | `false` | Enables reload, disables Secure cookies |

## 5. Final Note

Use these instructions as guidance, but verify referenced files, directories, commands, and workflows against the repository contents and available documentation before relying on them. If anything here differs from the repo or docs, follow the repo and docs as the source of truth.
