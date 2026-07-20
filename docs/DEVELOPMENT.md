# Callis — Development Guide

## 1. Local Dev Setup

### Prerequisites

- Docker + Docker Compose
- Python 3.12+
- `uv` — install with `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Node.js 20+ and npm (frontend development only — production images compile the frontend in a Docker build stage)

### Running the full stack locally

```bash
git clone https://github.com/pacnpal/callis.git
cd callis
docker compose up -d
```

On first start, the setup wizard at `http://localhost:8080` guides you through admin account creation and TOTP enrollment. No `.env` file is required — `SECRET_KEY` is auto-generated.

For development mode (verbose SQL logging), create `.env` with `DEV_MODE=true`.

### Watch mode (recommended for Docker-based dev)

Watch mode automatically syncs your local file changes into the running container, so you don't need to rebuild after every edit.

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -w
```

How it works:
- **File sync + restart**: Changes to files in `api/` are synced into the container and the service restarts automatically.
- **Rebuild trigger**: Changes to `api/pyproject.toml` (new dependencies) or anything under `frontend/` trigger a full container rebuild (the frontend is compiled at image build time).
- Files like `__pycache__/`, `*.pyc`, and `uv.lock` are excluded from sync.

This gives you a tight edit-save-refresh loop without leaving Docker. The full stack (API + sshd) runs exactly as it would in production.

### Running the stack outside Docker (for faster iteration)

Run the JSON API and the SvelteKit dev server side by side:

```bash
# Terminal 1 — the API (binds 127.0.0.1:8000 by default)
cd api
uv sync
uv run uvicorn main:app --reload --port 8000

# Terminal 2 — the SSR frontend with hot module reload
cd frontend
npm ci
npm run dev        # http://localhost:5173, talks to the API on :8000
```

`CALLIS_API_ORIGIN` (default `http://127.0.0.1:8000`) points the frontend at
the API. The sshd container still needs to be running via Docker Compose for
the full SSH flow to work.

---

## 2. Project Conventions

### Adding a new page

1. If the page needs new data, add a JSON endpoint to the appropriate router in
   `api/routers/` with a Pydantic schema in `api/schemas.py` — the API is the
   single source of truth; the frontend never computes data itself.
2. Create a route directory in `frontend/src/routes/<page>/` with
   `+page.server.ts` (server `load` calling the API via `$lib/server/api`, plus
   form actions for any mutations) and `+page.svelte` (the markup).
3. Add a nav link in `frontend/src/routes/+layout.svelte`.
4. That's it — no manual registration; SvelteKit's filesystem router picks it up.

### Form actions and mutations

Mutations are plain HTML form posts to SvelteKit actions (progressively
enhanced with `use:enhance`), which call the API server-side. Return
`fail(status, { error })` from an action to surface API validation errors;
never duplicate validation logic in the frontend.

### Route protection

Every route must use one of these dependencies:

```python
# Any logged-in user with TOTP enrolled
async def my_route(user: User = Depends(require_totp_complete)):
    ...

# Operator or admin only
async def my_route(user: User = Depends(require_role("operator"))):
    ...

# Admin only
async def my_route(user: User = Depends(require_role("admin"))):
    ...
```

Never check roles inline. Never check `request.state.user` directly in a route without going through a dependency.

### Database access

Use the `get_db` dependency for database sessions:

```python
async def my_route(db: AsyncSession = Depends(get_db), user: User = Depends(require_totp_complete)):
    result = await db.execute(select(MyModel).where(...))
    items = result.scalars().all()
    ...
```

### Audit logging

Every admin action and security event must write an audit log entry:

```python
from core import write_audit_log

await write_audit_log(
    db=db,
    actor_id=current_user.id,
    action=AuditAction.KEY_REVOKED,
    target_type="key",
    target_id=key.id,
    source_ip=request.client.host,
    detail={"key_fingerprint": key.fingerprint}
)
```

---

## 3. Dependency Management

Callis uses `uv` for Python dependency management.

```bash
# Add a dependency
uv add some-package

# Update lockfile
uv lock

# Sync environment
uv sync
```

Always commit both `pyproject.toml` and `uv.lock`.

---

## 4. Code Style

- Python: follow PEP 8. Use type hints everywhere.
- Frontend: Svelte 5 (runes), TypeScript strict mode, tab indent, semantic HTML.
  `npm run check` (svelte-check) must pass.
- No inline styles. All styling via bundled Pico CSS classes or
  `frontend/src/lib/styles/app.css`. The CSP restricts every source to `'self'`
  (framework hydration scripts are hash-allowlisted); no CDN assets.
- Frontend state derives from server data (`load` + form actions); pages must
  render and submit without JavaScript wherever practical.

---

## 5. Testing

```bash
cd api
uv run pytest
```

The suite in `api/tests/` covers the security-critical pure functions: SSH key
parsing/validation, TOTP verification, password hashing, JWT session lifecycle
(including idle/absolute expiry), slugify, username validation, and runtime
settings merging. CI (`.github/workflows/ci.yml`) runs it on every push and PR,
plus a full Docker image build.

API endpoint tests live in `api/tests/test_api_v1.py` and drive the same JSON
flow the SSR frontend uses. Every endpoint should have at minimum:
- A test for unauthenticated access (should return 401)
- A test for insufficient role (should return 403)
- A test for the happy path

Frontend type safety is enforced with `npm run check`; CI also compiles the
production bundle (`npm run build`).

---

## 6. Testing Internal API Endpoints

The internal API (port 8081) serves three endpoints used by the sshd container. To test locally:

```bash
# Derive the internal secret (same formula as entrypoint.sh)
SECRET=$(printf 'callis-internal' | openssl dgst -sha256 -hmac "$SECRET_KEY" -hex | awk '{print $NF}')

# Test key lookup
curl -H "X-Internal-Secret: $SECRET" http://localhost:8081/internal/keys/alice

# Test host resolution by tag
curl -H "X-Internal-Secret: $SECRET" http://localhost:8081/internal/resolve/alice/mac-mini

# Test host listing
curl -H "X-Internal-Secret: $SECRET" http://localhost:8081/internal/hosts/alice

# Test without secret (should return 403)
curl -v http://localhost:8081/internal/keys/alice
```

To test the SSH command interface end-to-end:

```bash
# Resolve a host tag via SSH
ssh -p 2222 alice@localhost "resolve mac-mini"

# List hosts via SSH
ssh -p 2222 alice@localhost list

# Shell access denied (default behavior)
ssh -p 2222 alice@localhost
```

---

## 7. Environment Variables for Dev

Add to `.env`:
```env
DEV_MODE=true          # Enables verbose SQL logging
LOG_LEVEL=debug        # Verbose logging
```

**Note:** Cookie `Secure` flag is controlled by `HTTPS_ENABLED`, not `DEV_MODE`. For local HTTP dev, ensure `HTTPS_ENABLED=false` (the default).
