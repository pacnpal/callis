# Callis — Development Guide

## 1. Local Dev Setup

### Prerequisites

- Docker + Docker Compose
- Python 3.12+
- `uv` — install with `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Running the full stack locally

```bash
git clone https://github.com/yourname/callis.git
cd callis
cp .env.example .env
docker compose up -d
```

The API container runs with `--reload` in development mode (set `DEV_MODE=true` in `.env`). Template changes and Python file changes reload automatically.

### Running the API outside Docker (for faster iteration)

```bash
cd api
uv sync
uv run uvicorn main:app --reload --port 8080
```

The sshd container still needs to be running via Docker Compose for the full SSH flow to work.

---

## 2. Project Conventions

### Adding a new page

1. Add a route function to the appropriate router in `routers/`
2. Create a template in `templates/`
3. Add a nav link to `templates/base.html`
4. That's it. No build step, no registration, no imports beyond the router.

### Adding a new htmx partial

1. Add a route that checks `request.headers.get("HX-Request")` and returns a `TemplateResponse` with a partial template
2. Create the partial template in `templates/partials/`
3. Wire the `hx-get` / `hx-post` / `hx-target` attributes in the parent template

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
async def my_route(db: Session = Depends(get_db), user: User = Depends(require_totp_complete)):
    items = db.query(MyModel).filter(...).all()
    ...
```

### Audit logging

Every admin action and security event must write an audit log entry:

```python
from core import write_audit_log

write_audit_log(
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
- Templates: Jinja2, 2-space indent, semantic HTML.
- No inline styles in templates. All styling via Pico CSS classes or `static/style.css`.
- No JavaScript files. All interactivity via htmx attributes in templates. Exception: minimal inline `onclick` for `<dialog>` modal toggling, which has no declarative alternative.

---

## 5. Testing

```bash
cd api
uv run pytest
```

Tests live in `api/tests/`. Every route should have at minimum:
- A test for unauthenticated access (should redirect to login)
- A test for insufficient role (should return 403)
- A test for the happy path

---

## 6. Environment Variables for Dev

Add to `.env`:
```env
DEV_MODE=true          # Enables verbose SQL logging
LOG_LEVEL=debug        # Verbose logging
```

**Note:** Cookie `Secure` flag is controlled by `HTTPS_ENABLED`, not `DEV_MODE`. For local HTTP dev, ensure `HTTPS_ENABLED=false` (the default).
