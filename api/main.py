import asyncio
import contextlib
import ipaddress
import logging
import shlex
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncEngine
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from core import get_engine, get_runtime_setting, get_session_factory, get_settings, limiter, load_db_settings
from middleware import SecurityHeadersMiddleware, SessionMiddleware, TOTPGuardMiddleware
from middleware.setup_guard import SetupGuardMiddleware
from models import AuditAction, Base, User
from routers import auth, users, hosts, groups, sessions, audit, setup, settings as settings_router
from routers import dashboard, meta
from routers.internal import internal_app
from session_tracker import close_stale_open_sessions, follow_sshd_log

logger = logging.getLogger("callis")

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # DB init + settings cache preload on startup — runs for any entrypoint
    # (both `python main.py` via run_servers() and `uvicorn main:app` directly)
    await _init_db()
    await load_db_settings()

    if get_settings().AUTH_MODE.lower() == "oidc":
        logger.warning(
            "AUTH_MODE=oidc is set but OIDC authentication is not implemented yet; "
            "falling back to the built-in local username/password + TOTP flow."
        )

    # Warn if no admin account has been created yet (first-run state)
    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(select(func.count()).select_from(User))
        if result.scalar() == 0:
            logger.warning("=" * 60)
            logger.warning("FIRST RUN: No admin account exists.")
            logger.warning("Open http://<server>:8080 IMMEDIATELY to complete setup.")
            logger.warning("The /setup page is publicly accessible until an admin")
            logger.warning("account is created. Do not expose this port until done.")
            logger.warning("=" * 60)

    # SSH session tracking: close records orphaned by a previous run (unless
    # their connection is still established), then follow the sshd log for
    # live connect/disconnect events.
    await close_stale_open_sessions()
    tracker_task = asyncio.create_task(follow_sshd_log())

    yield

    tracker_task.cancel()
    # Cancellation is the expected way the follower stops; anything else
    # already logged inside the task.
    with contextlib.suppress(asyncio.CancelledError):
        await tracker_task
    engine = get_engine()
    await engine.dispose()


# ---------------------------------------------------------------------------
# JSON API app (internal port; the SvelteKit SSR server on 8080 is the only
# public entrypoint and proxies /install.sh, /callis.sh and /health here)
# ---------------------------------------------------------------------------

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware (applied in reverse order — last added runs first)
app.add_middleware(TOTPGuardMiddleware)
app.add_middleware(SetupGuardMiddleware)
app.add_middleware(SessionMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
def _resolve_trusted_hosts(settings) -> list[str]:
    """Resolve the proxy allow-list for ProxyHeadersMiddleware.

    The SvelteKit SSR server always fronts this app from loopback and forwards
    the real client address in X-Forwarded-For, so loopback is always trusted.
    When HTTPS_ENABLED=true the deployment sits behind an additional TLS reverse
    proxy; TRUSTED_PROXIES must name that proxy's IP/CIDR(s) so only it can
    extend the forwarding chain. Trusting "*" — or a catch-all network like
    0.0.0.0/0 or ::/0 — would let ANY client spoof X-Forwarded-For, forging
    audit-log source IPs and bypassing the per-IP login rate limiter, so we fail
    closed on a missing/wildcard/catch-all allow-list rather than fall open.
    """
    loopback = ["127.0.0.1", "::1"]
    if not settings.HTTPS_ENABLED:
        # LAN/HTTP mode: only the loopback SSR server is a trusted hop.
        return loopback

    tokens = [h.strip() for h in settings.TRUSTED_PROXIES.split(",") if h.strip()]

    def _is_catch_all(token: str) -> bool:
        try:
            return ipaddress.ip_network(token, strict=False).prefixlen == 0
        except ValueError:
            return False

    if not tokens or "*" in tokens or any(_is_catch_all(t) for t in tokens):
        raise RuntimeError(
            'HTTPS_ENABLED=true requires TRUSTED_PROXIES to name your reverse '
            "proxy's IP address(es) or CIDR(s), comma-separated. Trusting \"*\" "
            "or a catch-all network (0.0.0.0/0, ::/0) lets any client spoof "
            "X-Forwarded-For, forging audit source IPs and bypassing login rate "
            "limiting. Set TRUSTED_PROXIES to your proxy and restart."
        )
    return loopback + tokens


app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=_resolve_trusted_hosts(get_settings()))

# Routers — the JSON API is versioned under /api/v1 and is the single source
# of truth for every value the frontend renders.
API_V1_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_V1_PREFIX)
app.include_router(setup.router, prefix=API_V1_PREFIX)
app.include_router(users.router, prefix=API_V1_PREFIX)
app.include_router(hosts.router, prefix=API_V1_PREFIX)
app.include_router(groups.router, prefix=API_V1_PREFIX)
app.include_router(sessions.router, prefix=API_V1_PREFIX)
app.include_router(audit.router, prefix=API_V1_PREFIX)
app.include_router(settings_router.router, prefix=API_V1_PREFIX)
app.include_router(dashboard.router, prefix=API_V1_PREFIX)
app.include_router(meta.router, prefix=API_V1_PREFIX)


@app.get("/health")
async def health():
    return {"status": "ok"}


# CLI installer — curl http://callis:8080/install.sh | sh
@app.get("/install.sh")
async def install_script():
    base_url = (await get_runtime_setting("base_url") or "http://localhost:8080").rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        return PlainTextResponse(
            "Installer unavailable: BASE_URL is not configured correctly.\n",
            status_code=503,
        )
    script_url = f"{base_url}/callis.sh"
    installer = f'''#!/bin/sh
set -e

CALLIS_DIR="$HOME/.config/callis"
SCRIPT_URL={shlex.quote(script_url)}

echo "Installing Callis CLI..."
mkdir -m 700 -p "$CALLIS_DIR"
chmod 700 "$CALLIS_DIR"
curl -fsSL "$SCRIPT_URL" -o "$CALLIS_DIR/callis.sh"
chmod 644 "$CALLIS_DIR/callis.sh"

SOURCE_LINE='. "$HOME/.config/callis/callis.sh"'
ADDED=0

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ]; then
        if ! grep -qF "callis/callis.sh" "$rc"; then
            printf '\\n# Callis CLI\\n%s\\n' "$SOURCE_LINE" >> "$rc"
            echo "  Added to $(basename "$rc")"
            ADDED=1
        else
            echo "  Already in $(basename "$rc")"
            ADDED=1
        fi
    fi
done

if [ "$ADDED" -eq 0 ]; then
    echo "  No .bashrc or .zshrc found. Add this to your shell rc:"
    echo "    $SOURCE_LINE"
fi

echo ""
echo "Done! Run '$SOURCE_LINE' or open a new shell, then:"
echo "  callis setup"
echo "  callis list"
echo "  callis <tag>"
'''
    return Response(content=installer, media_type="text/plain")


def _get_callis_script_path() -> Path | None:
    # api/static/callis.sh is the single canonical source; it is bundled into
    # the Docker image via `COPY api/ .` so it is always present in production.
    script_path = Path(__file__).resolve().parent / "static" / "callis.sh"
    return script_path if script_path.is_file() else None


# Serve the raw CLI script
@app.get("/callis.sh")
async def callis_script():
    script_path = _get_callis_script_path()
    if script_path is None:
        logger.warning(
            "callis.sh not found; expected at: %s",
            str(Path(__file__).resolve().parent / "static" / "callis.sh"),
        )
        return PlainTextResponse("callis.sh not found.\n", status_code=404)
    return FileResponse(script_path, media_type="text/plain")


# Global exception handlers — JSON only; the SSR frontend owns error pages.
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


# ---------------------------------------------------------------------------
# Entrypoint: run both apps
# ---------------------------------------------------------------------------

# Mutable set tracks which init steps have run; avoids a `global` bool flag.
_initialized: set[str] = set()


async def _sync_pg_audit_enum(engine: AsyncEngine) -> None:
    """PostgreSQL only: add any missing AuditAction labels to the native enum.

    Base.metadata.create_all() creates missing tables but never alters an
    existing native enum type, so an upgraded installation would fail on the
    first write of a newly introduced audit action. ALTER TYPE ... ADD VALUE
    cannot run inside a transaction block, hence the AUTOCOMMIT connection.
    No-op for SQLite.
    """
    if engine.dialect.name != "postgresql":
        return
    async with engine.connect() as conn:
        autocommit = await conn.execution_options(isolation_level="AUTOCOMMIT")
        for action in AuditAction:
            # SQLAlchemy persists PEP-435 enum member NAMES (e.g.
            # RECOVERY_CODE_USED), not .value — the labels added here must
            # match. Names are our own identifiers (ASCII), safe to inline.
            await autocommit.execute(
                text(f"ALTER TYPE auditaction ADD VALUE IF NOT EXISTS '{action.name}'")
            )


async def _init_db():
    """Run DB initialization (table creation) — idempotent; no-op if already done."""
    if "db" in _initialized:
        return
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _apply_light_migrations(conn)
    await _sync_pg_audit_enum(engine)
    _initialized.add("db")


# Columns added to `users` after the table's original schema. Each entry is the
# column name plus the type/constraint clause for the ALTER. create_all() only
# creates missing tables, never alters existing ones, so these bridge upgrades
# over an existing database. Keep additive and backward-compatible.
# Columns added to a table after its original schema, keyed by table name. Each
# entry is the column name plus the type/constraint clause for the ALTER.
# create_all() only creates missing tables, never alters existing ones, so these
# bridge upgrades over an existing database. Keep additive and backward-compatible.
_COLUMN_MIGRATIONS = {
    "users": (
        ("session_epoch", "INTEGER NOT NULL DEFAULT 0"),
        ("last_totp_step", "BIGINT"),
    ),
    "hosts": (
        ("username", "VARCHAR(32)"),
    ),
}


async def _apply_light_migrations(conn) -> None:
    """Idempotently add newer columns; safe under concurrent startup.

    Callis has no migration framework. On PostgreSQL we use ADD COLUMN IF NOT
    EXISTS so two API processes starting at once cannot duplicate-column-crash;
    on SQLite (single-writer, single-container by default) the inspect guard is
    sufficient since it has no IF NOT EXISTS for ADD COLUMN.
    """
    from sqlalchemy import inspect as _sa_inspect

    is_postgres = conn.dialect.name == "postgresql"

    for table, migrations in _COLUMN_MIGRATIONS.items():
        def _columns(sync_conn, _table=table):
            return {c["name"] for c in _sa_inspect(sync_conn).get_columns(_table)}

        existing = await conn.run_sync(_columns)
        for column, type_clause in migrations:
            if column in existing:
                continue
            logger.info("Migrating: adding %s.%s column", table, column)
            if is_postgres:
                await conn.exec_driver_sql(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {type_clause}"
                )
            else:
                await conn.exec_driver_sql(
                    f"ALTER TABLE {table} ADD COLUMN {column} {type_clause}"
                )


async def run_servers():
    # Initialize DB and preload settings cache before either server starts
    # so internal_app (which has no lifespan) can serve requests immediately.
    await _init_db()
    await load_db_settings()

    settings = get_settings()
    log_level = settings.LOG_LEVEL.lower()

    api_config = uvicorn.Config(
        app,
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level=log_level,
    )
    internal_config = uvicorn.Config(
        internal_app,
        host="0.0.0.0",
        port=8081,
        log_level=log_level,
    )

    api_server = uvicorn.Server(api_config)
    internal_server = uvicorn.Server(internal_config)

    await asyncio.gather(
        api_server.serve(),
        internal_server.serve(),
    )


if __name__ == "__main__":
    asyncio.run(run_servers())
