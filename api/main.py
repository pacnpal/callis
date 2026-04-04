import asyncio
import logging
import re
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from core import RESERVED_USERNAMES, USERNAME_RE, get_db, get_engine, get_session_factory, get_settings, hash_password, limiter, register_template_filters
from dependencies import require_totp_complete
from middleware import SecurityHeadersMiddleware, SessionMiddleware, TOTPGuardMiddleware
from models import AuditLog, Base, Host, SSHKey, User, UserRole
from routers import auth, users, hosts, audit
from routers.internal import internal_app

logger = logging.getLogger("callis")

templates = Jinja2Templates(directory="templates")


register_template_filters(templates)

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # DB init runs in _init_db() before servers start; lifespan only handles shutdown
    yield
    engine = get_engine()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Public app (port 8080)
# ---------------------------------------------------------------------------

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Middleware (applied in reverse order — last added runs first)
app.add_middleware(TOTPGuardMiddleware)
app.add_middleware(SessionMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(hosts.router)
app.include_router(audit.router)


# Dashboard
@app.get("/dashboard")
async def dashboard(
    request: Request,
    user: User = Depends(require_totp_complete),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy.orm import selectinload

    settings = get_settings()

    # Stats
    active_users_result = await db.execute(
        select(func.count()).select_from(User).where(User.is_active == True)
    )
    active_users = active_users_result.scalar()

    active_hosts_result = await db.execute(
        select(func.count()).select_from(Host).where(Host.is_active == True)
    )
    active_hosts = active_hosts_result.scalar()

    key_count_result = await db.execute(
        select(func.count()).select_from(SSHKey).where(
            SSHKey.user_id == user.id, SSHKey.is_active == True
        )
    )
    user_key_count = key_count_result.scalar()

    # Recent audit (last 10)
    audit_result = await db.execute(
        select(AuditLog)
        .options(selectinload(AuditLog.actor))
        .order_by(AuditLog.timestamp.desc())
        .limit(10)
    )
    recent_audit = audit_result.scalars().all()

    # SSH host for config snippet
    ssh_host = urlparse(settings.BASE_URL).hostname or "localhost"

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "active_users": active_users,
            "active_hosts": active_hosts,
            "user_key_count": user_key_count,
            "recent_audit": recent_audit,
            "ssh_host": ssh_host,
            "ssh_port": settings.SSH_PORT,
        },
    )


# Root redirect
@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/dashboard", status_code=303)


# Global exception handler
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Redirect exceptions (303) pass through as-is
    if exc.status_code == 303:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=exc.headers.get("Location", "/login"), status_code=303)
    # For browser requests, render an HTML error page
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return templates.TemplateResponse(
            "500.html",
            {"request": request, "error": exc.detail},
            status_code=exc.status_code,
        )
    # API/JSON clients get the default JSON response
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return templates.TemplateResponse("500.html", {"request": request}, status_code=500)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return templates.TemplateResponse("500.html", {"request": request}, status_code=500)


# ---------------------------------------------------------------------------
# Entrypoint: run both apps
# ---------------------------------------------------------------------------

async def _init_db():
    """Run DB initialization (table creation + admin seed) before servers start."""
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    admin_username = settings.ADMIN_USERNAME.lower().strip()
    if not USERNAME_RE.match(admin_username):
        raise ValueError(f"ADMIN_USERNAME '{settings.ADMIN_USERNAME}' is invalid.")
    if admin_username in RESERVED_USERNAMES:
        raise ValueError(
            f"ADMIN_USERNAME '{admin_username}' is a reserved system name."
        )

    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(select(func.count()).select_from(User))
        count = result.scalar()
        if count == 0:
            admin = User(
                username=admin_username,
                display_name="Administrator",
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                role=UserRole.admin,
                is_active=True,
            )
            db.add(admin)
            await db.commit()
            logger.info(f"Created initial admin user: {admin_username}")


async def run_servers():
    # Initialize DB before either server starts accepting connections
    await _init_db()

    settings = get_settings()
    log_level = settings.LOG_LEVEL.lower()

    public_config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8080,
        log_level=log_level,
    )
    internal_config = uvicorn.Config(
        internal_app,
        host="0.0.0.0",
        port=8081,
        log_level=log_level,
    )

    public_server = uvicorn.Server(public_config)
    internal_server = uvicorn.Server(internal_config)

    await asyncio.gather(
        public_server.serve(),
        internal_server.serve(),
    )


if __name__ == "__main__":
    asyncio.run(run_servers())
