import hashlib
import hmac
import os

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware

from core import get_session_factory, slugify
from models import Host, SSHKey, User, user_host_assignment

internal_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
router = APIRouter()


# ---------------------------------------------------------------------------
# Internal API auth middleware — validates X-Internal-Secret header
# ---------------------------------------------------------------------------


def _get_internal_secret() -> str:
    """Return the internal shared secret, derived from SECRET_KEY via HMAC."""
    cached = os.environ.get("CALLIS_INTERNAL_SECRET", "")
    if cached:
        return cached
    # Fallback: derive from SECRET_KEY (same formula as entrypoint.sh)
    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        return ""
    derived = hmac.new(
        secret_key.encode(), b"callis-internal", hashlib.sha256
    ).hexdigest()
    os.environ["CALLIS_INTERNAL_SECRET"] = derived
    return derived


class InternalSecretMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Health endpoint is unauthenticated
        if request.url.path == "/health":
            return await call_next(request)

        secret = _get_internal_secret()
        if not secret:
            return PlainTextResponse("", status_code=403)

        provided = request.headers.get("X-Internal-Secret", "")
        if not hmac.compare_digest(provided, secret):
            return PlainTextResponse("", status_code=403)

        return await call_next(request)


internal_app.add_middleware(InternalSecretMiddleware)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/internal/keys/{username}")
async def get_keys(username: str):
    factory = get_session_factory()
    async with factory() as db:
        # Find active user by username
        result = await db.execute(
            select(User).where(User.username == username, User.is_active == True)
        )
        user = result.scalar_one_or_none()
        if not user:
            return PlainTextResponse("", status_code=200)

        # Get active keys
        keys_result = await db.execute(
            select(SSHKey).where(SSHKey.user_id == user.id, SSHKey.is_active == True)
        )
        keys = keys_result.scalars().all()

        if not keys:
            return PlainTextResponse("", status_code=200)

        # Get user's assigned hosts for permitopen enforcement
        hosts_result = await db.execute(
            select(Host)
            .join(user_host_assignment)
            .where(
                user_host_assignment.c.user_id == user.id,
                Host.is_active == True,
            )
        )
        assigned_hosts = hosts_result.scalars().all()

        # Build permitopen options from assigned hosts
        if assigned_hosts:
            permits = ",".join(
                f'permitopen="{h.hostname}:{h.port}"' for h in assigned_hosts
            )
            key_texts = [f"{permits} {k.public_key_text}" for k in keys]
        else:
            # No assigned hosts — deny forwarding but still allow auth
            key_texts = [f"no-port-forwarding {k.public_key_text}" for k in keys]

        return PlainTextResponse("\n".join(key_texts) + "\n", status_code=200)


@router.get("/internal/resolve/{username}/{tag}")
async def resolve_host(username: str, tag: str):
    # Reject non-slug tags early (callis-cmd.sh sanitizes, but defend in depth)
    if not tag or slugify(tag) != tag:
        return PlainTextResponse("invalid tag", status_code=400)

    factory = get_session_factory()
    async with factory() as db:
        # Find active user
        result = await db.execute(
            select(User).where(User.username == username, User.is_active == True)
        )
        user = result.scalar_one_or_none()
        if not user:
            return PlainTextResponse("", status_code=200)

        # Get user's assigned active hosts
        hosts_result = await db.execute(
            select(Host)
            .join(user_host_assignment)
            .where(
                user_host_assignment.c.user_id == user.id,
                Host.is_active == True,
            )
        )
        assigned_hosts = hosts_result.scalars().all()

        # Find all hosts whose slugified label matches the tag
        matching_hosts = [
            host for host in assigned_hosts if slugify(host.label) == tag
        ]

        if len(matching_hosts) > 1:
            return PlainTextResponse("ambiguous host tag", status_code=409)

        if len(matching_hosts) == 1:
            host = matching_hosts[0]
            return PlainTextResponse(f"{host.hostname} {host.port}", status_code=200)

        return PlainTextResponse("", status_code=200)


@router.get("/internal/hosts/{username}")
async def list_hosts(username: str):
    factory = get_session_factory()
    async with factory() as db:
        # Find active user
        result = await db.execute(
            select(User).where(User.username == username, User.is_active == True)
        )
        user = result.scalar_one_or_none()
        if not user:
            return PlainTextResponse("", status_code=200)

        # Get user's assigned active hosts
        hosts_result = await db.execute(
            select(Host)
            .join(user_host_assignment)
            .where(
                user_host_assignment.c.user_id == user.id,
                Host.is_active == True,
            )
        )
        assigned_hosts = hosts_result.scalars().all()

        if not assigned_hosts:
            return PlainTextResponse("", status_code=200)

        # Format: tag\thostname\tport\tlabel (one per line)
        lines = []
        for host in assigned_hosts:
            # Sanitize label to prevent tabs/newlines from breaking the format
            safe_label = host.label.replace("\t", " ").replace("\n", " ").replace("\r", "")
            lines.append(
                f"{slugify(host.label)}\t{host.hostname}\t{host.port}\t{safe_label}"
            )

        return PlainTextResponse("\n".join(lines) + "\n", status_code=200)


internal_app.include_router(router)


@internal_app.get("/health")
async def internal_health():
    return {"status": "ok"}
