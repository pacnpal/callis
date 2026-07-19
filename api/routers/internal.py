import hashlib
import hmac
import logging
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware

from core import get_effective_hosts, get_session_factory, get_settings, slugify, write_audit_log
from models import AuditAction, AuditLog, SSHKey, User

logger = logging.getLogger("callis")

internal_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
router = APIRouter()


# ---------------------------------------------------------------------------
# Internal API auth middleware — validates X-Internal-Secret header
# ---------------------------------------------------------------------------

_internal_secret_cache: str | None = None


def _get_internal_secret() -> str:
    """Return the internal shared secret, derived from SECRET_KEY via HMAC.

    The CALLIS_INTERNAL_SECRET env var (set by entrypoint.sh) takes precedence;
    otherwise the secret is derived from the resolved SECRET_KEY — the same
    env-var → persisted-file → auto-generate resolution used everywhere else
    (core.get_settings), and the same HMAC formula as entrypoint.sh.
    """
    global _internal_secret_cache
    if _internal_secret_cache is not None:
        return _internal_secret_cache

    secret = os.environ.get("CALLIS_INTERNAL_SECRET", "")
    if not secret:
        secret_key = get_settings().SECRET_KEY
        if not secret_key:
            return ""
        secret = hmac.new(
            secret_key.encode(), b"callis-internal", hashlib.sha256
        ).hexdigest()
    _internal_secret_cache = secret
    return secret


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


# Suppress duplicate KEY_USED audit rows for the same key within this window.
# sshd invokes AuthorizedKeysCommand twice per connection (key offer + auth),
# milliseconds apart — the window only needs to cover that double call, and is
# kept short so separate rapid reconnections still get their own audit entries.
_KEY_USED_DEDUP_WINDOW = timedelta(seconds=5)


async def _record_key_usage(db, user: User, fingerprint: str) -> None:
    """Mark the matching key as used and audit it (FR-KEY-05 / FR-AUDIT-01).

    sshd passes the offered key's fingerprint (%f) via the `fp` query param.
    Only fingerprints that match one of the user's active keys are recorded.

    Known limitation: AuthorizedKeysCommand runs at key *offer* time, before
    sshd has verified possession of the private key — OpenSSH provides no
    post-auth hook that fires for ProxyJump (direct-tcpip) connections. A
    client holding a user's full public key (not just its fingerprint) could
    therefore create a key_used entry without completing authentication. This
    grants no access; sshd's VERBOSE log remains the authoritative record of
    accepted vs. failed authentications.
    """
    result = await db.execute(
        select(SSHKey).where(
            SSHKey.user_id == user.id,
            SSHKey.fingerprint == fingerprint,
            SSHKey.is_active == True,
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        return

    now = datetime.now(timezone.utc)
    key.last_used_at = now

    recent = await db.execute(
        select(AuditLog.timestamp)
        .where(AuditLog.action == AuditAction.KEY_USED, AuditLog.target_id == key.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(1)
    )
    last_logged = recent.scalar_one_or_none()
    if last_logged is not None:
        if last_logged.tzinfo is None:
            last_logged = last_logged.replace(tzinfo=timezone.utc)
        if now - last_logged < _KEY_USED_DEDUP_WINDOW:
            await db.commit()
            return

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.KEY_USED,
        target_type="key",
        target_id=key.id,
        detail={"fingerprint": fingerprint, "username": user.username, "label": key.label},
    )
    await db.commit()


@router.get("/internal/keys/{username}")
async def get_keys(username: str, fp: str = Query("")):
    factory = get_session_factory()
    async with factory() as db:
        # Find active user by username
        result = await db.execute(
            select(User).where(User.username == username, User.is_active == True)
        )
        user = result.scalar_one_or_none()
        if not user:
            return PlainTextResponse("", status_code=200)

        # Record key usage when sshd reports the offered key's fingerprint.
        # Never let bookkeeping break authentication.
        if fp:
            try:
                await _record_key_usage(db, user, fp.strip())
            except Exception:
                logger.exception("Failed to record SSH key usage for %r", username)
                await db.rollback()

        # Get active keys
        keys_result = await db.execute(
            select(SSHKey).where(SSHKey.user_id == user.id, SSHKey.is_active == True)
        )
        keys = keys_result.scalars().all()

        if not keys:
            return PlainTextResponse("", status_code=200)

        # Effective hosts (direct + group assignments) for permitopen enforcement
        assigned_hosts = await get_effective_hosts(db, user.id)

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

        # Effective hosts (direct + group assignments)
        assigned_hosts = await get_effective_hosts(db, user.id)

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

        # Effective hosts (direct + group assignments)
        assigned_hosts = await get_effective_hosts(db, user.id)

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
