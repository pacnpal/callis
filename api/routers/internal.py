import logging

from fastapi import APIRouter, FastAPI
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import get_session_factory
from models import Host, SSHKey, User, user_host_assignment

logger = logging.getLogger("callis")

internal_app = FastAPI(docs_url=None, redoc_url=None)
router = APIRouter()


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
            key_texts = [f'permitopen="none:0" {k.public_key_text}' for k in keys]

        return PlainTextResponse("\n".join(key_texts) + "\n", status_code=200)


internal_app.include_router(router)


@internal_app.get("/health")
async def internal_health():
    return {"status": "ok"}
