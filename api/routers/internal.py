import logging
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import get_session_factory
from models import SSHKey, User

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

        # Update last_used_at
        now = datetime.now(timezone.utc)
        for key in keys:
            key.last_used_at = now
        await db.commit()

        # Return newline-separated public keys
        key_texts = [k.public_key_text for k in keys]
        return PlainTextResponse("\n".join(key_texts) + "\n", status_code=200)


internal_app.include_router(router)


@internal_app.get("/health")
async def internal_health():
    return {"status": "ok"}
