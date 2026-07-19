"""Public instance metadata for the SSR frontend.

Everything here was previously rendered into unauthenticated pages (login
banner, instance name, footer version) or derived at request time
(setup-needed redirect), so none of it expands the unauthenticated surface.
"""

from fastapi import APIRouter
from sqlalchemy import func, select

from core import get_app_version, get_runtime_setting, get_session_factory, get_settings, get_ssh_host
from models import User
from schemas import MetaOut

router = APIRouter()


@router.get("/meta")
async def meta() -> MetaOut:
    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(select(func.count()).select_from(User))
        setup_needed = result.scalar() == 0

    settings = get_settings()
    return MetaOut(
        instance_name=await get_runtime_setting("instance_name") or "Callis",
        version=get_app_version(),
        motd=await get_runtime_setting("motd") or "",
        ssh_host=await get_ssh_host(),
        ssh_port=settings.SSH_PORT,
        base_url=await get_runtime_setting("base_url") or "http://localhost:8080",
        setup_needed=setup_needed,
    )
