from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import get_db, get_settings, get_ssh_host
from dependencies import require_totp_complete
from models import AuditLog, Host, SSHKey, SshSession, User, UserRole
from schemas import DashboardOut, audit_entry_out

router = APIRouter()


@router.get("/dashboard")
async def dashboard(
    user: User = Depends(require_totp_complete),
    db: AsyncSession = Depends(get_db),
) -> DashboardOut:
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

    active_sessions_result = await db.execute(
        select(func.count()).select_from(SshSession).where(SshSession.ended_at.is_(None))
    )
    active_sessions = active_sessions_result.scalar()

    # Recent audit (last 10) — admin-only, matching the audit log's access
    # level. Non-admins get an empty feed (the dashboard hides the section).
    if user.role == UserRole.admin:
        audit_result = await db.execute(
            select(AuditLog)
            .options(selectinload(AuditLog.actor))
            .order_by(AuditLog.timestamp.desc())
            .limit(10)
        )
        recent_audit = audit_result.scalars().all()
    else:
        recent_audit = []

    return DashboardOut(
        active_users=active_users,
        active_hosts=active_hosts,
        active_sessions=active_sessions,
        user_key_count=user_key_count,
        recent_audit=[audit_entry_out(e) for e in recent_audit],
        ssh_host=await get_ssh_host(),
        ssh_port=settings.SSH_PORT,
    )
