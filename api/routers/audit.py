from datetime import datetime, time, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import get_db
from dependencies import require_role
from models import AuditAction, AuditLog, User
from schemas import AuditPageOut, UserRef, audit_entry_out

router = APIRouter(prefix="/audit")

PAGE_SIZE = 50


@router.get("")
async def audit_log(
    page: int = Query(1, ge=1),
    action: str = Query(None),
    actor: str = Query(None),
    date_from: str = Query(None),
    date_to: str = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("readonly")),
) -> AuditPageOut:
    query = select(AuditLog).options(selectinload(AuditLog.actor))

    # Apply filters
    if action:
        try:
            action_enum = AuditAction(action)
            query = query.where(AuditLog.action == action_enum)
        except ValueError:
            pass  # Ignore invalid action filter values

    if actor:
        query = query.where(AuditLog.actor_id == actor)

    if date_from:
        try:
            dt = datetime.fromisoformat(date_from)
            dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
            query = query.where(AuditLog.timestamp >= dt)
        except ValueError:
            pass  # Ignore invalid date_from filter values

    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
            dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
            # Include the entire day
            dt = datetime.combine(dt.date(), time.max, tzinfo=timezone.utc)
            query = query.where(AuditLog.timestamp <= dt)
        except ValueError:
            pass  # Ignore invalid date_to filter values

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    # Paginate
    query = query.order_by(AuditLog.timestamp.desc())
    query = query.offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)
    result = await db.execute(query)
    entries = result.scalars().all()

    # Get all users for filter dropdown
    users_result = await db.execute(select(User).order_by(User.username))
    all_users = users_result.scalars().all()

    return AuditPageOut(
        entries=[audit_entry_out(e) for e in entries],
        page=page,
        total_pages=total_pages,
        total=total,
        actions=[a.value for a in AuditAction],
        users=[UserRef(id=u.id, username=u.username) for u in all_users],
    )
