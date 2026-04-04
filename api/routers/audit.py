from datetime import datetime, time, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import get_db, register_template_filters
from dependencies import require_role
from models import AuditAction, AuditLog, User

router = APIRouter()
templates = Jinja2Templates(directory="templates")
register_template_filters(templates)

PAGE_SIZE = 50


@router.get("/audit")
async def audit_log(
    request: Request,
    page: int = Query(1, ge=1),
    action: str = Query(None),
    actor: str = Query(None),
    date_from: str = Query(None),
    date_to: str = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("readonly")),
):
    query = select(AuditLog).options(selectinload(AuditLog.actor))

    # Apply filters
    if action:
        try:
            action_enum = AuditAction(action)
            query = query.where(AuditLog.action == action_enum)
        except ValueError:
            pass

    if actor:
        query = query.where(AuditLog.actor_id == actor)

    if date_from:
        try:
            dt = datetime.fromisoformat(date_from)
            dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
            query = query.where(AuditLog.timestamp >= dt)
        except ValueError:
            pass

    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
            dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
            # Include the entire day
            dt = datetime.combine(dt.date(), time.max, tzinfo=timezone.utc)
            query = query.where(AuditLog.timestamp <= dt)
        except ValueError:
            pass

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

    context = {
        "request": request,
        "entries": entries,
        "user": user,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "actions": [a.value for a in AuditAction],
        "all_users": all_users,
        "filter_action": action or "",
        "filter_actor": actor or "",
        "filter_date_from": date_from or "",
        "filter_date_to": date_to or "",
    }

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/audit_rows.html", context)

    return templates.TemplateResponse("audit.html", context)
