from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import get_db, write_audit_log
from dependencies import require_role, require_totp_complete
from models import AuditAction, Host, HostGroup, User
from schemas import CreateGroupIn, GroupOut, group_out

router = APIRouter(prefix="/groups")

_GROUP_NAME_MAX_LEN = 100


def _validate_group_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name must not be empty")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise HTTPException(status_code=400, detail="Group name must not contain control characters")
    if len(name) > _GROUP_NAME_MAX_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Group name must not exceed {_GROUP_NAME_MAX_LEN} characters",
        )
    return name


async def _group_or_404(db: AsyncSession, group_id: str) -> HostGroup:
    result = await db.execute(
        select(HostGroup)
        .options(selectinload(HostGroup.hosts), selectinload(HostGroup.users))
        .where(HostGroup.id == group_id)
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


@router.get("")
async def group_list(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_totp_complete),
) -> list[GroupOut]:
    result = await db.execute(
        select(HostGroup)
        .options(selectinload(HostGroup.hosts), selectinload(HostGroup.users))
        .order_by(HostGroup.name)
    )
    return [group_out(g) for g in result.scalars().all()]


@router.post("", status_code=201)
async def create_group(
    request: Request,
    body: CreateGroupIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> GroupOut:
    name = _validate_group_name(body.name)

    existing = await db.execute(select(HostGroup).where(HostGroup.name == name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="A group with this name already exists")

    group = HostGroup(name=name, description=body.description)
    db.add(group)
    await db.flush()

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.GROUP_CREATED,
        target_type="group",
        target_id=group.id,
        source_ip=request.client.host if request.client else None,
        detail={"name": name},
    )

    return group_out(await _group_or_404(db, group.id))


@router.delete("/{group_id}", status_code=204)
async def delete_group(
    request: Request,
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    group = await _group_or_404(db, group_id)

    name = group.name
    await db.delete(group)

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.GROUP_DELETED,
        target_type="group",
        target_id=group_id,
        source_ip=request.client.host if request.client else None,
        detail={"name": name},
    )
    return Response(status_code=204)


@router.post("/{group_id}/hosts/{host_id}")
async def add_host_to_group(
    request: Request,
    group_id: str,
    host_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> GroupOut:
    group = await _group_or_404(db, group_id)

    host_result = await db.execute(select(Host).where(Host.id == host_id))
    host = host_result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    if host not in group.hosts:
        group.hosts.append(host)
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.GROUP_HOST_ADDED,
            target_type="group",
            target_id=group_id,
            source_ip=request.client.host if request.client else None,
            detail={"group_name": group.name, "host_label": host.label},
        )

    await db.flush()
    return group_out(group)


@router.delete("/{group_id}/hosts/{host_id}")
async def remove_host_from_group(
    request: Request,
    group_id: str,
    host_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> GroupOut:
    group = await _group_or_404(db, group_id)

    host_result = await db.execute(select(Host).where(Host.id == host_id))
    host = host_result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    if host in group.hosts:
        group.hosts.remove(host)
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.GROUP_HOST_REMOVED,
            target_type="group",
            target_id=group_id,
            source_ip=request.client.host if request.client else None,
            detail={"group_name": group.name, "host_label": host.label},
        )

    await db.flush()
    return group_out(group)


@router.post("/{group_id}/users/{target_user_id}")
async def add_user_to_group(
    request: Request,
    group_id: str,
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> GroupOut:
    group = await _group_or_404(db, group_id)

    target_result = await db.execute(select(User).where(User.id == target_user_id))
    target_user = target_result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user not in group.users:
        group.users.append(target_user)
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.GROUP_USER_ADDED,
            target_type="group",
            target_id=group_id,
            source_ip=request.client.host if request.client else None,
            detail={"group_name": group.name, "username": target_user.username},
        )

    await db.flush()
    return group_out(group)


@router.delete("/{group_id}/users/{target_user_id}")
async def remove_user_from_group(
    request: Request,
    group_id: str,
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> GroupOut:
    group = await _group_or_404(db, group_id)

    target_result = await db.execute(select(User).where(User.id == target_user_id))
    target_user = target_result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user in group.users:
        group.users.remove(target_user)
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.GROUP_USER_REMOVED,
            target_type="group",
            target_id=group_id,
            source_ip=request.client.host if request.client else None,
            detail={"group_name": group.name, "username": target_user.username},
        )

    await db.flush()
    return group_out(group)
