import re

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import (
    get_db,
    get_effective_hosts,
    get_server_deploy_public_key,
    slugify,
    write_audit_log,
)
from dependencies import require_role, require_totp_complete
from models import AuditAction, Host, User, UserRole
from schemas import CreateHostIn, DeployKeyOut, HostOut, host_out

# Hostnames/IPv4 only; IPv6 literals (with colons) not yet supported
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

router = APIRouter(prefix="/hosts")


async def _host_with_assignments(db: AsyncSession, host_id: str) -> Host | None:
    result = await db.execute(
        select(Host).options(selectinload(Host.assigned_users)).where(Host.id == host_id)
    )
    return result.scalar_one_or_none()


async def _host_or_404(db: AsyncSession, host_id: str) -> Host:
    host = await _host_with_assignments(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.get("")
async def host_list(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_totp_complete),
) -> list[HostOut]:
    # Admins manage the whole fleet and need the full inventory plus the
    # user->host assignment map. Non-admins are shown only the hosts they can
    # actually reach, with other users' assignments stripped — the internal SSH
    # endpoint already filters this way; the web view must not leak the entire
    # network topology and access map to a low-privilege account.
    if user.role == UserRole.admin:
        result = await db.execute(
            select(Host)
            .options(selectinload(Host.assigned_users))
            .order_by(Host.created_at.desc())
        )
        return [host_out(h) for h in result.scalars().all()]

    # Effective access = direct assignments ∪ host-group memberships (the same
    # source of truth the SSH internal API uses), so a user assigned only via a
    # group still sees their hosts. Build HostOut without the assignment map — a
    # non-admin must not learn who else can reach a host, only that they can.
    effective_hosts = await get_effective_hosts(db, user.id)
    return [
        HostOut(
            id=h.id,
            label=h.label,
            alias=slugify(h.label),
            hostname=h.hostname,
            port=h.port,
            description=h.description,
            is_active=h.is_active,
            created_at=h.created_at,
            assigned_users=[],
        )
        for h in effective_hosts
    ]


@router.get("/deploy-key")
async def deploy_key(
    user: User = Depends(require_role("admin")),
) -> DeployKeyOut:
    key = await anyio.to_thread.run_sync(get_server_deploy_public_key)
    return DeployKeyOut(public_key=key)


@router.post("", status_code=201)
async def create_host(
    request: Request,
    body: CreateHostIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> HostOut:
    # Validate label: strip whitespace, reject empty or control characters
    label = body.label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="Label must not be empty")
    if any(c in label for c in "\t\n\r"):
        raise HTTPException(status_code=400, detail="Label must not contain tab or newline characters")

    # Validate hostname (no quotes, commas, spaces — these would break permitopen options)
    hostname = body.hostname.strip()
    if not _HOSTNAME_RE.match(hostname) or len(hostname) > 255:
        raise HTTPException(
            status_code=400,
            detail="Invalid hostname. Use alphanumeric characters, dots, hyphens, and underscores only.",
        )
    if not 1 <= body.port <= 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")

    # Validate that no active host's label already slugifies to the same CLI tag
    new_slug = slugify(label)
    existing_result = await db.execute(select(Host).where(Host.is_active == True))
    existing_hosts = existing_result.scalars().all()
    if any(slugify(h.label) == new_slug for h in existing_hosts):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Another active host already uses the CLI tag '{new_slug}'. "
                "Choose a label that produces a unique tag."
            ),
        )

    new_host = Host(
        label=label,
        hostname=hostname,
        port=body.port,
        description=body.description,
    )
    db.add(new_host)
    await db.flush()

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.HOST_CREATED,
        target_type="host",
        target_id=new_host.id,
        source_ip=request.client.host if request.client else None,
        detail={"label": label, "hostname": hostname, "port": body.port},
    )

    # Reload with assignment relationship for a consistent response shape
    return host_out(await _host_or_404(db, new_host.id))


@router.post("/{host_id}/deactivate")
async def deactivate_host(
    request: Request,
    host_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> HostOut:
    host = await _host_or_404(db, host_id)

    host.is_active = False
    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.HOST_DEACTIVATED,
        target_type="host",
        target_id=host_id,
        source_ip=request.client.host if request.client else None,
        detail={"label": host.label},
    )
    return host_out(host)


@router.delete("/{host_id}", status_code=204)
async def delete_host(
    request: Request,
    host_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    host = await _host_or_404(db, host_id)

    label = host.label
    await db.delete(host)

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.HOST_DELETED,
        target_type="host",
        target_id=host_id,
        source_ip=request.client.host if request.client else None,
        detail={"label": label},
    )
    return Response(status_code=204)


@router.post("/{host_id}/assign/{target_user_id}")
async def assign_host(
    request: Request,
    host_id: str,
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> HostOut:
    host = await _host_or_404(db, host_id)

    target_result = await db.execute(select(User).where(User.id == target_user_id))
    target_user = target_result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user not in host.assigned_users:
        host.assigned_users.append(target_user)
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.HOST_ASSIGNED,
            target_type="host",
            target_id=host_id,
            source_ip=request.client.host if request.client else None,
            detail={"host_label": host.label, "username": target_user.username},
        )

    await db.flush()
    return host_out(host)


@router.post("/{host_id}/unassign/{target_user_id}")
async def unassign_host(
    request: Request,
    host_id: str,
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> HostOut:
    host = await _host_or_404(db, host_id)

    target_result = await db.execute(select(User).where(User.id == target_user_id))
    target_user = target_result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user in host.assigned_users:
        host.assigned_users.remove(target_user)
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.HOST_UNASSIGNED,
            target_type="host",
            target_id=host_id,
            source_ip=request.client.host if request.client else None,
            detail={"host_label": host.label, "username": target_user.username},
        )

    await db.flush()
    return host_out(host)
