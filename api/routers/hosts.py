import re
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import get_db, get_settings, register_template_filters, slugify, write_audit_log
from dependencies import require_role, require_totp_complete
from models import AuditAction, Host, User, UserRole

# Hostnames/IPv4 only; IPv6 literals (with colons) not yet supported
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

router = APIRouter()
templates = Jinja2Templates(directory="templates")
register_template_filters(templates)


@router.get("/hosts")
async def host_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_totp_complete),
):
    result = await db.execute(
        select(Host).options(selectinload(Host.assigned_users)).order_by(Host.created_at.desc())
    )
    hosts = result.scalars().all()
    settings = get_settings()
    ssh_host = urlparse(settings.BASE_URL).hostname or "localhost"

    # Load all active users for assignment dropdowns (admin only)
    all_users = []
    if user.role == UserRole.admin:
        users_result = await db.execute(
            select(User).where(User.is_active == True).order_by(User.username)
        )
        all_users = users_result.scalars().all()

    return templates.TemplateResponse(
        "hosts.html",
        {"request": request, "hosts": hosts, "user": user, "settings": settings, "ssh_host": ssh_host, "all_users": all_users},
    )


@router.post("/hosts")
async def create_host(
    request: Request,
    label: str = Form(...),
    hostname: str = Form(...),
    port: int = Form(22),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    async def _form_error(detail: str):
        settings = get_settings()
        ssh_host = urlparse(settings.BASE_URL).hostname or "localhost"
        result = await db.execute(
            select(Host).options(selectinload(Host.assigned_users)).order_by(Host.created_at.desc())
        )
        all_hosts = result.scalars().all()
        au = []
        if user.role == UserRole.admin:
            ur = await db.execute(select(User).where(User.is_active == True).order_by(User.username))
            au = ur.scalars().all()
        return templates.TemplateResponse(
            "hosts.html",
            {"request": request, "error": detail, "hosts": all_hosts, "user": user, "settings": settings, "ssh_host": ssh_host, "all_users": au},
            status_code=400,
        )

    # Validate hostname (no quotes, commas, spaces — these would break permitopen options)
    hostname = hostname.strip()
    if not _HOSTNAME_RE.match(hostname) or len(hostname) > 255:
        return await _form_error("Invalid hostname. Use alphanumeric characters, dots, hyphens, and underscores only.")
    if not 1 <= port <= 65535:
        return await _form_error("Port must be between 1 and 65535")

    # Validate that no active host's label already slugifies to the same CLI tag
    new_slug = slugify(label)
    existing_result = await db.execute(select(Host).where(Host.is_active == True))
    existing_hosts = existing_result.scalars().all()
    if any(slugify(h.label) == new_slug for h in existing_hosts):
        return await _form_error(
            f"Another active host already uses the CLI tag '{new_slug}'. "
            "Choose a label that produces a unique tag."
        )

    new_host = Host(
        label=label,
        hostname=hostname,
        port=port,
        description=description,
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
        detail={"label": label, "hostname": hostname, "port": port},
    )

    if request.headers.get("HX-Request"):
        return RedirectResponse(url="/hosts", status_code=303)
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{host_id}/deactivate")
async def deactivate_host(
    request: Request,
    host_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

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

    if request.headers.get("HX-Request"):
        result = await db.execute(
            select(Host).options(selectinload(Host.assigned_users)).where(Host.id == host_id)
        )
        host = result.scalar_one()
        settings = get_settings()
        ssh_host = urlparse(settings.BASE_URL).hostname or "localhost"
        return templates.TemplateResponse(
            "partials/host_row.html",
            {"request": request, "host": host, "user": user, "settings": settings, "ssh_host": ssh_host},
        )
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{host_id}/delete")
@router.delete("/hosts/{host_id}")
async def delete_host(
    request: Request,
    host_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

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

    if request.headers.get("HX-Request"):
        return HTMLResponse("")
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{host_id}/assign/{target_user_id}")
async def assign_host(
    request: Request,
    host_id: str,
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(Host).options(selectinload(Host.assigned_users)).where(Host.id == host_id)
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

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

    if request.headers.get("HX-Request"):
        await db.flush()
        result = await db.execute(
            select(Host).options(selectinload(Host.assigned_users)).where(Host.id == host_id)
        )
        host = result.scalar_one()
        settings = get_settings()
        ssh_host = urlparse(settings.BASE_URL).hostname or "localhost"
        users_result = await db.execute(select(User).where(User.is_active == True).order_by(User.username))
        all_users = users_result.scalars().all()
        return templates.TemplateResponse(
            "partials/host_row.html",
            {"request": request, "host": host, "user": user, "settings": settings, "ssh_host": ssh_host, "all_users": all_users},
        )
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{host_id}/unassign/{target_user_id}")
async def unassign_host(
    request: Request,
    host_id: str,
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(Host).options(selectinload(Host.assigned_users)).where(Host.id == host_id)
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

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

    if request.headers.get("HX-Request"):
        await db.flush()
        result = await db.execute(
            select(Host).options(selectinload(Host.assigned_users)).where(Host.id == host_id)
        )
        host = result.scalar_one()
        settings = get_settings()
        ssh_host = urlparse(settings.BASE_URL).hostname or "localhost"
        users_result = await db.execute(select(User).where(User.is_active == True).order_by(User.username))
        all_users = users_result.scalars().all()
        return templates.TemplateResponse(
            "partials/host_row.html",
            {"request": request, "host": host, "user": user, "settings": settings, "ssh_host": ssh_host, "all_users": all_users},
        )
    return RedirectResponse(url="/hosts", status_code=303)
