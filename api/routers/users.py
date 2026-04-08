import html
import logging
from urllib.parse import urlparse
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import RESERVED_USERNAMES, USERNAME_RE, generate_ssh_keypair, get_db, get_runtime_setting, get_settings, hash_password, parse_ssh_public_key, register_template_filters, write_audit_log
from dependencies import require_admin_or_self, require_role
from models import AuditAction, SSHKey, User, UserRole

router = APIRouter()
logger = logging.getLogger("callis")
templates = Jinja2Templates(directory="templates")
register_template_filters(templates)


@router.get("/users")
async def user_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(User).order_by(User.created_at.desc())
    )
    users = result.scalars().all()

    # Get key counts with a single aggregate query to avoid N+1
    user_ids = [u.id for u in users]
    key_counts = {uid: 0 for uid in user_ids}
    if user_ids:
        count_result = await db.execute(
            select(SSHKey.user_id, func.count())
            .where(SSHKey.user_id.in_(user_ids), SSHKey.is_active == True)
            .group_by(SSHKey.user_id)
        )
        for user_id, count in count_result.all():
            key_counts[user_id] = count

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request,
            "users.html",
            context={"users": users, "key_counts": key_counts, "user": user},
        )

    return templates.TemplateResponse(
        request,
        "users.html",
        context={"users": users, "key_counts": key_counts, "user": user},
    )


@router.get("/users/{user_id}")
async def user_detail(
    request: Request,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
):
    result = await db.execute(
        select(User)
        .options(selectinload(User.ssh_keys), selectinload(User.assigned_hosts))
        .where(User.id == user_id)
    )
    target_user = result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    active_keys = [k for k in target_user.ssh_keys if k.is_active]
    assigned_hosts = [h for h in target_user.assigned_hosts if h.is_active]

    settings = get_settings()
    ssh_host = urlparse(await get_runtime_setting("base_url")).hostname or "localhost"

    return templates.TemplateResponse(
        request,
        "user_detail.html",
        context={
            "target_user": target_user,
            "keys": active_keys,
            "assigned_hosts": assigned_hosts,
            "ssh_host": ssh_host,
            "ssh_port": settings.SSH_PORT,
            "user": user,
        },
    )


@router.post("/users")
async def create_user(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    password: str = Form(...),
    role: str = Form("readonly"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    async def _form_error(detail: str):
        result = await db.execute(select(User).order_by(User.created_at.desc()))
        all_users = result.scalars().all()
        user_ids = [u.id for u in all_users]
        kc = {uid: 0 for uid in user_ids}
        if user_ids:
            cr = await db.execute(
                select(SSHKey.user_id, func.count())
                .where(SSHKey.user_id.in_(user_ids), SSHKey.is_active == True)
                .group_by(SSHKey.user_id)
            )
            for uid, count in cr.all():
                kc[uid] = count
        return templates.TemplateResponse(
            request,
            "users.html",
            context={"error": detail, "users": all_users, "key_counts": kc, "user": user},
            status_code=400,
        )

    # Server-side username validation
    username = username.lower().strip()
    if not USERNAME_RE.match(username):
        return await _form_error("Username must be 1-32 lowercase alphanumeric characters, hyphens, or underscores, starting with a letter.")
    if username in RESERVED_USERNAMES:
        return await _form_error(f"Username '{username}' is reserved")

    # Server-side password validation
    pwd_min = await get_runtime_setting("password_min_length")
    if len(password) < pwd_min:
        return await _form_error(f"Password must be at least {pwd_min} characters")

    # Validate role
    try:
        user_role = UserRole(role)
    except ValueError:
        return await _form_error(f"Invalid role '{role}'. Must be one of: admin, operator, readonly")

    # Check duplicate username
    existing = await db.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        return await _form_error("Username already exists")

    new_user = User(
        username=username,
        display_name=display_name or username,
        email=email or None,
        hashed_password=hash_password(password),
        role=user_role,
    )
    db.add(new_user)
    await db.flush()

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.USER_CREATED,
        target_type="user",
        target_id=new_user.id,
        source_ip=request.client.host if request.client else None,
        detail={"username": username, "role": role},
    )

    if request.headers.get("HX-Request"):
        return RedirectResponse(url="/users", status_code=303)
    return RedirectResponse(url="/users", status_code=303)


@router.post("/users/{user_id}/deactivate")
async def deactivate_user(
    request: Request,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.is_active = False
    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.USER_DEACTIVATED,
        target_type="user",
        target_id=user_id,
        source_ip=request.client.host if request.client else None,
        detail={"username": target.username},
    )

    if request.headers.get("HX-Request"):
        key_count_result = await db.execute(
            select(func.count()).where(SSHKey.user_id == target.id, SSHKey.is_active == True)
        )
        key_count = key_count_result.scalar()
        return templates.TemplateResponse(
            request,
            "partials/user_row.html",
            context={"row_user": target, "key_count": key_count, "user": user},
        )
    return RedirectResponse(url="/users", status_code=303)


@router.post("/users/{user_id}/activate")
async def activate_user(
    request: Request,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.is_active = True
    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.USER_ACTIVATED,
        target_type="user",
        target_id=user_id,
        source_ip=request.client.host if request.client else None,
        detail={"username": target.username},
    )

    if request.headers.get("HX-Request"):
        key_count_result = await db.execute(
            select(func.count()).where(SSHKey.user_id == target.id, SSHKey.is_active == True)
        )
        key_count = key_count_result.scalar()
        return templates.TemplateResponse(
            request,
            "partials/user_row.html",
            context={"row_user": target, "key_count": key_count, "user": user},
        )
    return RedirectResponse(url="/users", status_code=303)


@router.post("/users/{user_id}/delete")
@router.delete("/users/{user_id}")
async def delete_user(
    request: Request,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    if user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    username = target.username
    await db.delete(target)

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.USER_DELETED,
        target_type="user",
        target_id=user_id,
        source_ip=request.client.host if request.client else None,
        detail={"username": username},
    )

    if request.headers.get("HX-Request"):
        return HTMLResponse("")
    return RedirectResponse(url="/users", status_code=303)


_LABEL_MAX_LEN = 100


def _validate_label(label: str) -> str:
    """Strip and validate a key label.

    Returns the stripped label, or raises HTTP 400 if the label contains
    control characters or exceeds the maximum allowed length.
    """
    label = label.strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in label):
        raise HTTPException(status_code=400, detail="Label must not contain control characters")
    if len(label) > _LABEL_MAX_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Label must not exceed {_LABEL_MAX_LEN} characters",
        )
    return label


async def _check_key_limit(user_id: str, db: AsyncSession) -> None:
    """Raise HTTP 400 if the user has reached the configured per-user key limit."""
    max_keys = await get_runtime_setting("max_keys_per_user")
    count_result = await db.execute(
        select(func.count()).where(SSHKey.user_id == user_id, SSHKey.is_active == True)
    )
    current_count = count_result.scalar()
    if current_count >= max_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {max_keys} keys per user",
        )


@router.post("/users/{user_id}/keys")
async def upload_key(
    request: Request,
    user_id: str,
    label: str = Form(...),
    public_key: str = Form(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
):
    # Verify target user exists and is active
    target_result = await db.execute(select(User).where(User.id == user_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if not target.is_active:
        raise HTTPException(status_code=400, detail="Cannot upload keys for inactive user")

    # Check key limit
    await _check_key_limit(user_id, db)

    # Validate label
    try:
        label = _validate_label(label)
        if not label:
            raise HTTPException(status_code=400, detail="Label cannot be blank")
    except HTTPException as exc:
        if request.headers.get("HX-Request"):
            return HTMLResponse(
                f'<span class="text-error">{html.escape(exc.detail)}</span>',
                status_code=200,
                headers={"HX-Retarget": "#upload-error-msg", "HX-Reswap": "innerHTML"},
            )
        raise

    # Validate and parse the key
    try:
        key_info = parse_ssh_public_key(public_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Check for duplicate fingerprint
    dup_result = await db.execute(
        select(SSHKey).where(
            SSHKey.user_id == user_id,
            SSHKey.fingerprint == key_info["fingerprint"],
            SSHKey.is_active == True,
        )
    )
    if dup_result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="This key is already registered")

    new_key = SSHKey(
        user_id=user_id,
        label=label,
        public_key_text=key_info["public_key_text"],
        fingerprint=key_info["fingerprint"],
        key_type=key_info["key_type"],
    )
    db.add(new_key)
    await db.flush()

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.KEY_ADDED,
        target_type="key",
        target_id=new_key.id,
        source_ip=request.client.host if request.client else None,
        detail={"fingerprint": key_info["fingerprint"], "key_type": key_info["key_type"], "label": label},
    )

    if request.headers.get("HX-Request"):
        # Return updated key list partial
        result = await db.execute(
            select(SSHKey).where(SSHKey.user_id == user_id, SSHKey.is_active == True)
        )
        keys = result.scalars().all()
        return templates.TemplateResponse(
            request,
            "partials/key_list.html",
            context={"keys": keys, "target_user_id": user_id, "user": user},
        )
    return RedirectResponse(url=request.url_for("user_detail", user_id=user_id), status_code=303)


@router.post("/users/{user_id}/keys/{key_id}/revoke")
async def revoke_key(
    request: Request,
    user_id: str,
    key_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
):
    result = await db.execute(
        select(SSHKey).where(SSHKey.id == key_id, SSHKey.user_id == user_id)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    key.is_active = False
    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.KEY_REVOKED,
        target_type="key",
        target_id=key_id,
        source_ip=request.client.host if request.client else None,
        detail={"fingerprint": key.fingerprint, "label": key.label},
    )

    if request.headers.get("HX-Request"):
        keys_result = await db.execute(
            select(SSHKey).where(SSHKey.user_id == user_id, SSHKey.is_active == True)
        )
        keys = keys_result.scalars().all()
        return templates.TemplateResponse(
            request,
            "partials/key_list.html",
            context={"keys": keys, "target_user_id": user_id, "user": user},
        )
    return RedirectResponse(url=request.url_for("user_detail", user_id=user_id), status_code=303)


@router.post("/users/{user_id}/keys/generate")
async def generate_key(
    request: Request,
    user_id: str,
    label: str = Form(""),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
):
    # Verify target user exists and is active
    target_result = await db.execute(select(User).where(User.id == user_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if not target.is_active:
        raise HTTPException(status_code=400, detail="Cannot generate keys for inactive user")

    # Check key limit
    await _check_key_limit(user_id, db)

    # Default label when blank
    try:
        label = _validate_label(label)
    except HTTPException as exc:
        if request.headers.get("HX-Request"):
            return HTMLResponse(
                f'<p class="text-error" role="alert">{html.escape(exc.detail)}</p>',
                status_code=200,
                headers={
                    "HX-Retarget": "#generate-key-error",
                    "HX-Reswap": "innerHTML",
                },
            )
        raise
    if not label:
        label = f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"

    # Generate Ed25519 keypair; use username as the key comment
    private_key_text, public_key_text = generate_ssh_keypair(comment=target.username)

    try:
        key_info = parse_ssh_public_key(public_key_text)
    except ValueError as e:
        safe_user_id = (user_id or "").replace("\r", "").replace("\n", "")
        logger.exception("Key generation internal error for user %s: %s", safe_user_id, e)
        raise HTTPException(status_code=500, detail="Key generation failed")

    new_key = SSHKey(
        user_id=user_id,
        label=label,
        public_key_text=key_info["public_key_text"],
        fingerprint=key_info["fingerprint"],
        key_type=key_info["key_type"],
    )
    db.add(new_key)
    await db.flush()

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.KEY_ADDED,
        target_type="key",
        target_id=new_key.id,
        source_ip=request.client.host if request.client else None,
        detail={
            "fingerprint": key_info["fingerprint"],
            "key_type": key_info["key_type"],
            "label": label,
            "generated": True,
        },
    )

    # Fetch updated key list for the out-of-band swap
    keys_result = await db.execute(
        select(SSHKey).where(SSHKey.user_id == user_id, SSHKey.is_active == True)
    )
    keys = keys_result.scalars().all()

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request,
            "partials/generated_key.html",
            context={
                "private_key": private_key_text,
                "label": label,
                "fingerprint": key_info["fingerprint"],
                "keys": keys,
                "target_user_id": user_id,
                "user": user,
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    return templates.TemplateResponse(
        request,
        "generated_key_page.html",
        context={
            "private_key": private_key_text,
            "label": label,
            "fingerprint": key_info["fingerprint"],
            "target_user_id": user_id,
            "user": user,
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
