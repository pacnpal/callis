import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import (
    RESERVED_USERNAMES,
    USERNAME_RE,
    generate_ssh_keypair,
    get_db,
    get_runtime_setting,
    get_settings,
    get_ssh_host,
    hash_password,
    parse_ssh_public_key,
    write_audit_log,
)
from dependencies import require_admin_or_self, require_role
from models import AuditAction, Host, SSHKey, User, UserRole
from schemas import (
    ChangeRoleIn,
    CreateUserIn,
    GeneratedKeyOut,
    GenerateKeyIn,
    SSHKeyOut,
    UploadKeyIn,
    UserDetailOut,
    UserListItem,
    UserOut,
    host_out,
    ssh_key_out,
    user_out,
)

router = APIRouter(prefix="/users")
logger = logging.getLogger("callis")


async def _key_counts(db: AsyncSession, user_ids: list[str]) -> dict[str, int]:
    """Active-key counts per user, in a single aggregate query (avoids N+1)."""
    counts = {uid: 0 for uid in user_ids}
    if user_ids:
        result = await db.execute(
            select(SSHKey.user_id, func.count())
            .where(SSHKey.user_id.in_(user_ids), SSHKey.is_active == True)
            .group_by(SSHKey.user_id)
        )
        for user_id, count in result.all():
            counts[user_id] = count
    return counts


async def _active_key_count(db: AsyncSession, user_id: str) -> int:
    result = await db.execute(
        select(func.count()).where(SSHKey.user_id == user_id, SSHKey.is_active == True)
    )
    return result.scalar()


async def _get_user_or_404(db: AsyncSession, user_id: str) -> User:
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    return target


@router.get("")
async def user_list(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> list[UserListItem]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    key_counts = await _key_counts(db, [u.id for u in users])
    return [
        UserListItem(**user_out(u).model_dump(), key_count=key_counts.get(u.id, 0))
        for u in users
    ]


@router.get("/{user_id}")
async def user_detail(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
) -> UserDetailOut:
    result = await db.execute(
        select(User)
        .options(
            selectinload(User.ssh_keys),
            selectinload(User.assigned_hosts).selectinload(Host.assigned_users),
        )
        .where(User.id == user_id)
    )
    target_user = result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    settings = get_settings()
    return UserDetailOut(
        user=user_out(target_user),
        keys=[ssh_key_out(k) for k in target_user.ssh_keys if k.is_active],
        assigned_hosts=[host_out(h) for h in target_user.assigned_hosts if h.is_active],
        ssh_host=await get_ssh_host(),
        ssh_port=settings.SSH_PORT,
        roles=[r.value for r in UserRole],
    )


@router.post("", status_code=201)
async def create_user(
    request: Request,
    body: CreateUserIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> UserOut:
    # Server-side username validation
    username = body.username.lower().strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 1-32 lowercase alphanumeric characters, hyphens, or underscores, starting with a letter.",
        )
    if username in RESERVED_USERNAMES:
        raise HTTPException(status_code=400, detail=f"Username '{username}' is reserved")

    # Server-side password validation
    pwd_min = await get_runtime_setting("password_min_length")
    if len(body.password) < pwd_min:
        raise HTTPException(status_code=400, detail=f"Password must be at least {pwd_min} characters")

    # Validate role
    try:
        user_role = UserRole(body.role)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{body.role}'. Must be one of: admin, operator, readonly",
        )

    # Check duplicate username
    existing = await db.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = User(
        username=username,
        display_name=body.display_name or username,
        email=body.email or None,
        hashed_password=hash_password(body.password),
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
        detail={"username": username, "role": body.role},
    )

    return user_out(new_user)


@router.post("/{user_id}/deactivate")
async def deactivate_user(
    request: Request,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> UserOut:
    target = await _get_user_or_404(db, user_id)

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
    return user_out(target)


@router.post("/{user_id}/activate")
async def activate_user(
    request: Request,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> UserOut:
    target = await _get_user_or_404(db, user_id)

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
    return user_out(target)


@router.put("/{user_id}/role")
async def change_role(
    request: Request,
    user_id: str,
    body: ChangeRoleIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> UserOut:
    # A user must never change their own role (FR-USER-06): prevents both
    # self-elevation and admins accidentally locking themselves out.
    if user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    try:
        new_role = UserRole(body.role)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{body.role}'. Must be one of: admin, operator, readonly",
        )

    target = await _get_user_or_404(db, user_id)

    old_role = target.role
    if new_role != old_role:
        target.role = new_role
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.USER_ROLE_CHANGED,
            target_type="user",
            target_id=user_id,
            source_ip=request.client.host if request.client else None,
            detail={"username": target.username, "old_role": old_role.value, "new_role": new_role.value},
        )

    return user_out(target)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    request: Request,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    if user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    target = await _get_user_or_404(db, user_id)

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
    return Response(status_code=204)


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
    if await _active_key_count(db, user_id) >= max_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {max_keys} keys per user",
        )


async def _check_duplicate_fingerprint(db: AsyncSession, user_id: str, fingerprint: str) -> None:
    """Raise HTTP 400 if the user already has an active key with this fingerprint."""
    dup_result = await db.execute(
        select(SSHKey).where(
            SSHKey.user_id == user_id,
            SSHKey.fingerprint == fingerprint,
            SSHKey.is_active == True,
        )
    )
    if dup_result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="This key is already registered")


async def _add_key(
    request: Request,
    db: AsyncSession,
    actor: User,
    user_id: str,
    label: str,
    key_info: dict,
    *,
    generated: bool = False,
) -> SSHKey:
    """Persist a validated key and write its audit entry."""
    new_key = SSHKey(
        user_id=user_id,
        label=label,
        public_key_text=key_info["public_key_text"],
        fingerprint=key_info["fingerprint"],
        key_type=key_info["key_type"],
    )
    db.add(new_key)
    await db.flush()

    detail = {
        "fingerprint": key_info["fingerprint"],
        "key_type": key_info["key_type"],
        "label": label,
    }
    if generated:
        detail["generated"] = True
    await write_audit_log(
        db,
        actor_id=actor.id,
        action=AuditAction.KEY_ADDED,
        target_type="key",
        target_id=new_key.id,
        source_ip=request.client.host if request.client else None,
        detail=detail,
    )
    return new_key


@router.get("/{user_id}/keys")
async def list_keys(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
) -> list[SSHKeyOut]:
    await _get_user_or_404(db, user_id)
    result = await db.execute(
        select(SSHKey).where(SSHKey.user_id == user_id, SSHKey.is_active == True)
    )
    return [ssh_key_out(k) for k in result.scalars().all()]


@router.post("/{user_id}/keys", status_code=201)
async def upload_key(
    request: Request,
    user_id: str,
    body: UploadKeyIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
) -> SSHKeyOut:
    target = await _get_user_or_404(db, user_id)
    if not target.is_active:
        raise HTTPException(status_code=400, detail="Cannot upload keys for inactive user")

    # Check key limit
    await _check_key_limit(user_id, db)

    # Validate label
    label = _validate_label(body.label)
    if not label:
        raise HTTPException(status_code=400, detail="Label cannot be blank")

    # Validate and parse the key
    try:
        key_info = parse_ssh_public_key(body.public_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    await _check_duplicate_fingerprint(db, user_id, key_info["fingerprint"])

    new_key = await _add_key(request, db, user, user_id, label, key_info)
    return ssh_key_out(new_key)


@router.post("/{user_id}/keys/{key_id}/revoke")
async def revoke_key(
    request: Request,
    user_id: str,
    key_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
) -> SSHKeyOut:
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
    return ssh_key_out(key)


@router.post("/{user_id}/keys/generate", status_code=201)
async def generate_key(
    request: Request,
    response: Response,
    user_id: str,
    body: GenerateKeyIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin_or_self),
) -> GeneratedKeyOut:
    target = await _get_user_or_404(db, user_id)
    if not target.is_active:
        raise HTTPException(status_code=400, detail="Cannot generate keys for inactive user")

    # Check key limit
    await _check_key_limit(user_id, db)

    # Default label when blank
    label = _validate_label(body.label)
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

    # Check for duplicate fingerprint (generated keys are unique in practice, but guard anyway)
    await _check_duplicate_fingerprint(db, user_id, key_info["fingerprint"])

    new_key = await _add_key(request, db, user, user_id, label, key_info, generated=True)

    # The private key is returned exactly once and never persisted server-side.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return GeneratedKeyOut(private_key=private_key_text, key=ssh_key_out(new_key))
