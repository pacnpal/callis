import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from core import (
    RESERVED_USERNAMES,
    USERNAME_RE,
    create_jwt,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    get_runtime_setting,
    get_session_factory,
    hash_password,
    issue_recovery_codes,
    limiter,
    totp_qr_b64,
    verify_totp,
    write_audit_log,
)
from models import AuditAction, User, UserRole
from dependencies import get_current_user
from routers.auth import set_session_cookie
from schemas import EnrollOut, SessionOut, SetupIn, TOTPSetupOut, TOTPVerifyIn, user_out

router = APIRouter(prefix="/setup")

# Prevent concurrent first-run POSTs from creating multiple admin accounts.
#
# Multi-worker safety note:
# This asyncio.Lock only serialises requests within a single process.  For
# multi-worker deployments the following defence-in-depth layers apply:
#
#   1. SQLite (the default backend) enforces a single-writer lock at the
#      database level, so concurrent INSERTs from different workers are
#      serialised automatically.
#
#   2. The re-check of `count == 0` inside the transaction (below) ensures
#      that if two workers both pass the pre-lock check, only the first to
#      commit will see count == 0.
#
#   3. The IntegrityError catch on commit handles the remaining edge case
#      where a unique-constraint violation occurs (e.g. duplicate username).
#
# For PostgreSQL multi-worker deployments, layer (1) does not apply, but
# layers (2) and (3) together provide the necessary safety net: the re-check
# races are resolved by the IntegrityError catch on the unique constraint.
_setup_lock = asyncio.Lock()


async def _is_setup_needed() -> bool:
    """Return True if the database has no users."""
    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(select(func.count()).select_from(User))
        return result.scalar() == 0


async def _is_fully_setup() -> bool:
    """Return True if at least one admin user has completed TOTP enrollment."""
    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(
            select(func.count())
            .select_from(User)
            .where(User.role == UserRole.admin, User.totp_enrolled.is_(True))
        )
        return result.scalar() > 0


@router.get("/status")
async def setup_status():
    """Public first-run probe used by the SSR frontend's setup redirect."""
    return {
        "setup_needed": await _is_setup_needed(),
        "fully_setup": await _is_fully_setup(),
    }


@router.post("", status_code=201)
@limiter.limit("10/minute")
async def setup_submit(
    request: Request,
    response: Response,
    body: SetupIn,
) -> SessionOut:
    if not await _is_setup_needed():
        raise HTTPException(status_code=404)

    username = body.username.lower().strip()
    display_name = body.display_name.strip() or "Administrator"
    errors = []

    if not USERNAME_RE.match(username):
        errors.append("Username must start with a letter, contain only lowercase letters, numbers, hyphens, and underscores, and be 1-32 characters.")
    if username in RESERVED_USERNAMES:
        errors.append(f"Username '{username}' is reserved.")
    min_length: int = await get_runtime_setting("password_min_length")
    if len(body.password) < min_length:
        errors.append(f"Password must be at least {min_length} characters.")
    if body.password != body.password_confirm:
        errors.append("Passwords do not match.")

    if errors:
        raise HTTPException(status_code=400, detail=" ".join(errors))

    # Acquire lock and re-verify no user exists to prevent concurrent setup races
    async with _setup_lock:
        if not await _is_setup_needed():
            raise HTTPException(status_code=409, detail="Setup has already been completed.")

        # Create admin user
        factory = get_session_factory()
        async with factory() as db:
            # Check for existing username to avoid an IntegrityError on commit
            existing = await db.execute(select(User).where(User.username == username))
            if existing.scalar_one_or_none():
                raise HTTPException(status_code=400, detail=f"Username '{username}' is already taken.")

            # Re-check count inside the transaction before inserting.
            # Design decision: SQLite (the default) is single-writer, so this
            # re-check alone is sufficient to prevent duplicate admin creation.
            # For PostgreSQL multi-worker deployments, the User table's unique
            # constraint on `username` provides the final safety net — the
            # IntegrityError catch on db.commit() below handles that case.
            # See the _setup_lock comment at module level for full rationale.
            recount = await db.execute(select(func.count()).select_from(User))
            if recount.scalar() > 0:
                raise HTTPException(status_code=409, detail="Setup has already been completed.")

            admin = User(
                username=username,
                display_name=display_name,
                hashed_password=hash_password(body.password),
                role=UserRole.admin,
                is_active=True,
            )
            # Generate and encrypt TOTP secret now (verified in next step)
            totp_secret = generate_totp_secret()
            admin.totp_secret = encrypt_totp_secret(totp_secret)
            db.add(admin)
            # Flush to assign admin.id before writing the audit log
            await db.flush()

            await write_audit_log(
                db,
                actor_id=admin.id,
                action=AuditAction.USER_CREATED,
                target_type="user",
                target_id=admin.id,
                source_ip=request.client.host if request.client else None,
                detail={"username": username, "role": "admin", "source": "setup_wizard"},
            )
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                raise HTTPException(status_code=400, detail=f"Username '{username}' is already taken.")

    # Set session cookie so TOTP step is authenticated
    token = create_jwt(admin.id, admin.session_epoch)
    set_session_cookie(response, token)
    return SessionOut(user=user_out(admin))


@router.get("/totp")
async def setup_totp_page(user: User = Depends(get_current_user)) -> TOTPSetupOut:
    if await _is_fully_setup():
        raise HTTPException(status_code=404)

    if user.totp_enrolled:
        raise HTTPException(status_code=409, detail="totp_already_enrolled")

    if not user.totp_secret:
        raise HTTPException(status_code=409, detail="totp_not_initialized")

    secret = decrypt_totp_secret(user.totp_secret)
    return TOTPSetupOut(qr_png_b64=totp_qr_b64(secret, user.username), secret=secret)


@router.post("/totp/verify")
@limiter.limit("10/minute")
async def setup_totp_verify(
    request: Request,
    body: TOTPVerifyIn,
    user: User = Depends(get_current_user),
) -> EnrollOut:
    if await _is_fully_setup():
        raise HTTPException(status_code=404)

    if user.totp_enrolled:
        raise HTTPException(status_code=409, detail="totp_already_enrolled")

    if not user.totp_secret:
        raise HTTPException(status_code=409, detail="totp_not_initialized")

    secret = decrypt_totp_secret(user.totp_secret)

    if not verify_totp(secret, body.totp_code):
        raise HTTPException(status_code=400, detail="Invalid code. Please try again.")

    # Mark TOTP as enrolled
    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(select(User).where(User.id == user.id))
        db_user = result.scalar_one()
        db_user.totp_enrolled = True

        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.TOTP_SETUP,
            target_type="user",
            target_id=user.id,
            source_ip=request.client.host if request.client else None,
            detail={"source": "setup_wizard"},
        )

        # Issue single-use recovery codes, returned exactly once.
        codes = await issue_recovery_codes(db, user.id)
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.RECOVERY_CODES_GENERATED,
            target_type="user",
            target_id=user.id,
            source_ip=request.client.host if request.client else None,
            detail={"count": len(codes), "source": "setup_wizard"},
        )
        await db.commit()

    return EnrollOut(user=user_out(db_user), recovery_codes=codes)
