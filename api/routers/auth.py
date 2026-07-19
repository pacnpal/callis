from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import (
    consume_recovery_code,
    create_jwt,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    get_db,
    get_settings,
    hash_password,
    issue_recovery_codes,
    limiter,
    looks_like_recovery_code,
    totp_qr_b64,
    unused_recovery_code_count,
    verify_password,
    verify_totp,
    write_audit_log,
)
from dependencies import get_current_user
from models import AuditAction, User
from schemas import EnrollOut, LoginIn, SessionOut, TOTPSetupOut, TOTPVerifyIn, user_out

router = APIRouter(prefix="/auth")

# Precomputed dummy hash for constant-time login checks (avoid hashing on every failed attempt)
_DUMMY_HASH = hash_password("dummy-constant-time-check")


def set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        "callis_session",
        token,
        httponly=True,
        secure=settings.HTTPS_ENABLED,
        samesite="strict",
        path="/",
    )


@router.get("/me")
async def me(user: User = Depends(get_current_user)) -> SessionOut:
    return SessionOut(user=user_out(user))


@router.post("/login")
@limiter.limit("5/15minutes")
async def login_submit(
    request: Request,
    response: Response,
    body: LoginIn,
    db: AsyncSession = Depends(get_db),
) -> SessionOut:
    error = HTTPException(status_code=401, detail="Invalid credentials")
    username = body.username.lower().strip()

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        # Constant-time: verify against precomputed dummy hash to prevent timing attacks
        verify_password(body.password, _DUMMY_HASH)
        await write_audit_log(
            db,
            actor_id=None,
            action=AuditAction.LOGIN_FAILURE,
            target_type="user",
            source_ip=request.client.host if request.client else None,
            detail={"username": username, "reason": "user_not_found"},
        )
        # Commit before raising: the HTTPException sends this session through
        # get_db()'s rollback path, which would otherwise drop the audit row.
        await db.commit()
        raise error

    if not verify_password(body.password, user.hashed_password):
        await write_audit_log(
            db,
            actor_id=None,
            action=AuditAction.LOGIN_FAILURE,
            target_type="user",
            target_id=user.id,
            source_ip=request.client.host if request.client else None,
            detail={"reason": "wrong_password", "target_username": user.username},
        )
        await db.commit()
        raise error

    # If TOTP enrolled, verify code (always run decrypt+verify for constant-time)
    if user.totp_enrolled:
        secret = decrypt_totp_secret(user.totp_secret)
        submitted_totp_code = (body.totp_code or "").strip()
        # verify_totp already handles invalid/empty formats in constant-time
        totp_valid = verify_totp(secret, submitted_totp_code)

        # A single-use recovery code may be entered in place of the TOTP code
        # (lost/replaced authenticator device). Only attempted when the input
        # has recovery-code shape, so 6-digit TOTP attempts never hit the DB.
        used_recovery_code = False
        if not totp_valid and looks_like_recovery_code(submitted_totp_code):
            used_recovery_code = await consume_recovery_code(db, user.id, submitted_totp_code)

        if used_recovery_code:
            remaining = await unused_recovery_code_count(db, user.id)
            await write_audit_log(
                db,
                actor_id=user.id,
                action=AuditAction.RECOVERY_CODE_USED,
                target_type="user",
                target_id=user.id,
                source_ip=request.client.host if request.client else None,
                detail={"target_username": user.username, "remaining_codes": remaining},
            )
        elif not totp_valid:
            totp_failure_reason = "totp_missing" if not submitted_totp_code else "totp_invalid"
            await write_audit_log(
                db,
                actor_id=None,
                action=AuditAction.TOTP_FAILURE,
                target_type="user",
                target_id=user.id,
                source_ip=request.client.host if request.client else None,
                detail={"reason": totp_failure_reason, "target_username": user.username},
            )
            await db.commit()
            raise error

    # Success
    user.last_login_at = datetime.now(timezone.utc)
    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.LOGIN_SUCCESS,
        target_type="user",
        target_id=user.id,
        source_ip=request.client.host if request.client else None,
    )

    token = create_jwt(user.id)
    set_session_cookie(response, token)
    return SessionOut(user=user_out(user))


@router.get("/totp/setup")
async def totp_setup(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TOTPSetupOut:
    """Return (generating if needed) the pending TOTP enrollment secret + QR code."""
    if user.totp_enrolled:
        raise HTTPException(status_code=409, detail="totp_already_enrolled")

    # Re-load user in this session so mutations are persisted
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one()

    # Generate or reuse TOTP secret
    if db_user.totp_secret:
        secret = decrypt_totp_secret(db_user.totp_secret)
    else:
        secret = generate_totp_secret()
        db_user.totp_secret = encrypt_totp_secret(secret)
        await db.flush()

    return TOTPSetupOut(qr_png_b64=totp_qr_b64(secret, user.username), secret=secret)


@router.post("/totp/verify")
async def totp_verify(
    request: Request,
    body: TOTPVerifyIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EnrollOut:
    if user.totp_enrolled:
        raise HTTPException(status_code=409, detail="totp_already_enrolled")

    # Re-load user in this session so mutations are persisted
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one()

    if not db_user.totp_secret:
        raise HTTPException(status_code=409, detail="totp_not_initialized")

    secret = decrypt_totp_secret(db_user.totp_secret)
    if not verify_totp(secret, body.totp_code):
        raise HTTPException(status_code=400, detail="Invalid code. Please try again.")

    db_user.totp_enrolled = True
    await write_audit_log(
        db,
        actor_id=db_user.id,
        action=AuditAction.TOTP_SETUP,
        target_type="user",
        target_id=db_user.id,
        source_ip=request.client.host if request.client else None,
    )

    # Issue single-use recovery codes, returned exactly once.
    codes = await issue_recovery_codes(db, db_user.id)
    await write_audit_log(
        db,
        actor_id=db_user.id,
        action=AuditAction.RECOVERY_CODES_GENERATED,
        target_type="user",
        target_id=db_user.id,
        source_ip=request.client.host if request.client else None,
        detail={"count": len(codes), "source": "totp_enrollment"},
    )

    return EnrollOut(user=user_out(db_user), recovery_codes=codes)


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    user = getattr(request.state, "user", None)
    if user:
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.LOGOUT,
            target_type="user",
            target_id=user.id,
            source_ip=request.client.host if request.client else None,
        )

    response = Response(status_code=204)
    response.delete_cookie("callis_session", path="/")
    return response
