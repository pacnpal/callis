import io
import base64
from datetime import datetime, timezone

import qrcode
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import (
    create_jwt,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    get_db,
    get_settings,
    get_totp_uri,
    hash_password,
    limiter,
    register_template_filters,
    verify_password,
    verify_totp,
    write_audit_log,
)
from dependencies import get_current_user
from models import AuditAction, User

router = APIRouter()
templates = Jinja2Templates(directory="templates")
register_template_filters(templates)

# Precomputed dummy hash for constant-time login checks (avoid hashing on every failed attempt)
_DUMMY_HASH = hash_password("dummy-constant-time-check")


@router.get("/login")
async def login_page(request: Request):
    user = getattr(request.state, "user", None)
    if user and user.totp_enrolled:
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(request, "login.html")


@router.post("/login")
@limiter.limit("5/15minutes")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    error_msg = "Invalid credentials"
    username = username.lower().strip()

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        # Constant-time: verify against precomputed dummy hash to prevent timing attacks
        verify_password(password, _DUMMY_HASH)
        await write_audit_log(
            db,
            actor_id=None,
            action=AuditAction.LOGIN_FAILURE,
            target_type="user",
            source_ip=request.client.host if request.client else None,
            detail={"username": username, "reason": "user_not_found"},
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            context={"error": error_msg},
            status_code=401,
        )

    if not verify_password(password, user.hashed_password):
        await write_audit_log(
            db,
            actor_id=None,
            action=AuditAction.LOGIN_FAILURE,
            target_type="user",
            target_id=user.id,
            source_ip=request.client.host if request.client else None,
            detail={"reason": "wrong_password", "target_username": user.username},
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            context={"error": error_msg},
            status_code=401,
        )

    # If TOTP enrolled, verify code (always run decrypt+verify for constant-time)
    if user.totp_enrolled:
        secret = decrypt_totp_secret(user.totp_secret)
        # Normalize empty code to a dummy value so verify_totp always runs
        totp_valid = verify_totp(secret, totp_code if totp_code else "000000")
        if not totp_valid:
            await write_audit_log(
                db,
                actor_id=None,
                action=AuditAction.TOTP_FAILURE,
                target_type="user",
                target_id=user.id,
                source_ip=request.client.host if request.client else None,
                detail={"reason": "invalid_totp", "target_username": user.username},
            )
            return templates.TemplateResponse(
                request,
                "login.html",
                context={"error": error_msg},
                status_code=401,
            )

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
    redirect_url = "/dashboard" if user.totp_enrolled else "/totp/setup"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        "callis_session",
        token,
        httponly=True,
        secure=settings.HTTPS_ENABLED,
        samesite="strict",
        path="/",
    )
    return response


@router.get("/totp/setup")
async def totp_setup_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if user.totp_enrolled:
        return RedirectResponse(url="/dashboard", status_code=303)

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

    # Generate QR code as base64
    uri = get_totp_uri(secret, user.username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return templates.TemplateResponse(
        request,
        "totp_setup.html",
        context={
            "user": user,
            "qr_code": qr_b64,
            "totp_secret": secret,
        },
    )


@router.post("/totp/verify")
async def totp_verify(
    request: Request,
    totp_code: str = Form(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if user.totp_enrolled:
        return RedirectResponse(url="/dashboard", status_code=303)

    # Re-load user in this session so mutations are persisted
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one()

    if not db_user.totp_secret:
        return RedirectResponse(url="/totp/setup", status_code=303)

    secret = decrypt_totp_secret(db_user.totp_secret)
    if not verify_totp(secret, totp_code):
        # Re-render setup with error
        uri = get_totp_uri(secret, db_user.username)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return templates.TemplateResponse(
            request,
            "totp_setup.html",
            context={
                "user": user,
                "qr_code": qr_b64,
                "totp_secret": secret,
                "error": "Invalid code. Please try again.",
            },
        )

    db_user.totp_enrolled = True
    await write_audit_log(
        db,
        actor_id=db_user.id,
        action=AuditAction.TOTP_SETUP,
        target_type="user",
        target_id=db_user.id,
        source_ip=request.client.host if request.client else None,
    )

    return RedirectResponse(url="/dashboard", status_code=303)


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

    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("callis_session", path="/")
    return response


@router.get("/health")
async def health():
    return {"status": "ok"}
