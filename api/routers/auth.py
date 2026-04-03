import io
import base64
import logging
from datetime import datetime, timezone

import qrcode
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address
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
    verify_password,
    verify_totp,
    write_audit_log,
)
from dependencies import get_current_user
from models import AuditAction, User

logger = logging.getLogger("callis")
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
templates = Jinja2Templates(directory="templates")

# Precomputed dummy hash for constant-time login checks (avoid hashing on every failed attempt)
_DUMMY_HASH = hash_password("dummy-constant-time-check")


@router.get("/login")
async def login_page(request: Request):
    user = getattr(request.state, "user", None)
    if user and user.totp_enrolled:
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request})


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
            "login.html",
            {"request": request, "error": error_msg},
            status_code=401,
        )

    if not verify_password(password, user.hashed_password):
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.LOGIN_FAILURE,
            target_type="user",
            target_id=user.id,
            source_ip=request.client.host if request.client else None,
            detail={"reason": "wrong_password"},
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": error_msg},
            status_code=401,
        )

    # If TOTP enrolled, verify code (always run verify to maintain constant-time)
    if user.totp_enrolled:
        secret = decrypt_totp_secret(user.totp_secret)
        totp_valid = verify_totp(secret, totp_code) if totp_code else False
        if not totp_valid:
            await write_audit_log(
                db,
                actor_id=user.id,
                action=AuditAction.TOTP_FAILURE,
                target_type="user",
                target_id=user.id,
                source_ip=request.client.host if request.client else None,
            )
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": error_msg},
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

    # Generate or reuse TOTP secret
    if user.totp_secret:
        secret = decrypt_totp_secret(user.totp_secret)
    else:
        secret = generate_totp_secret()
        user.totp_secret = encrypt_totp_secret(secret)
        await db.flush()

    # Generate QR code as base64
    uri = get_totp_uri(secret, user.username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return templates.TemplateResponse(
        "totp_setup.html",
        {
            "request": request,
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

    secret = decrypt_totp_secret(user.totp_secret)
    if not verify_totp(secret, totp_code):
        # Re-render setup with error
        uri = get_totp_uri(secret, user.username)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return templates.TemplateResponse(
            "totp_setup.html",
            {
                "request": request,
                "user": user,
                "qr_code": qr_b64,
                "totp_secret": secret,
                "error": "Invalid code. Please try again.",
            },
        )

    user.totp_enrolled = True
    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.TOTP_SETUP,
        target_type="user",
        target_id=user.id,
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
