import base64
import io

import qrcode
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from core import (
    RESERVED_USERNAMES,
    USERNAME_RE,
    create_jwt,
    encrypt_totp_secret,
    generate_totp_secret,
    get_session_factory,
    get_settings,
    get_totp_uri,
    hash_password,
    limiter,
    register_template_filters,
    verify_totp,
    write_audit_log,
)
from middleware.setup_guard import SetupGuardMiddleware
from models import AuditAction, User, UserRole
from dependencies import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory="templates")
register_template_filters(templates)


async def _is_setup_needed() -> bool:
    """Return True if the database has no users."""
    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(select(func.count()).select_from(User))
        return result.scalar() == 0


@router.get("/setup")
async def setup_page(request: Request):
    if not await _is_setup_needed():
        raise HTTPException(status_code=404)
    return templates.TemplateResponse("setup.html", {"request": request})


@router.post("/setup")
@limiter.limit("10/minute")
async def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    display_name: str = Form("Administrator"),
):
    if not await _is_setup_needed():
        raise HTTPException(status_code=404)

    username = username.lower().strip()
    display_name = display_name.strip() or "Administrator"
    errors = []

    if not USERNAME_RE.match(username):
        errors.append("Username must start with a letter, contain only lowercase letters, numbers, hyphens, and underscores, and be 1-32 characters.")
    if username in RESERVED_USERNAMES:
        errors.append(f"Username '{username}' is reserved.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if password != password_confirm:
        errors.append("Passwords do not match.")

    if errors:
        return templates.TemplateResponse(
            "setup.html",
            {"request": request, "error": " ".join(errors), "username": username, "display_name": display_name},
            status_code=400,
        )

    # Create admin user
    factory = get_session_factory()
    async with factory() as db:
        # Check for existing username to avoid an IntegrityError on commit
        existing = await db.execute(select(User).where(User.username == username))
        if existing.scalar_one_or_none():
            return templates.TemplateResponse(
                "setup.html",
                {"request": request, "error": f"Username '{username}' is already taken.", "username": username, "display_name": display_name},
                status_code=400,
            )

        admin = User(
            username=username,
            display_name=display_name,
            hashed_password=hash_password(password),
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
            return templates.TemplateResponse(
                "setup.html",
                {"request": request, "error": f"Username '{username}' is already taken.", "username": username, "display_name": display_name},
                status_code=400,
            )

    # Set session cookie so TOTP step is authenticated
    token = create_jwt(admin.id)
    response = RedirectResponse(url="/setup/totp", status_code=303)
    settings = get_settings()
    response.set_cookie(
        "callis_session",
        token,
        httponly=True,
        secure=settings.HTTPS_ENABLED,
        samesite="strict",
        path="/",
    )
    return response


@router.get("/setup/totp")
async def setup_totp_page(request: Request, user: User = Depends(get_current_user)):
    if user.totp_enrolled:
        return RedirectResponse(url="/dashboard", status_code=303)

    if not user.totp_secret:
        return RedirectResponse(url="/totp/setup", status_code=303)

    from core import decrypt_totp_secret
    secret = decrypt_totp_secret(user.totp_secret)
    uri = get_totp_uri(secret, user.username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return templates.TemplateResponse(
        "setup_totp.html",
        {"request": request, "user": user, "qr_code": qr_b64, "totp_secret": secret},
    )


@router.post("/setup/totp")
@limiter.limit("10/minute")
async def setup_totp_verify(
    request: Request,
    totp_code: str = Form(...),
    user: User = Depends(get_current_user),
):
    if user.totp_enrolled:
        return RedirectResponse(url="/dashboard", status_code=303)

    if not user.totp_secret:
        return RedirectResponse(url="/totp/setup", status_code=303)

    from core import decrypt_totp_secret
    secret = decrypt_totp_secret(user.totp_secret)

    if not verify_totp(secret, totp_code):
        uri = get_totp_uri(secret, user.username)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return templates.TemplateResponse(
            "setup_totp.html",
            {"request": request, "user": user, "qr_code": qr_b64, "totp_secret": secret, "error": "Invalid code. Please try again."},
            status_code=400,
        )

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
        await db.commit()

    # Mark setup as complete so middleware stops redirecting
    SetupGuardMiddleware._setup_complete = True

    return RedirectResponse(url="/dashboard", status_code=303)
