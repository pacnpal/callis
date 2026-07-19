import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from sqlalchemy import select

from core import decode_jwt_detailed, get_session_factory, refresh_jwt, get_settings, write_audit_log
from models import AuditAction, User

logger = logging.getLogger("callis")


class SessionMiddleware(BaseHTTPMiddleware):
    # Paths that don't need session loading
    _SKIP_PATHS = ("/health", "/install.sh", "/callis.sh")

    async def dispatch(self, request: Request, call_next) -> Response:
        request.state.user = None

        # Skip session loading for static assets and health checks
        path = request.url.path
        if any(path.startswith(p) for p in self._SKIP_PATHS):
            return await call_next(request)

        session_expired = False
        token = request.cookies.get("callis_session")
        if token:
            payload, reason = decode_jwt_detailed(token)
            if reason == "ok" and payload:
                user_id = payload.get("sub")
                if user_id:
                    factory = get_session_factory()
                    async with factory() as db:
                        result = await db.execute(
                            select(User).where(User.id == user_id)
                        )
                        user = result.scalar_one_or_none()
                        if user and user.is_active:
                            request.state.user = user
            elif reason == "expired" and payload:
                # A real session ended (idle timeout or max lifetime).
                # Audit it once (FR-AUDIT-01: session expiry) and clear the
                # stale cookie below so this fires only once per session.
                session_expired = True
                try:
                    factory = get_session_factory()
                    async with factory() as db:
                        result = await db.execute(
                            select(User).where(User.id == payload.get("sub"))
                        )
                        user = result.scalar_one_or_none()
                        if user:
                            await write_audit_log(
                                db,
                                actor_id=user.id,
                                action=AuditAction.LOGOUT,
                                target_type="user",
                                target_id=user.id,
                                source_ip=request.client.host if request.client else None,
                                detail={"reason": "session_expired"},
                            )
                            await db.commit()
                except Exception:
                    logger.exception("Failed to audit session expiry")

        response = await call_next(request)

        # Check whether the handler already set/deleted the session cookie (e.g. login/logout)
        has_session_cookie_change = any(
            "callis_session" in h for h in response.headers.getlist("set-cookie")
        )

        if session_expired and not has_session_cookie_change:
            # Remove the stale cookie so the expiry is only processed once.
            response.delete_cookie("callis_session", path="/")
            return response

        # Refresh idle timeout by re-signing JWT with updated last_activity
        if request.state.user and token and not has_session_cookie_change:
            new_token = refresh_jwt(token)
            if new_token:
                settings = get_settings()
                response.set_cookie(
                    "callis_session",
                    new_token,
                    httponly=True,
                    secure=settings.HTTPS_ENABLED,
                    samesite="strict",
                    path="/",
                )

        return response
