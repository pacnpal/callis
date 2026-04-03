from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from sqlalchemy import select

from core import decode_jwt, get_session_factory, refresh_jwt, get_settings
from models import User


class SessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request.state.user = None

        token = request.cookies.get("callis_session")
        if token:
            payload = decode_jwt(token)
            if payload:
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

        response = await call_next(request)

        # Refresh idle timeout by re-signing JWT with updated last_activity
        if request.state.user and token:
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
