from sqlalchemy import func, select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from core import get_session_factory
from models import User

_SETUP_EXEMPT_PATHS = {"/setup"}
_SETUP_EXEMPT_PREFIXES = ("/static/", "/health")


class SetupGuardMiddleware(BaseHTTPMiddleware):
    """Redirect all requests to /setup when the database has no users."""

    _setup_complete = False

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._setup_complete:
            return await call_next(request)

        path = request.url.path

        # Don't block setup routes themselves
        if path in _SETUP_EXEMPT_PATHS or any(path.startswith(p) for p in _SETUP_EXEMPT_PREFIXES):
            return await call_next(request)

        # Check if any users exist
        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(select(func.count()).select_from(User))
            count = result.scalar()

        if count == 0:
            return RedirectResponse(url="/setup", status_code=303)

        # Users exist — cache this for the lifetime of the process
        SetupGuardMiddleware._setup_complete = True
        return await call_next(request)
