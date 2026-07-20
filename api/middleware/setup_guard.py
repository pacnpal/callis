from sqlalchemy import func, select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from core import get_session_factory
from models import User

_SETUP_EXEMPT_PATHS = {"/install.sh", "/callis.sh", "/health"}
_SETUP_EXEMPT_PREFIXES = ("/api/v1/setup", "/api/v1/meta")


class SetupGuardMiddleware(BaseHTTPMiddleware):
    """Reject all requests with a setup-required error when the DB has no users.

    The SSR frontend reads `setup_needed` from /api/v1/meta (exempt below) and
    redirects browsers to the /setup wizard; this middleware is the server-side
    enforcement layer that keeps every other endpoint closed until an admin
    account exists.
    """

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
            return JSONResponse({"detail": "setup_required"}, status_code=409)

        # Users exist — cache this for the lifetime of the process
        SetupGuardMiddleware._setup_complete = True
        return await call_next(request)
