from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

TOTP_EXEMPT_PATHS = {"/totp/setup", "/totp/verify", "/login", "/logout", "/health"}
TOTP_EXEMPT_PREFIXES = ("/static",)


class TOTPGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        user = getattr(request.state, "user", None)

        if user and not user.totp_enrolled:
            path = request.url.path
            if path not in TOTP_EXEMPT_PATHS and not path.startswith(TOTP_EXEMPT_PREFIXES):
                return RedirectResponse(url="/totp/setup", status_code=303)

        return await call_next(request)
