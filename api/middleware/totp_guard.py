from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

TOTP_EXEMPT_PATHS = {"/health", "/install.sh", "/callis.sh"}
TOTP_EXEMPT_PREFIXES = ("/api/v1/auth/", "/api/v1/setup", "/api/v1/meta")


class TOTPGuardMiddleware(BaseHTTPMiddleware):
    """Block authenticated-but-unenrolled users from everything except enrollment.

    The SSR frontend translates the totp_enrollment_required error into a
    redirect to /totp/setup; this middleware is the server-side enforcement.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        user = getattr(request.state, "user", None)

        if user and not user.totp_enrolled:
            path = request.url.path
            if path not in TOTP_EXEMPT_PATHS and not path.startswith(TOTP_EXEMPT_PREFIXES):
                return JSONResponse(
                    {"detail": "totp_enrollment_required"}, status_code=403
                )

        return await call_next(request)
