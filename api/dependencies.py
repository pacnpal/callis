from fastapi import Depends, HTTPException, Request

from models import User, UserRole

ROLE_HIERARCHY = {
    UserRole.admin: 3,
    UserRole.operator: 2,
    UserRole.readonly: 1,
}


async def get_current_user(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


async def require_totp_complete(
    user: User = Depends(get_current_user),
) -> User:
    if not user.totp_enrolled:
        raise HTTPException(status_code=303, headers={"Location": "/totp/setup"})
    return user


def require_role(role: str):
    required_level = ROLE_HIERARCHY.get(UserRole(role), 0)

    async def _check(user: User = Depends(require_totp_complete)) -> User:
        user_level = ROLE_HIERARCHY.get(user.role, 0)
        if user_level < required_level:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _check


async def require_admin_or_self(
    user_id: str,
    user: User = Depends(require_totp_complete),
) -> User:
    """Allow admin to act on any user, or a user to act on themselves."""
    if user.role != UserRole.admin and user.id != user_id:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return user
