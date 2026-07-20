from datetime import datetime, timezone

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import get_db, write_audit_log
from dependencies import require_role, require_totp_complete
from models import AuditAction, SshSession, User
from schemas import SessionsOut, SshSessionOut, ssh_session_out
from session_tracker import terminate_session_process

router = APIRouter(prefix="/sessions")

RECENT_CLOSED_LIMIT = 20


@router.get("")
async def session_list(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_totp_complete),
) -> SessionsOut:
    active_result = await db.execute(
        select(SshSession)
        .where(SshSession.ended_at.is_(None))
        .order_by(SshSession.started_at.desc())
    )
    recent_result = await db.execute(
        select(SshSession)
        .where(SshSession.ended_at.is_not(None))
        .order_by(SshSession.ended_at.desc())
        .limit(RECENT_CLOSED_LIMIT)
    )
    return SessionsOut(
        active=[ssh_session_out(s) for s in active_result.scalars().all()],
        recent=[ssh_session_out(s) for s in recent_result.scalars().all()],
    )


@router.post("/{session_id}/terminate")
async def terminate_session(
    request: Request,
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> SshSessionOut:
    result = await db.execute(
        select(SshSession).where(SshSession.id == session_id, SshSession.ended_at.is_(None))
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Active session not found")

    # Signal the sshd child owning this connection. The /proc scan is
    # synchronous — run it off the event loop.
    signalled = await anyio.to_thread.run_sync(
        terminate_session_process, session.source_ip, session.source_port
    )

    if not signalled:
        # Keep the record open: in a split deployment the API cannot see
        # sshd's PID namespace, so the connection may well still be live.
        # Closing here would hide it from the page and falsely audit a
        # termination; the log follower (or the startup sweep) closes the
        # record when the connection actually ends.
        raise HTTPException(status_code=409, detail="session_process_not_found")

    session.ended_at = datetime.now(timezone.utc)
    session.close_reason = "terminated"

    await write_audit_log(
        db,
        actor_id=user.id,
        action=AuditAction.SESSION_TERMINATED,
        target_type="session",
        target_id=session.id,
        source_ip=request.client.host if request.client else None,
        detail={
            "username": session.username,
            "session_source_ip": session.source_ip,
        },
    )
    return ssh_session_out(session)
