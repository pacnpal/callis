"""Live SSH session tracking.

Tails the sshd log (written by ``sshd -E``, shared with the fail2ban
sidecar) and turns authentication accepts / disconnects into SshSession
rows plus session_opened / session_closed audit entries. Also locates the
per-connection sshd child process via /proc so admins can terminate a
session from the web UI (the unified container runs api and sshd in the
same PID namespace).

sshd -E log lines carry no timestamps, so event times are stamped when the
line is read — the follower tails live, so this is accurate to the poll
interval.
"""

import asyncio
import ipaddress
import logging
import os
import re
import signal
from datetime import datetime, timezone

from sqlalchemy import select

from core import get_session_factory, write_audit_log
from models import AuditAction, SessionTrackerState, SshSession, User

logger = logging.getLogger("callis")

SSHD_LOG_PATH = os.environ.get("CALLIS_SSHD_LOG", "/var/log/callis/auth.log")
POLL_INTERVAL = 2.0
_MISSING_FILE_RETRY = 15.0
_EVENT_RETRY_LIMIT = 5

_ACCEPT_RE = re.compile(
    r"Accepted publickey for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    r" ssh2(?:: (?P<key_type>\S+) (?P<fingerprint>\S+))?"
)
# Ordered: more specific patterns (with username) first. sshd usually logs
# several of these per disconnect; the first one to match an open session
# closes it and the rest become no-ops.
_CLOSE_RES = (
    re.compile(r"Disconnected from user (?P<username>\S+) (?P<ip>\S+) port (?P<port>\d+)"),
    re.compile(r"Connection closed by user (?P<username>\S+) (?P<ip>\S+) port (?P<port>\d+)"),
    re.compile(r"Received disconnect from (?P<ip>\S+) port (?P<port>\d+)"),
    re.compile(r"Connection (?:closed|reset) by (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"),
)


def parse_log_line(line: str) -> dict | None:
    """Parse one sshd log line into an accept/close event, or None.

    Pre-auth lines are ignored — they never correspond to an accepted
    session (failed auth attempts are fail2ban's domain, and remain in the
    sshd log and audit trail via key_used/VERBOSE logging).
    """
    if "[preauth]" in line:
        return None

    m = _ACCEPT_RE.search(line)
    if m:
        return {
            "event": "accept",
            "username": m.group("username"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
            "fingerprint": m.group("fingerprint"),
        }

    for close_re in _CLOSE_RES:
        m = close_re.search(line)
        if m:
            groups = m.groupdict()
            return {
                "event": "close",
                "username": groups.get("username"),
                "ip": groups["ip"],
                "port": int(groups["port"]),
            }
    return None


async def _handle_accept(db, event: dict) -> None:
    # Idempotent: startup replay of the log window covering an API outage may
    # re-read an accept line that was already processed. A live TCP peer
    # (ip, port) is unique, so an existing open session means this exact
    # connection is already tracked.
    existing = await db.execute(
        select(SshSession).where(
            SshSession.ended_at.is_(None),
            SshSession.username == event["username"],
            SshSession.source_ip == event["ip"],
            SshSession.source_port == event["port"],
        )
    )
    if existing.scalars().first() is not None:
        return

    result = await db.execute(
        select(User).where(User.username == event["username"], User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()

    session = SshSession(
        user_id=user.id if user else None,
        username=event["username"],
        source_ip=event["ip"],
        source_port=event["port"],
        key_fingerprint=event.get("fingerprint"),
    )
    db.add(session)
    await db.flush()

    await write_audit_log(
        db,
        actor_id=user.id if user else None,
        action=AuditAction.SESSION_OPENED,
        target_type="session",
        target_id=session.id,
        source_ip=event["ip"],
        detail={
            "username": event["username"],
            "source_port": event["port"],
            "fingerprint": event.get("fingerprint"),
        },
    )


async def _handle_close(db, event: dict, reason: str = "disconnected") -> None:
    query = (
        select(SshSession)
        .where(
            SshSession.ended_at.is_(None),
            SshSession.source_ip == event["ip"],
            SshSession.source_port == event["port"],
        )
        .order_by(SshSession.started_at.desc())
    )
    if event.get("username"):
        query = query.where(SshSession.username == event["username"])
    result = await db.execute(query)
    session = result.scalars().first()
    if session is None:
        return  # duplicate close line, or a connection opened before tracking

    now = datetime.now(timezone.utc)
    session.ended_at = now
    session.close_reason = reason

    started = session.started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    await write_audit_log(
        db,
        actor_id=session.user_id,
        action=AuditAction.SESSION_CLOSED,
        target_type="session",
        target_id=session.id,
        source_ip=session.source_ip,
        detail={
            "username": session.username,
            "duration_seconds": max(0, int((now - started).total_seconds())),
            "reason": reason,
        },
    )


async def _set_position_row(db, inode: int, offset: int) -> None:
    row = await db.get(SessionTrackerState, 1)
    if row is None:
        row = SessionTrackerState(id=1)
        db.add(row)
    row.log_inode = inode
    row.log_offset = offset


async def apply_log_event(event: dict, position: tuple[int, int] | None = None) -> None:
    """Apply one accept/close event; optionally advance the read position.

    When ``position`` is given it is written in the SAME transaction as the
    event, so a committed event can never be replayed after a crash — the
    persisted offset always points past exactly the events that committed.
    """
    factory = get_session_factory()
    async with factory() as db:
        try:
            if event["event"] == "accept":
                await _handle_accept(db, event)
            else:
                await _handle_close(db, event)
            if position is not None:
                await _set_position_row(db, *position)
            await db.commit()
        except Exception:
            await db.rollback()
            raise


async def close_stale_open_sessions() -> int:
    """Close session records from a previous run whose connection is gone.

    Called at startup. supervisord restarts the api process independently of
    sshd, so open records are only closed when no established socket to the
    session's peer remains (checked via /proc/net/tcp{,6} in the unified
    container). Records whose connection is still alive stay open, so an
    API-only restart does not hide live sessions. Where /proc is not
    shared with sshd (split deployments), no socket is ever found and all
    open records are closed — matching the pre-restart-tracking behaviour.
    """
    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(select(SshSession).where(SshSession.ended_at.is_(None)))
        open_sessions = result.scalars().all()
        now = datetime.now(timezone.utc)
        stale_count = 0
        for session in open_sessions:
            if connection_still_established(session.source_ip, session.source_port):
                continue
            session.ended_at = now
            session.close_reason = "server_restart"
            stale_count += 1

            # Keep the audit trail consistent with normal disconnects: every
            # closed session gets a session_closed entry, whatever the cause.
            started = session.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            await write_audit_log(
                db,
                actor_id=session.user_id,
                action=AuditAction.SESSION_CLOSED,
                target_type="session",
                target_id=session.id,
                source_ip=session.source_ip,
                detail={
                    "username": session.username,
                    "duration_seconds": max(0, int((now - started).total_seconds())),
                    "reason": "server_restart",
                },
            )
        await db.commit()
    if stale_count:
        logger.info("Closed %d stale SSH session record(s) from a previous run", stale_count)
    return stale_count


async def _load_log_position() -> tuple[int, int] | None:
    """Return the persisted (inode, offset) of the last processed log line.

    Returns None (start at EOF) on any failure — bookkeeping must never
    prevent the follower from starting.
    """
    try:
        factory = get_session_factory()
        async with factory() as db:
            row = await db.get(SessionTrackerState, 1)
            if row is not None and row.log_inode is not None and row.log_offset is not None:
                return row.log_inode, row.log_offset
    except Exception:
        logger.exception("Failed to load persisted sshd log position")
    return None


async def _save_log_position(inode: int, offset: int) -> None:
    factory = get_session_factory()
    async with factory() as db:
        await _set_position_row(db, inode, offset)
        await db.commit()


async def _save_log_position_safe(inode: int, offset: int) -> None:
    """Persist the read position; bookkeeping must never kill the follower."""
    try:
        await _save_log_position(inode, offset)
    except Exception:
        logger.exception("Failed to persist sshd log position")


def resolve_start_offset(
    saved: tuple[int, int] | None,
    inode: int,
    size: int,
    appeared_after_absence: bool = False,
) -> int:
    """Where to start reading a newly opened log file.

    Resume from the persisted offset when it belongs to this same file, so
    sessions accepted while the API was down (sshd keeps running under
    supervisord) are reconciled on restart. A file that appeared after the
    follower found it missing is brand new (sshd just created it) — read it
    from the start so connections accepted before our retry woke up are not
    dropped. Otherwise — first run against an existing log, rotation while
    down, or truncation — start at EOF: replaying unbounded history would
    fabricate session records with meaningless timestamps.
    """
    if saved is not None:
        saved_inode, saved_offset = saved
        if saved_inode == inode and 0 <= saved_offset <= size:
            return saved_offset
    if appeared_after_absence:
        return 0
    return size


async def follow_sshd_log(path: str | None = None, poll_interval: float = POLL_INTERVAL) -> None:
    """Tail the sshd log forever, applying accept/close events to the DB.

    Resumes from the last persisted position when the file is unchanged
    (reconciling the API-downtime window; replayed events get stamped with
    read time, so timestamps are off by at most the outage duration).
    Survives log rotation and truncation, and idles quietly when the file
    does not exist (split deployments, local development).
    """
    path = path or SSHD_LOG_PATH
    f = None
    cur_ino = 0
    pos_dirty = False
    warned_missing = False
    file_was_missing = False
    retry_pos = -1
    retry_count = 0
    try:
        while True:
            if f is None:
                try:
                    f = open(path, "rb")
                    st = os.fstat(f.fileno())
                    cur_ino = st.st_ino
                    f.seek(
                        resolve_start_offset(
                            await _load_log_position(),
                            st.st_ino,
                            st.st_size,
                            appeared_after_absence=file_was_missing,
                        )
                    )
                    logger.info(
                        "Session tracker following sshd log at %s from offset %d", path, f.tell()
                    )
                    warned_missing = False
                    file_was_missing = False
                except OSError:
                    if f is not None:
                        f.close()
                        f = None
                    file_was_missing = True
                    if not warned_missing:
                        logger.info(
                            "sshd log %s not readable; session tracking idle until it appears",
                            path,
                        )
                        warned_missing = True
                    await asyncio.sleep(_MISSING_FILE_RETRY)
                    continue

            try:
                st = os.stat(path)
                if st.st_ino != cur_ino:
                    # Rotated while running: we were current up to the switch,
                    # so read the replacement file from the start.
                    f.close()
                    f = open(path, "rb")
                    cur_ino = os.fstat(f.fileno()).st_ino
                    pos_dirty = True
                elif st.st_size < f.tell():
                    # Truncated in place: start over.
                    f.seek(0)
                    pos_dirty = True
            except OSError:
                f.close()
                f = None
                continue

            try:
                raw = f.readline()
                if not raw:
                    if pos_dirty:
                        await _save_log_position_safe(cur_ino, f.tell())
                        pos_dirty = False
                    await asyncio.sleep(poll_interval)
                    continue
                if not raw.endswith(b"\n"):
                    # Partial line mid-write: rewind and retry next poll.
                    f.seek(-len(raw), os.SEEK_CUR)
                    await asyncio.sleep(poll_interval)
                    continue
            except OSError as exc:
                logger.warning("Error reading sshd log %s: %s; reopening", path, exc)
                f.close()
                f = None
                await asyncio.sleep(poll_interval)
                continue

            pos_dirty = True
            line_start = f.tell() - len(raw)
            event = parse_log_line(raw.decode("utf-8", errors="replace"))
            if event is None:
                # Yield so a burst of non-matching lines cannot starve the
                # event loop (nothing below awaits on this path).
                await asyncio.sleep(0)
                continue
            try:
                # Event and offset commit atomically: a committed event is
                # never replayed, and a failed one leaves the offset behind
                # so the retry below re-reads the same line.
                await apply_log_event(event, position=(cur_ino, f.tell()))
                retry_pos, retry_count = -1, 0
                pos_dirty = False
                continue
            except Exception:
                # Transient failures (e.g. SQLite "database is locked") must
                # not lose the event: rewind and retry the same line, bounded
                # so a permanently failing line cannot wedge the tracker.
                if line_start == retry_pos:
                    retry_count += 1
                else:
                    retry_pos, retry_count = line_start, 1
                if retry_count <= _EVENT_RETRY_LIMIT:
                    logger.exception(
                        "Failed to record SSH session event %r (attempt %d); retrying",
                        event,
                        retry_count,
                    )
                    f.seek(line_start)
                    await asyncio.sleep(poll_interval)
                    continue
                logger.exception(
                    "Failed to record SSH session event %r after %d attempts; skipping line",
                    event,
                    retry_count,
                )
                retry_pos, retry_count = -1, 0
                # Deliberately skipping this line: advance the offset past it.
                await _save_log_position_safe(cur_ino, f.tell())
                pos_dirty = False
    except asyncio.CancelledError:
        raise
    finally:
        if f is not None:
            f.close()


# ---------------------------------------------------------------------------
# Session process lookup and termination (/proc, unified container only)
# ---------------------------------------------------------------------------


def _candidate_hex_addrs(ip: str, port: int) -> set[str]:
    """Render an IP:port as the hex forms used in /proc/net/tcp{,6}.

    Addresses are stored as little-endian hex per 32-bit group. An IPv4
    client can appear either in /proc/net/tcp or, as an IPv4-mapped IPv6
    address, in /proc/net/tcp6 — both forms are returned.

    Returns an empty set for values that are not valid IP addresses, so a
    malformed stored source_ip can never crash the termination endpoint.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return set()
    port_hex = f"{port:04X}"
    forms: set[str] = set()

    def v4_hex(v4: ipaddress.IPv4Address) -> str:
        return bytes(reversed(v4.packed)).hex().upper()

    def v6_hex(v6: ipaddress.IPv6Address) -> str:
        packed = v6.packed
        groups = [packed[i : i + 4][::-1] for i in range(0, 16, 4)]
        return b"".join(groups).hex().upper()

    if addr.version == 4:
        forms.add(f"{v4_hex(addr)}:{port_hex}")
        forms.add(f"{v6_hex(ipaddress.IPv6Address('::ffff:' + ip))}:{port_hex}")
    else:
        forms.add(f"{v6_hex(addr)}:{port_hex}")
        if addr.ipv4_mapped:
            forms.add(f"{v4_hex(addr.ipv4_mapped)}:{port_hex}")
    return forms


_TCP_ESTABLISHED = "01"


def find_socket_inodes(proc_net_text: str, ip: str, port: int) -> set[str]:
    """Socket inodes in /proc/net/tcp{,6} content whose peer is ip:port."""
    targets = _candidate_hex_addrs(ip, port)
    inodes: set[str] = set()
    for line in proc_net_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        rem_address, state, inode = fields[2], fields[3], fields[9]
        if state == _TCP_ESTABLISHED and rem_address.upper() in targets:
            inodes.add(inode)
    return inodes


def _pids_for_inodes(inodes: set[str]) -> list[int]:
    pids = []
    socket_links = {f"socket:[{inode}]" for inode in inodes}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        fd_dir = f"/proc/{entry}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    if os.readlink(f"{fd_dir}/{fd}") in socket_links:
                        pids.append(int(entry))
                        break
                except OSError:
                    continue
        except OSError:
            continue  # process exited or not ours
    return pids


def _socket_inodes_for_peer(ip: str, port: int) -> set[str]:
    """Inodes of established sockets whose peer is ip:port, from /proc."""
    inodes: set[str] = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table) as fh:
                inodes |= find_socket_inodes(fh.read(), ip, port)
        except OSError:
            continue
    return inodes


def connection_still_established(ip: str, port: int) -> bool:
    """True if an established socket to ip:port still exists on this host."""
    return bool(_socket_inodes_for_peer(ip, port))


def terminate_session_process(ip: str, port: int) -> bool:
    """SIGTERM the sshd child holding the connection from ip:port.

    Returns True if at least one process was signalled. Only works in the
    unified container (api shares a PID namespace with sshd and runs as
    root); returns False otherwise.
    """
    inodes = _socket_inodes_for_peer(ip, port)
    if not inodes:
        return False

    signalled = False
    for pid in _pids_for_inodes(inodes):
        if pid == os.getpid():
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            signalled = True
            logger.info("Terminated SSH session process pid=%d (%s:%d)", pid, ip, port)
        except OSError as exc:
            logger.warning("Could not signal pid %d for %s:%d: %s", pid, ip, port, exc)
    return signalled
