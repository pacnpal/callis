import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import core
import session_tracker
from core import hash_password
from models import AuditAction, AuditLog, Base, SshSession, User, UserRole
from session_tracker import (
    _candidate_hex_addrs,
    close_stale_open_sessions,
    find_socket_inodes,
    parse_log_line,
    resolve_start_offset,
)


# ---------------------------------------------------------------------------
# Log line parsing
# ---------------------------------------------------------------------------

ACCEPT_LINE = (
    "Accepted publickey for alice from 172.18.0.1 port 51234 ssh2: "
    "ED25519 SHA256:AbCdEf123456"
)


def test_parse_accept_line():
    event = parse_log_line(ACCEPT_LINE)
    assert event == {
        "event": "accept",
        "username": "alice",
        "ip": "172.18.0.1",
        "port": 51234,
        "fingerprint": "SHA256:AbCdEf123456",
    }


def test_parse_accept_line_without_key_info():
    event = parse_log_line("Accepted publickey for bob from 10.0.0.5 port 40000 ssh2")
    assert event["event"] == "accept"
    assert event["username"] == "bob"
    assert event["fingerprint"] is None


def test_parse_close_lines():
    for line, username in (
        ("Disconnected from user alice 172.18.0.1 port 51234", "alice"),
        ("Connection closed by user alice 172.18.0.1 port 51234", "alice"),
        ("Received disconnect from 172.18.0.1 port 51234:11: disconnected by user", None),
        ("Connection reset by 172.18.0.1 port 51234", None),
    ):
        event = parse_log_line(line)
        assert event is not None, line
        assert event["event"] == "close", line
        assert event["ip"] == "172.18.0.1"
        assert event["port"] == 51234
        assert event.get("username") == username, line


def test_parse_ignores_preauth_and_noise():
    assert parse_log_line("Connection closed by authenticating user bob 1.2.3.4 port 9 [preauth]") is None
    assert parse_log_line("Received disconnect from 1.2.3.4 port 9:11: bye [preauth]") is None
    assert parse_log_line("Failed publickey for bob from 1.2.3.4 port 9 ssh2 [preauth]") is None
    assert parse_log_line("Server listening on 0.0.0.0 port 22.") is None
    assert parse_log_line("") is None


def test_parse_tolerates_syslog_prefix():
    event = parse_log_line("Jul 19 12:00:00 bastion sshd[123]: " + ACCEPT_LINE)
    assert event is not None and event["event"] == "accept"


# ---------------------------------------------------------------------------
# DB event application
# ---------------------------------------------------------------------------


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


def _patch_factory(monkeypatch, factory):
    monkeypatch.setattr(core, "get_session_factory", lambda: factory)
    monkeypatch.setattr(session_tracker, "get_session_factory", lambda: factory)


def test_accept_and_close_lifecycle(monkeypatch):
    async def scenario():
        engine, factory = await _make_db()
        _patch_factory(monkeypatch, factory)
        try:
            async with factory() as db:
                db.add(
                    User(
                        username="alice",
                        display_name="Alice",
                        hashed_password=hash_password("password123"),
                        role=UserRole.readonly,
                        totp_enrolled=True,
                    )
                )
                await db.commit()

            await session_tracker.apply_log_event(parse_log_line(ACCEPT_LINE))

            async with factory() as db:
                sessions = (await db.execute(select(SshSession))).scalars().all()
                assert len(sessions) == 1
                s = sessions[0]
                assert s.username == "alice"
                assert s.user_id is not None
                assert s.ended_at is None
                assert s.key_fingerprint == "SHA256:AbCdEf123456"

                audit = (await db.execute(select(AuditLog))).scalars().all()
                assert [a.action for a in audit] == [AuditAction.SESSION_OPENED]

            await session_tracker.apply_log_event(
                parse_log_line("Disconnected from user alice 172.18.0.1 port 51234")
            )
            # A duplicate close line must be a no-op
            await session_tracker.apply_log_event(
                parse_log_line("Received disconnect from 172.18.0.1 port 51234:11: bye")
            )

            async with factory() as db:
                s = (await db.execute(select(SshSession))).scalars().one()
                assert s.ended_at is not None
                assert s.close_reason == "disconnected"
                actions = [a.action for a in (await db.execute(select(AuditLog))).scalars().all()]
                assert actions.count(AuditAction.SESSION_CLOSED) == 1
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_accept_is_idempotent_on_replay(monkeypatch):
    """Re-reading an already-processed accept line must not duplicate rows."""

    async def scenario():
        engine, factory = await _make_db()
        _patch_factory(monkeypatch, factory)
        try:
            event = parse_log_line(ACCEPT_LINE)
            await session_tracker.apply_log_event(event)
            await session_tracker.apply_log_event(event)

            async with factory() as db:
                sessions = (await db.execute(select(SshSession))).scalars().all()
                assert len(sessions) == 1
                audit = (await db.execute(select(AuditLog))).scalars().all()
                assert [a.action for a in audit] == [AuditAction.SESSION_OPENED]
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_resolve_start_offset():
    # No saved state (first run): start at EOF
    assert resolve_start_offset(None, inode=7, size=500) == 500
    # Same file, valid offset: resume (reconciles the API-downtime window)
    assert resolve_start_offset((7, 200), inode=7, size=500) == 200
    # Rotated (different inode): EOF — unbounded replay would fabricate history
    assert resolve_start_offset((6, 200), inode=7, size=500) == 500
    # Truncated below the saved offset: EOF
    assert resolve_start_offset((7, 900), inode=7, size=500) == 500
    # Saved offset at exactly EOF is valid
    assert resolve_start_offset((7, 500), inode=7, size=500) == 500


def test_resolve_start_offset_file_appeared_after_absence():
    # A file that appeared after being missing is brand new: read from 0 so
    # connections accepted before the retry woke up are not dropped
    assert resolve_start_offset(None, inode=7, size=500, appeared_after_absence=True) == 0
    # ...but a matching saved position still wins (restart during the window)
    assert resolve_start_offset((7, 200), inode=7, size=500, appeared_after_absence=True) == 200
    # Stale state from a different file: still read the new file from 0
    assert resolve_start_offset((6, 200), inode=7, size=500, appeared_after_absence=True) == 0


def test_accept_for_unknown_user_still_recorded(monkeypatch):
    async def scenario():
        engine, factory = await _make_db()
        _patch_factory(monkeypatch, factory)
        try:
            await session_tracker.apply_log_event(
                parse_log_line("Accepted publickey for ghost from 10.0.0.9 port 1024 ssh2")
            )
            async with factory() as db:
                s = (await db.execute(select(SshSession))).scalars().one()
                assert s.username == "ghost"
                assert s.user_id is None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_close_stale_open_sessions(monkeypatch):
    async def scenario():
        engine, factory = await _make_db()
        _patch_factory(monkeypatch, factory)
        # No established socket exists for these peers in this test env
        monkeypatch.setattr(session_tracker, "connection_still_established", lambda ip, port: False)
        try:
            async with factory() as db:
                db.add(SshSession(username="alice", source_ip="1.2.3.4", source_port=1))
                db.add(SshSession(username="bob", source_ip="1.2.3.4", source_port=2))
                await db.commit()

            assert await close_stale_open_sessions() == 2
            assert await close_stale_open_sessions() == 0

            async with factory() as db:
                sessions = (await db.execute(select(SshSession))).scalars().all()
                assert all(s.ended_at is not None for s in sessions)
                assert all(s.close_reason == "server_restart" for s in sessions)

                # Each stale closure must be audited like a normal disconnect
                audit = (await db.execute(select(AuditLog))).scalars().all()
                closed = [a for a in audit if a.action == AuditAction.SESSION_CLOSED]
                assert len(closed) == 2
                assert all(a.detail["reason"] == "server_restart" for a in closed)
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_close_stale_keeps_live_connections_open(monkeypatch):
    """API-only restart: sessions with a still-established socket stay open."""

    async def scenario():
        engine, factory = await _make_db()
        _patch_factory(monkeypatch, factory)
        monkeypatch.setattr(
            session_tracker,
            "connection_still_established",
            lambda ip, port: port == 1,  # only alice's connection is still alive
        )
        try:
            async with factory() as db:
                db.add(SshSession(username="alice", source_ip="1.2.3.4", source_port=1))
                db.add(SshSession(username="bob", source_ip="1.2.3.4", source_port=2))
                await db.commit()

            assert await close_stale_open_sessions() == 1

            async with factory() as db:
                sessions = (await db.execute(select(SshSession))).scalars().all()
                by_user = {s.username: s for s in sessions}
                assert by_user["alice"].ended_at is None
                assert by_user["bob"].ended_at is not None
                assert by_user["bob"].close_reason == "server_restart"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# /proc/net/tcp parsing
# ---------------------------------------------------------------------------

# 172.18.0.1 = AC 12 00 01 → little-endian hex 010012AC; port 51234 = 0xC822
_PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0B00007F:0016 010012AC:C822 01 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 20 4 30 10 -1
   2: 0B00007F:0016 010012AC:C823 01 00000000:00000000 00:00000000 00000000     0        0 67891 1 0000000000000000 20 4 30 10 -1
"""


def test_find_socket_inodes_matches_peer():
    assert find_socket_inodes(_PROC_NET_TCP, "172.18.0.1", 51234) == {"67890"}
    assert find_socket_inodes(_PROC_NET_TCP, "172.18.0.1", 51235) == {"67891"}
    assert find_socket_inodes(_PROC_NET_TCP, "172.18.0.2", 51234) == set()


def test_find_socket_inodes_ignores_non_established():
    # Row 0 is LISTEN (0A) with rem 0.0.0.0:0 — never matched
    assert find_socket_inodes(_PROC_NET_TCP, "0.0.0.0", 0) == set()


def test_candidate_hex_addrs_ipv4_and_mapped():
    forms = _candidate_hex_addrs("172.18.0.1", 51234)
    assert "010012AC:C822" in forms  # /proc/net/tcp form
    # IPv4-mapped IPv6 form for /proc/net/tcp6
    assert any(len(f.split(":")[0]) == 32 for f in forms)


def test_candidate_hex_addrs_ipv6():
    forms = _candidate_hex_addrs("::1", 22)
    assert any(len(f.split(":")[0]) == 32 for f in forms)


def test_candidate_hex_addrs_invalid_ip_returns_empty():
    assert _candidate_hex_addrs("not-an-ip", 22) == set()
    assert _candidate_hex_addrs("", 22) == set()
    assert find_socket_inodes(_PROC_NET_TCP, "bad.host.name", 51234) == set()
