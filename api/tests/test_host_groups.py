import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from core import get_effective_hosts, hash_password
from models import Base, Host, HostGroup, User, UserRole


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


def _user(username: str) -> User:
    return User(
        username=username,
        display_name=username,
        hashed_password=hash_password("password123"),
        role=UserRole.readonly,
        totp_enrolled=True,
    )


def test_effective_hosts_union_of_direct_and_group():
    async def scenario():
        engine, factory = await _make_db()
        try:
            async with factory() as db:
                alice = _user("alice")
                direct_host = Host(label="Direct", hostname="direct.internal", port=22)
                group_host = Host(label="Grouped", hostname="grouped.internal", port=22)
                both_host = Host(label="Both", hostname="both.internal", port=22)
                other_host = Host(label="Other", hostname="other.internal", port=22)

                alice.assigned_hosts.append(direct_host)
                alice.assigned_hosts.append(both_host)

                group = HostGroup(name="prod")
                group.hosts.extend([group_host, both_host])
                group.users.append(alice)

                db.add_all([alice, direct_host, group_host, both_host, other_host, group])
                await db.commit()

                hosts = await get_effective_hosts(db, alice.id)
                labels = sorted(h.label for h in hosts)
                # Union without duplicates; unassigned host excluded
                assert labels == ["Both", "Direct", "Grouped"]
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_effective_hosts_excludes_inactive_hosts():
    async def scenario():
        engine, factory = await _make_db()
        try:
            async with factory() as db:
                alice = _user("alice")
                inactive_direct = Host(label="Old Direct", hostname="a.internal", port=22, is_active=False)
                inactive_grouped = Host(label="Old Grouped", hostname="b.internal", port=22, is_active=False)
                alice.assigned_hosts.append(inactive_direct)
                group = HostGroup(name="stale")
                group.hosts.append(inactive_grouped)
                group.users.append(alice)
                db.add_all([alice, inactive_direct, inactive_grouped, group])
                await db.commit()

                assert await get_effective_hosts(db, alice.id) == []
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_effective_hosts_isolated_between_users():
    async def scenario():
        engine, factory = await _make_db()
        try:
            async with factory() as db:
                alice = _user("alice")
                bob = _user("bob")
                host = Host(label="Prod Web", hostname="web.internal", port=22)
                group = HostGroup(name="prod")
                group.hosts.append(host)
                group.users.append(alice)
                db.add_all([alice, bob, host, group])
                await db.commit()

                assert [h.label for h in await get_effective_hosts(db, alice.id)] == ["Prod Web"]
                assert await get_effective_hosts(db, bob.id) == []
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_group_deletion_revokes_group_access():
    async def scenario():
        engine, factory = await _make_db()
        try:
            async with factory() as db:
                alice = _user("alice")
                host = Host(label="Prod Web", hostname="web.internal", port=22)
                group = HostGroup(name="prod")
                group.hosts.append(host)
                group.users.append(alice)
                db.add_all([alice, host, group])
                await db.commit()

                assert len(await get_effective_hosts(db, alice.id)) == 1
                await db.delete(group)
                await db.commit()
                assert await get_effective_hosts(db, alice.id) == []
        finally:
            await engine.dispose()

    asyncio.run(scenario())
