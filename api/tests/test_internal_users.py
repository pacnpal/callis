"""Tests for the internal /internal/users endpoint used by the sshd-side
account reconciler (user-sync.sh) to pre-create OS accounts."""

import hashlib
import hmac

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import core
from models import Base, SSHKey, User
from routers.internal import internal_app


def _internal_secret() -> str:
    # conftest sets SECRET_KEY = "a" * 64; derive the secret the same way the
    # middleware does (HMAC-SHA256 of "callis-internal" keyed by SECRET_KEY).
    return hmac.new(b"a" * 64, b"callis-internal", hashlib.sha256).hexdigest()


@pytest_asyncio.fixture
async def internal_client():
    engine = core.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    transport = ASGITransport(app=internal_app)
    async with AsyncClient(transport=transport, base_url="http://internal") as c:
        yield c


async def _add_user_with_key(username: str, *, user_active: bool = True, key_active: bool = True) -> None:
    factory = core.get_session_factory()
    async with factory() as db:
        user = User(username=username, hashed_password="x", is_active=user_active)
        db.add(user)
        await db.flush()
        db.add(
            SSHKey(
                user_id=user.id,
                label="test",
                public_key_text="ssh-ed25519 AAAA",
                fingerprint=f"SHA256:{username}",
                key_type="ssh-ed25519",
                is_active=key_active,
            )
        )
        await db.commit()


@pytest.mark.asyncio
async def test_list_users_requires_internal_secret(internal_client):
    r = await internal_client.get("/internal/users")
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_list_users_returns_only_active_key_holders(internal_client):
    await _add_user_with_key("alice")
    await _add_user_with_key("bob", key_active=False)      # inactive key -> excluded
    await _add_user_with_key("carol", user_active=False)   # inactive user -> excluded
    await _add_user_with_key("dave")                       # no keys? -> has a key, included

    r = await internal_client.get(
        "/internal/users", headers={"X-Internal-Secret": _internal_secret()}
    )
    assert r.status_code == 200
    names = set(r.text.split())
    assert names == {"alice", "dave"}


@pytest.mark.asyncio
async def test_list_users_empty(internal_client):
    r = await internal_client.get(
        "/internal/users", headers={"X-Internal-Secret": _internal_secret()}
    )
    assert r.status_code == 200
    assert r.text.strip() == ""
