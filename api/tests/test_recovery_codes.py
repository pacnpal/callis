import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from core import (
    RECOVERY_CODE_COUNT,
    consume_recovery_code,
    generate_recovery_code,
    hash_password,
    hash_recovery_code,
    issue_recovery_codes,
    looks_like_recovery_code,
    normalize_recovery_code,
    unused_recovery_code_count,
)
from models import Base, RecoveryCode, User, UserRole


def test_generate_recovery_code_format():
    for _ in range(50):
        code = generate_recovery_code()
        assert len(code) == 11
        assert code[5] == "-"
        normalized = normalize_recovery_code(code)
        assert len(normalized) == 10
        # No ambiguous characters
        for ch in normalized:
            assert ch in "23456789abcdefghjkmnpqrstuvwxyz"


def test_generate_recovery_codes_unique():
    codes = {generate_recovery_code() for _ in range(100)}
    assert len(codes) == 100


def test_normalize_recovery_code():
    assert normalize_recovery_code("  AbCd2-34567 ") == "abcd234567"
    assert normalize_recovery_code("abcd2 34567") == "abcd234567"


def test_hash_recovery_code_ignores_formatting():
    code = generate_recovery_code()
    assert hash_recovery_code(code) == hash_recovery_code(code.replace("-", "").upper())
    assert hash_recovery_code(code) != hash_recovery_code(generate_recovery_code())
    assert len(hash_recovery_code(code)) == 64  # hex SHA-256


def test_looks_like_recovery_code():
    assert looks_like_recovery_code(generate_recovery_code())
    assert looks_like_recovery_code("abcd2-34567")
    # The alphabet contains digits, so a (rare) all-numeric issued code
    # must still be recognized — length alone distinguishes it from TOTP.
    assert looks_like_recovery_code("23456-78923")
    assert not looks_like_recovery_code("123456")       # TOTP code
    assert not looks_like_recovery_code("")
    assert not looks_like_recovery_code("abc")           # too short


def _run(coro):
    return asyncio.run(coro)


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _make_user(db) -> User:
    user = User(
        username="alice",
        display_name="Alice",
        hashed_password=hash_password("password123"),
        role=UserRole.admin,
        totp_enrolled=True,
    )
    db.add(user)
    await db.flush()
    return user


def test_issue_and_consume_recovery_code():
    async def scenario():
        engine, factory = await _make_db()
        try:
            async with factory() as db:
                user = await _make_user(db)
                codes = await issue_recovery_codes(db, user.id)
                assert len(codes) == RECOVERY_CODE_COUNT
                assert await unused_recovery_code_count(db, user.id) == RECOVERY_CODE_COUNT

                # Wrong code fails, right code succeeds exactly once
                assert not await consume_recovery_code(db, user.id, "zzzzz-zzzzz")
                assert await consume_recovery_code(db, user.id, codes[0])
                assert not await consume_recovery_code(db, user.id, codes[0])
                assert await unused_recovery_code_count(db, user.id) == RECOVERY_CODE_COUNT - 1

                # Formatting-insensitive consumption
                assert await consume_recovery_code(db, user.id, codes[1].replace("-", "").upper())
        finally:
            await engine.dispose()

    _run(scenario())


def test_reissue_invalidates_old_codes():
    async def scenario():
        engine, factory = await _make_db()
        try:
            async with factory() as db:
                user = await _make_user(db)
                old_codes = await issue_recovery_codes(db, user.id)
                new_codes = await issue_recovery_codes(db, user.id)

                assert await unused_recovery_code_count(db, user.id) == RECOVERY_CODE_COUNT
                assert not await consume_recovery_code(db, user.id, old_codes[0])
                assert await consume_recovery_code(db, user.id, new_codes[0])

                # Only the new set exists in the DB
                result = await db.execute(select(RecoveryCode).where(RecoveryCode.user_id == user.id))
                assert len(result.scalars().all()) == RECOVERY_CODE_COUNT
        finally:
            await engine.dispose()

    _run(scenario())


def test_codes_are_stored_hashed():
    async def scenario():
        engine, factory = await _make_db()
        try:
            async with factory() as db:
                user = await _make_user(db)
                codes = await issue_recovery_codes(db, user.id)
                result = await db.execute(select(RecoveryCode))
                stored = {rc.code_digest for rc in result.scalars().all()}
                for code in codes:
                    assert code not in stored
                    assert normalize_recovery_code(code) not in stored
                    assert hash_recovery_code(code) in stored
        finally:
            await engine.dispose()

    _run(scenario())
