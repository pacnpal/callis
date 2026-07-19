from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pyotp

import core
from core import (
    JWT_ALGORITHM,
    create_jwt,
    decode_jwt,
    decode_jwt_detailed,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    get_settings,
    hash_password,
    verify_password,
    verify_totp,
)


def test_password_hash_roundtrip():
    hashed = hash_password("hunter2secret")
    assert hashed != "hunter2secret"
    assert verify_password("hunter2secret", hashed)
    assert not verify_password("wrong", hashed)


def test_totp_secret_encryption_roundtrip():
    secret = generate_totp_secret()
    encrypted = encrypt_totp_secret(secret)
    assert encrypted != secret
    assert decrypt_totp_secret(encrypted) == secret


def test_verify_totp_accepts_current_code():
    secret = generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert verify_totp(secret, code)
    assert verify_totp(secret, f"  {code}  ")  # whitespace tolerated


def test_verify_totp_accepts_adjacent_window():
    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret)
    now = datetime.now(timezone.utc).timestamp()
    assert verify_totp(secret, totp.at(now - totp.interval))
    assert verify_totp(secret, totp.at(now + totp.interval))


def test_verify_totp_rejects_bad_input():
    secret = generate_totp_secret()
    assert not verify_totp(secret, "000000") or pyotp.TOTP(secret).now() == "000000"
    assert not verify_totp(secret, "")
    assert not verify_totp(secret, "12345")     # too short
    assert not verify_totp(secret, "abcdef")    # not digits
    assert not verify_totp(secret, "1234567")   # too long


def test_jwt_roundtrip():
    token = create_jwt("user-123")
    payload = decode_jwt(token)
    assert payload is not None
    assert payload["sub"] == "user-123"


def test_jwt_tampered_token_invalid():
    token = create_jwt("user-123")
    payload, reason = decode_jwt_detailed(token + "x")
    assert payload is None
    assert reason == "invalid"
    assert decode_jwt(token + "x") is None


def test_jwt_wrong_key_invalid():
    token = pyjwt.encode({"sub": "user-123"}, "b" * 64, algorithm=JWT_ALGORITHM)
    payload, reason = decode_jwt_detailed(token)
    assert payload is None
    assert reason == "invalid"


def _make_token(*, exp_delta: timedelta, last_activity_delta: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "iat": int(now.timestamp()),
        "exp": int((now + exp_delta).timestamp()),
        "last_activity": (now + last_activity_delta).isoformat(),
    }
    return pyjwt.encode(payload, get_settings().SECRET_KEY, algorithm=JWT_ALGORITHM)


def test_jwt_absolute_expiry_reported_as_expired():
    token = _make_token(exp_delta=timedelta(seconds=-10), last_activity_delta=timedelta(0))
    payload, reason = decode_jwt_detailed(token)
    assert reason == "expired"
    assert payload is not None and payload["sub"] == "user-123"
    assert decode_jwt(token) is None


def test_jwt_idle_timeout_reported_as_expired():
    idle_limit = core._get_session_idle_timeout_seconds()
    token = _make_token(
        exp_delta=timedelta(hours=1),
        last_activity_delta=timedelta(seconds=-(idle_limit + 60)),
    )
    payload, reason = decode_jwt_detailed(token)
    assert reason == "expired"
    assert payload is not None
    assert decode_jwt(token) is None
