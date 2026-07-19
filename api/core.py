import base64
import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import stat as _stat
import struct
import threading
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import pyotp
import qrcode
from sqlalchemy import delete, func, or_, select, update
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_ssh_private_key,
)
import jwt
from jwt.exceptions import PyJWTError as JWTError
import bcrypt
from pydantic_settings import BaseSettings
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from models import (
    AuditAction,
    AuditLog,
    Host,
    RecoveryCode,
    Setting,
    User,
    host_group_hosts,
    host_group_users,
    user_host_assignment,
)

logger = logging.getLogger("callis")


def get_app_version() -> str:
    """Read app version from APP_VERSION env var (injected at Docker build time from the release tag).

    In production, APP_VERSION is set via the --build-arg in the release workflow and baked
    into the image as an ENV. In local dev it falls back to 'dev'.
    """
    return os.environ.get("APP_VERSION", "").strip() or "dev"

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

# Overridable so dev/test environments don't collide with a real /data volume.
_SECRET_KEY_FILE = os.environ.get("CALLIS_SECRET_KEY_FILE", "/data/.secret_key")


def _fix_key_file_permissions(path: str = _SECRET_KEY_FILE) -> None:
    """Ensure the secret key file has 0o600 permissions.

    Logs a warning and continues if the chmod fails (e.g. running outside
    Docker where /data may be on a filesystem that ignores POSIX modes).
    """
    try:
        st = os.stat(path)
        if _stat.S_IMODE(st.st_mode) != 0o600:
            logger.warning("Secret key file %s has loose permissions; fixing.", path)
            os.chmod(path, 0o600)
    except FileNotFoundError:
        pass  # Expected on first run — file doesn't exist yet
    except (PermissionError, OSError) as exc:
        logger.warning("Could not check/fix permissions on %s: %s", path, exc)


def _resolve_secret_key() -> str:
    """Resolve SECRET_KEY: env var → persisted file → auto-generate."""
    # 1. Env var takes precedence — but if a persisted key already exists we
    #    must verify they match to prevent silent key rotation.  This mirrors
    #    the same safety check performed in entrypoint.sh.
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key:
        try:
            with open(_SECRET_KEY_FILE) as f:
                persisted = f.read().strip()
            if persisted and persisted != env_key:
                rotate = os.environ.get("CALLIS_ROTATE_SECRET_KEY", "").strip().lower()
                if rotate != "true":
                    raise ValueError(
                        f"SECRET_KEY env var does not match the persisted key in "
                        f"{_SECRET_KEY_FILE}. Refusing to start. Set "
                        f"CALLIS_ROTATE_SECRET_KEY=true to intentionally rotate "
                        f"the key (this will invalidate all active sessions and "
                        f"stored TOTP secrets)."
                    )
                logger.warning(
                    "CALLIS_ROTATE_SECRET_KEY is set — overwriting persisted key "
                    "in %s with the env var value.", _SECRET_KEY_FILE,
                )
                try:
                    fd = os.open(_SECRET_KEY_FILE, os.O_WRONLY | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w") as fw:
                        fw.write(env_key)
                except (PermissionError, OSError) as exc:
                    logger.warning(
                        "Could not persist rotated key to %s: %s. "
                        "Using env var value in-memory only.",
                        _SECRET_KEY_FILE, exc,
                    )
        except FileNotFoundError:
            pass  # No persisted file yet — env var wins without conflict
        _fix_key_file_permissions()
        return env_key

    # 2. Check persisted file (from previous run or setup wizard)
    try:
        _fix_key_file_permissions()
        with open(_SECRET_KEY_FILE) as f:
            key = f.read().strip()
            if key:
                return key
    except FileNotFoundError:
        pass  # No persisted key yet — will auto-generate below

    # 3. Auto-generate and persist — create with 0o600 from the start to avoid
    #    a brief window where the file is world-readable.
    key = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(_SECRET_KEY_FILE), exist_ok=True)
    except (PermissionError, OSError) as exc:
        logger.warning(
            "Could not create directory %s: %s. "
            "The auto-generated SECRET_KEY will only be held in memory and "
            "will change on next restart. Set the SECRET_KEY env var for "
            "persistence.",
            os.path.dirname(_SECRET_KEY_FILE), exc,
        )
        return key

    try:
        fd = os.open(_SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
    except FileExistsError:
        # Another process beat us to it — use the existing key
        _fix_key_file_permissions()
        with open(_SECRET_KEY_FILE) as f:
            existing = f.read().strip()
        if not existing:
            raise ValueError(f"Secret key file exists at {_SECRET_KEY_FILE} but is empty; remove it and restart.")
        return existing
    except (PermissionError, OSError) as exc:
        logger.warning(
            "Could not write secret key to %s: %s. "
            "The auto-generated SECRET_KEY will only be held in memory and "
            "will change on next restart. Set the SECRET_KEY env var for "
            "persistence.",
            _SECRET_KEY_FILE, exc,
        )
        return key
    logger.info("Auto-generated SECRET_KEY and saved to %s", _SECRET_KEY_FILE)
    return key


class Settings(BaseSettings):
    SECRET_KEY: str = ""
    DATABASE_URL: str = "sqlite+aiosqlite:////data/callis.db"
    SESSION_IDLE_TIMEOUT: int = 1800  # 30 minutes
    SESSION_MAX_LIFETIME: int = 28800  # 8 hours
    MAX_KEYS_PER_USER: int = 5
    AUTH_MODE: str = "local"
    BASE_URL: str = "http://localhost:8080"
    DEV_MODE: bool = False
    HTTPS_ENABLED: bool = False
    TRUSTED_PROXIES: str = "*"
    LOG_LEVEL: str = "info"
    SSH_PORT: int = 2222
    # Bind address for the JSON API. The SvelteKit SSR server on :8080 is the
    # public entrypoint; the API itself stays on loopback inside the container.
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.SECRET_KEY = _resolve_secret_key()
    return settings


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_engine = None
_session_factory = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        kwargs: dict[str, Any] = {}
        if ":memory:" in settings.DATABASE_URL:
            # A pooled in-memory SQLite would give every connection its own
            # empty database; share one connection so tests see a single DB.
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
        _engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEV_MODE,
            **kwargs,
        )
    return _engine


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory


async def get_db():
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# Password hashing (bcrypt, rounds=12, constant-time)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------


def slugify(value: str) -> str:
    """Convert a string to a safe SSH Host alias (lowercase, alphanumeric + hyphens)."""
    slug = value.lower().strip()
    slug = re.sub(r"[^a-z0-9-]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug or "host"


USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
RESERVED_USERNAMES = frozenset({
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "sshd", "guest", "operator", "test",
})


# ---------------------------------------------------------------------------
# Rate limiter (shared instance for app and routers)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

JWT_ALGORITHM = "HS256"


def _get_session_max_lifetime_seconds() -> int:
    """Return session max lifetime in seconds, checking DB cache then env."""
    if _db_settings_cache and "session_max_lifetime" in _db_settings_cache:
        raw_value = _db_settings_cache["session_max_lifetime"]
        try:
            return int(raw_value) * 60
        except (TypeError, ValueError):
            logger.warning(
                "Invalid cached setting for session_max_lifetime: %r; falling back to default",
                raw_value,
            )
    return get_settings().SESSION_MAX_LIFETIME


def _get_session_idle_timeout_seconds() -> int:
    """Return session idle timeout in seconds, checking DB cache then env."""
    if _db_settings_cache and "session_idle_timeout" in _db_settings_cache:
        raw_value = _db_settings_cache["session_idle_timeout"]
        try:
            return int(raw_value) * 60
        except (TypeError, ValueError):
            logger.warning(
                "Invalid cached setting for session_idle_timeout: %r; falling back to default",
                raw_value,
            )
    return get_settings().SESSION_IDLE_TIMEOUT


def create_jwt(user_id: str, session_epoch: int = 0) -> str:
    settings = get_settings()
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=_get_session_max_lifetime_seconds())
    payload = {
        "sub": user_id,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "last_activity": issued_at.isoformat(),
        # Session-revocation epoch: the SessionMiddleware rejects the token if
        # this no longer matches the user's current session_epoch in the DB,
        # so bumping the user's epoch (e.g. on logout) invalidates all their
        # outstanding tokens server-side despite the stateless JWT design.
        "epoch": int(session_epoch),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt_detailed(token: str) -> tuple[dict | None, str]:
    """Decode a session JWT.

    Returns (payload, reason). The payload is the signature-verified claims
    dict, or None when the token cannot be trusted at all. Reasons:
      - "ok": session is valid.
      - "expired": signature valid but the absolute lifetime (exp) or the
        idle timeout has passed — a real session that ended. The payload is
        still returned so callers can attribute the expiry (e.g. audit logs).
      - "invalid": bad signature, malformed token, or unparseable claims.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM],
            options={"verify_exp": False},
        )
    except (JWTError, ValueError, TypeError):
        return None, "invalid"
    try:
        exp = int(payload.get("exp", 0))
        if datetime.now(timezone.utc).timestamp() > exp:
            return payload, "expired"
        # Check idle timeout
        last_activity_str = payload.get("last_activity")
        if last_activity_str:
            last_activity = datetime.fromisoformat(last_activity_str)
            idle = (datetime.now(timezone.utc) - last_activity).total_seconds()
            if idle > _get_session_idle_timeout_seconds():
                return payload, "expired"
    except (ValueError, TypeError):
        return None, "invalid"
    return payload, "ok"


def decode_jwt(token: str) -> dict | None:
    payload, reason = decode_jwt_detailed(token)
    return payload if reason == "ok" else None


def refresh_jwt(token: str) -> str | None:
    """Re-sign JWT with updated last_activity timestamp."""
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])
        payload["last_activity"] = datetime.now(timezone.utc).isoformat()
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# TOTP (pyotp + Fernet encryption at rest)
# ---------------------------------------------------------------------------

def _derive_fernet_key(secret_key: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"callis-totp-encryption",
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))


@lru_cache
def _get_fernet() -> Fernet:
    settings = get_settings()
    key = _derive_fernet_key(settings.SECRET_KEY)
    return Fernet(key)


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def encrypt_totp_secret(secret: str) -> str:
    f = _get_fernet()
    return f.encrypt(secret.encode()).decode()


def decrypt_totp_secret(encrypted: str) -> str:
    f = _get_fernet()
    return f.decrypt(encrypted.encode()).decode()


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    submitted = code.strip()
    valid_format = submitted.isdigit() and len(submitted) == 6
    normalized_code = submitted if valid_format else "000000"

    # Check current and adjacent time steps (±1) for clock skew tolerance
    # Always compare all steps to maintain constant-time behavior
    now = datetime.now(timezone.utc).timestamp()
    matched = False
    for step_offset in (-1, 0, 1):
        expected = totp.at(now + (step_offset * totp.interval))
        matched |= secrets.compare_digest(expected, normalized_code)

    return valid_format and matched


def totp_matching_step(secret: str, code: str) -> int | None:
    """Return the absolute time-step index a valid TOTP code matches, else None.

    Mirrors verify_totp's ±1 skew tolerance and constant-time comparison, but
    returns the matched step index so callers can enforce single-use (replay
    protection) by rejecting a step that was already consumed.
    """
    submitted = code.strip()
    valid_format = submitted.isdigit() and len(submitted) == 6
    normalized_code = submitted if valid_format else "000000"

    totp = pyotp.TOTP(secret)
    now = datetime.now(timezone.utc).timestamp()
    base_step = int(now // totp.interval)
    matched_step: int | None = None
    for step_offset in (-1, 0, 1):
        expected = totp.at(now + (step_offset * totp.interval))
        if secrets.compare_digest(expected, normalized_code):
            matched_step = base_step + step_offset

    return matched_step if valid_format else None


async def consume_totp_step(db: AsyncSession, user_id: str, step: int) -> bool:
    """Atomically claim a TOTP time-step for single-use (durable replay guard).

    Advances ``users.last_totp_step`` to *step* only if it is currently unset or
    below *step*, in a single UPDATE. Returns True if this call won the claim
    (accept), or False if the step was already consumed (replay — reject).

    Because the guard lives in the row, single-use holds across process
    restarts and multiple API workers: concurrent claims of the same step
    serialize on the row, and only the first UPDATE matches the WHERE clause.
    """
    result = await db.execute(
        update(User)
        .where(
            User.id == user_id,
            or_(User.last_totp_step.is_(None), User.last_totp_step < step),
        )
        .values(last_totp_step=step)
    )
    return result.rowcount == 1


def get_totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Callis")


# ---------------------------------------------------------------------------
# 2FA recovery codes
# ---------------------------------------------------------------------------

RECOVERY_CODE_COUNT = 10
# Unambiguous lowercase alphabet (no 0/o/1/l/i): 10 chars ≈ 49 bits of entropy.
_RECOVERY_CODE_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
_RECOVERY_CODE_LENGTH = 10


def generate_recovery_code() -> str:
    """Generate one recovery code, formatted as xxxxx-xxxxx."""
    raw = "".join(secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(_RECOVERY_CODE_LENGTH))
    return f"{raw[:5]}-{raw[5:]}"


def normalize_recovery_code(code: str) -> str:
    """Normalize user input: lowercase, strip whitespace and hyphens."""
    return code.strip().lower().replace("-", "").replace(" ", "")


def hash_recovery_code(code: str) -> str:
    """HMAC-SHA256 digest of a normalized recovery code, keyed by SECRET_KEY.

    Recovery codes are high-entropy random strings (~49 bits), so a fast
    keyed hash is appropriate — offline brute force is infeasible without
    the server key, and the digest column can be indexed for O(1) lookup.
    Passwords must NOT use this; they use bcrypt.
    """
    secret_key = get_settings().SECRET_KEY
    return hmac.new(
        secret_key.encode(),
        f"callis-recovery:{normalize_recovery_code(code)}".encode(),
        hashlib.sha256,
    ).hexdigest()


def looks_like_recovery_code(code: str) -> bool:
    """True if the submitted 2FA value has recovery-code shape (vs 6-digit TOTP).

    Length alone distinguishes the formats: recovery codes normalize to 10
    characters, TOTP codes are 6 digits. All-digit inputs of length 10 must
    still qualify — the generation alphabet contains digits, so an issued
    code can (rarely) be entirely numeric.
    """
    return len(normalize_recovery_code(code)) == _RECOVERY_CODE_LENGTH


async def issue_recovery_codes(db: AsyncSession, user_id: str) -> list[str]:
    """Replace all of a user's recovery codes with a fresh set.

    Returns the plaintext codes — the only time they are ever available.
    Does not commit; the caller owns the transaction.
    """
    await db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
    codes = [generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    for code in codes:
        db.add(RecoveryCode(user_id=user_id, code_digest=hash_recovery_code(code)))
    await db.flush()
    return codes


async def consume_recovery_code(db: AsyncSession, user_id: str, submitted: str) -> bool:
    """Mark a matching unused recovery code as used. Returns True on success.

    Single-use is enforced atomically: the conditional UPDATE re-evaluates
    ``used_at IS NULL`` at commit visibility, so two concurrent logins with
    the same code cannot both succeed on PostgreSQL (SQLite is single-writer
    and safe either way).

    Does not commit; the caller owns the transaction.
    """
    digest = hash_recovery_code(submitted)
    result = await db.execute(
        update(RecoveryCode)
        .where(
            RecoveryCode.user_id == user_id,
            RecoveryCode.code_digest == digest,
            RecoveryCode.used_at.is_(None),
        )
        .values(used_at=datetime.now(timezone.utc))
    )
    return result.rowcount == 1


async def unused_recovery_code_count(db: AsyncSession, user_id: str) -> int:
    result = await db.execute(
        select(func.count())
        .select_from(RecoveryCode)
        .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
    )
    return result.scalar()




def totp_qr_b64(secret: str, username: str) -> str:
    """Render the TOTP provisioning URI as a base64-encoded PNG QR code."""
    uri = get_totp_uri(secret, username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ---------------------------------------------------------------------------
# SSH Key Parsing & Validation
# ---------------------------------------------------------------------------

def parse_ssh_public_key(key_text: str) -> dict:
    """Parse and validate an SSH public key.

    Returns dict with: key_type, fingerprint, public_key_text (cleaned).
    Raises ValueError if invalid or disallowed key type/size.
    """
    key_text = key_text.strip()
    # Reject all ASCII control characters that could inject authorized_keys lines or cause parsing issues
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in key_text):
        raise ValueError("SSH public key must not contain control characters")
    parts = key_text.split()
    if len(parts) < 2:
        raise ValueError("Invalid SSH public key format")

    key_type_str = parts[0]
    key_data_b64 = parts[1]

    try:
        key_data = base64.b64decode(key_data_b64, validate=True)
    except Exception:
        raise ValueError("Invalid base64 in SSH public key")

    # Extract key type from the binary data
    if len(key_data) < 4:
        raise ValueError("SSH key data too short")
    type_len = struct.unpack(">I", key_data[:4])[0]
    if len(key_data) < 4 + type_len:
        raise ValueError("SSH key data truncated")
    embedded_type = key_data[4 : 4 + type_len].decode("ascii", errors="replace")

    if key_type_str not in ("ssh-ed25519", "ssh-rsa"):
        raise ValueError(f"Key type '{key_type_str}' not allowed. Only ssh-ed25519 and ssh-rsa (>= 4096 bit) are accepted.")

    if embedded_type != key_type_str:
        raise ValueError("Key type mismatch between header and data")

    # For RSA, check minimum key size (4096 bits)
    if key_type_str == "ssh-rsa":
        _check_rsa_key_size(key_data, min_bits=4096)

    # Compute SHA-256 fingerprint
    digest = hashlib.sha256(key_data).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode()

    # Reconstruct from parsed tokens to guarantee single-line output
    comment = " ".join(parts[2:]) if len(parts) > 2 else ""
    clean_key = f"{key_type_str} {key_data_b64}" + (f" {comment}" if comment else "")

    return {
        "key_type": key_type_str,
        "fingerprint": fingerprint,
        "public_key_text": clean_key,
    }


def _check_rsa_key_size(key_data: bytes, min_bits: int) -> None:
    """Extract RSA public key size from SSH wire format and check minimum."""
    # Skip key type string
    type_len = struct.unpack(">I", key_data[:4])[0]
    offset = 4 + type_len

    # Read exponent
    if offset + 4 > len(key_data):
        raise ValueError("Truncated RSA key data")
    e_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
    offset += 4 + e_len

    # Read modulus
    if offset + 4 > len(key_data):
        raise ValueError("Truncated RSA key data")
    n_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
    offset += 4
    if offset + n_len > len(key_data):
        raise ValueError("Truncated RSA key data")
    n_bytes = key_data[offset : offset + n_len]

    # Key size in bits (strip leading zero byte from mpint, then use actual bit length)
    if n_bytes and n_bytes[0] == 0:
        n_bytes = n_bytes[1:]
    key_bits = int.from_bytes(n_bytes, "big").bit_length()

    if key_bits < min_bits:
        raise ValueError(f"RSA key is {key_bits} bits, minimum {min_bits} required")


# ---------------------------------------------------------------------------
# SSH Keypair Generation
# ---------------------------------------------------------------------------

def generate_ssh_keypair(comment: str = "") -> tuple[str, str]:
    """Generate an Ed25519 SSH keypair.

    Returns:
        (private_key_openssh: str, public_key_openssh: str)

    The private key is in OpenSSH PEM format.  The public key is a single
    authorized_keys line; an optional comment is appended when provided.
    """
    private_key = Ed25519PrivateKey.generate()
    private_key_text = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.OpenSSH,
        encryption_algorithm=NoEncryption(),
    ).decode()
    public_key_text = private_key.public_key().public_bytes(
        encoding=Encoding.OpenSSH,
        format=PublicFormat.OpenSSH,
    ).decode().rstrip()
    if comment:
        # Strip and reject control characters to ensure the public key line
        # remains a single valid authorized_keys entry.
        comment = comment.strip()
        if any(ord(c) < 32 or ord(c) == 127 for c in comment):
            raise ValueError("SSH key comment must not contain control characters")
        if comment:
            public_key_text = f"{public_key_text} {comment}"
    return private_key_text, public_key_text


_DEPLOY_KEY_PATH = "/data/callis_deploy_key"
_deploy_public_key_cache: str | None = None
# This cache is process-local. In multi-worker deployments, each worker process
# maintains its own copy. The lock below protects concurrent initialisation when
# get_server_deploy_public_key() is offloaded to a thread pool.
_deploy_key_lock = threading.Lock()


def _derive_public_key_from_private_file(priv_path: str, pub_path: str) -> str | None:
    """Load the deploy private key from *priv_path* and return its OpenSSH public key.

    Writes the derived public key to *pub_path* as a side-effect when possible.
    Returns ``None`` if the file is missing; returns ``None`` and logs a warning
    if the file is unreadable or has insecure permissions that cannot be tightened.
    """
    try:
        st = os.stat(priv_path)
        mode = _stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            try:
                os.chmod(priv_path, 0o600)
            except OSError as exc:
                logger.warning(
                    "Deploy private key at %s has insecure permissions %s and could not be tightened: %s",
                    priv_path,
                    oct(mode),
                    exc,
                )
                return None
        with open(priv_path, "rb") as f:
            priv_bytes = f.read()
        priv = load_ssh_private_key(priv_bytes, password=None)
        pub_text = priv.public_key().public_bytes(
            encoding=Encoding.OpenSSH,
            format=PublicFormat.OpenSSH,
        ).decode().strip()
        try:
            parse_ssh_public_key(pub_text)
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Derived public key from %s is not a valid SSH public key; "
                "falling back to generating a fresh keypair: %s",
                priv_path,
                exc,
            )
            return None
        # Validation passed — persist and return the derived public key.
        try:
            with open(pub_path, "w") as fh:
                fh.write(pub_text + "\n")
        except OSError as exc:
            logger.warning("Could not write deploy public key to %s: %s", pub_path, exc)
        return pub_text
    except FileNotFoundError:
        return None
    except Exception as exc:
        logger.warning("Could not load deploy private key at %s: %s", priv_path, exc)
        return None


def get_server_deploy_public_key() -> str:
    """Return Callis's server deploy public key, generating it if needed.

    The keypair is persisted to /data/callis_deploy_key[.pub].  Returns the
    OpenSSH public key as a single-line string, or an empty string if the key
    cannot be generated (e.g. /data is not writable in dev without Docker).

    **Blocking:** this function performs synchronous disk I/O (stat, open, read,
    chmod, and possibly key generation and file writes).  It must not be called
    directly from async request handlers.  Call it at application startup (e.g.
    in the FastAPI ``lifespan`` function) or offload it to a thread pool::

        import anyio
        key = await anyio.to_thread.run_sync(get_server_deploy_public_key)

    The result is cached in memory after the first call so that subsequent
    calls return immediately without any I/O.  Persistent failures (e.g.
    /data is not writable) are also cached as an empty string so that callers
    do not repeatedly retry expensive I/O on every request.
    """
    global _deploy_public_key_cache
    # Lock-free fast path — avoids acquiring the lock on every call once cached.
    if _deploy_public_key_cache is not None:
        return _deploy_public_key_cache

    with _deploy_key_lock:
        # Re-check inside the lock to handle concurrent first-call racing.
        if _deploy_public_key_cache is not None:
            return _deploy_public_key_cache

        priv_path = _DEPLOY_KEY_PATH
        pub_path = priv_path + ".pub"

        # Fast path: public key file already exists.
        try:
            with open(pub_path) as f:
                first_line = f.readline().strip()
            if first_line:
                try:
                    parse_ssh_public_key(first_line)
                except (TypeError, ValueError):
                    logger.warning(
                        "Deploy public key file %s is not a valid SSH public key; ignoring.",
                        pub_path,
                    )
                else:
                    _deploy_public_key_cache = first_line
                    return _deploy_public_key_cache
        except FileNotFoundError:
            # Missing public key file is expected on first run; derive or generate it below.
            pass
        except OSError as exc:
            logger.warning(
                "Could not read deploy public key at %s: %s; "
                "falling through to derive/generate.",
                pub_path, exc,
            )
            # Fall through to deriving from the private key or generating a new keypair.

        # Private key exists but public key file is missing or unreadable — derive it.
        pub_text = _derive_public_key_from_private_file(priv_path, pub_path)
        if pub_text is not None:
            _deploy_public_key_cache = pub_text
            return pub_text

        # Generate a fresh keypair and persist it.
        private_key_text, public_key_text = generate_ssh_keypair(comment="callis@deploy")
        public_key_text = public_key_text.strip()
        try:
            os.makedirs(os.path.dirname(priv_path), exist_ok=True)
        except (OSError, ValueError) as exc:
            logger.warning("Could not create directory for deploy key at %s: %s", priv_path, exc)
        try:
            fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(private_key_text)
        except FileExistsError:
            # File was created between our check and the open call (e.g. by another
            # process on first startup). Try to read the key they persisted; fall
            # back to deriving it from the private key file.
            try:
                with open(pub_path) as f:
                    first_line = f.readline().strip()
                if first_line:
                    try:
                        parse_ssh_public_key(first_line)
                    except (TypeError, ValueError):
                        logger.warning(
                            "Deploy public key file %s is not a valid SSH public key after concurrent creation; ignoring.",
                            pub_path,
                        )
                    else:
                        _deploy_public_key_cache = first_line
                        return _deploy_public_key_cache
            except FileNotFoundError:
                # Public key file was not found after concurrent creation attempt;
                # fall back to deriving it from the private key file below.
                logger.debug(
                    "Deploy public key file %s not found after concurrent creation attempt.",
                    pub_path,
                )
            except OSError as exc:
                logger.warning(
                    "Could not read deploy public key at %s after concurrent creation: %s",
                    pub_path, exc,
                )

            derived = _derive_public_key_from_private_file(priv_path, pub_path)
            if derived is not None:
                _deploy_public_key_cache = derived
                return _deploy_public_key_cache

            logger.warning(
                "Could not recover deploy public key after concurrent creation at %s; "
                "returning empty string. Cache left unset so the next call can retry.",
                priv_path,
            )
            return ""
        except (PermissionError, OSError) as exc:
            logger.warning(
                "Could not persist server deploy key to %s: %s. "
                "Returning empty string because the generated key is not durable.",
                priv_path,
                exc,
            )
            _deploy_public_key_cache = ""
            return ""
        try:
            with open(pub_path, "w") as f:
                f.write(public_key_text + "\n")
        except (PermissionError, OSError) as exc:
            logger.warning("Could not write deploy public key to %s: %s", pub_path, exc)
        logger.info("Generated Callis server deploy key and saved to %s", priv_path)
        _deploy_public_key_cache = public_key_text
        return public_key_text


# ---------------------------------------------------------------------------
# Effective host access (direct assignments ∪ group memberships)
# ---------------------------------------------------------------------------

async def get_effective_hosts(db: AsyncSession, user_id: str) -> list[Host]:
    """Active hosts a user may reach: direct assignments plus host groups.

    This is the single source of truth for host access — used by the
    internal API (permitopen construction, tag resolution, and host
    listing) and the web UI, so they can never disagree.
    """
    direct_ids = select(user_host_assignment.c.host_id).where(
        user_host_assignment.c.user_id == user_id
    )
    group_ids = (
        select(host_group_hosts.c.host_id)
        .join(
            host_group_users,
            host_group_users.c.group_id == host_group_hosts.c.group_id,
        )
        .where(host_group_users.c.user_id == user_id)
    )
    result = await db.execute(
        select(Host)
        .where(
            Host.is_active == True,  # noqa: E712
            Host.id.in_(direct_ids.union(group_ids)),
        )
        .order_by(Host.label)
    )
    return result.scalars().all()


# ---------------------------------------------------------------------------
# Audit logging (append-only)
# ---------------------------------------------------------------------------

async def write_audit_log(
    db: AsyncSession,
    *,
    actor_id: str | None,
    action: AuditAction,
    target_type: str | None = None,
    target_id: str | None = None,
    source_ip: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        source_ip=source_ip,
        detail=detail,
    )
    db.add(entry)
    await db.flush()


# ---------------------------------------------------------------------------
# Runtime-configurable settings (DB-backed, env vars as fallback)
# ---------------------------------------------------------------------------

CONFIGURABLE_SETTINGS: dict[str, dict] = OrderedDict([
    # -- Branding --
    ("instance_name",        {"type": "str",    "default": "Callis",              "label": "Instance Name",                "group": "Branding",  "help": "Displayed in the navigation bar and page titles."}),
    ("motd",                 {"type": "text",   "default": "",                    "label": "Login Banner Message",         "group": "Branding",  "help": "Shown on the login page. Supports plain text."}),
    # -- Security --
    ("session_idle_timeout", {"type": "int",    "default": 30,                    "label": "Session Idle Timeout (min)",   "group": "Security",  "help": "Minutes of inactivity before a session expires.", "min": 5, "max": 1440}),
    ("session_max_lifetime", {"type": "int",    "default": 480,                   "label": "Session Max Lifetime (min)",   "group": "Security",  "help": "Maximum session duration regardless of activity.", "min": 15, "max": 10080}),
    ("max_keys_per_user",    {"type": "int",    "default": 5,                     "label": "Max SSH Keys Per User",        "group": "Security",  "help": "Maximum number of active SSH keys a user can have.", "min": 1, "max": 50}),
    ("password_min_length",  {"type": "int",    "default": 8,                     "label": "Minimum Password Length",      "group": "Security",  "help": "Minimum characters required for new passwords.", "min": 8, "max": 128}),
    # -- General --
    ("base_url",             {"type": "str",    "default": "http://localhost:8080","label": "Base URL",                     "group": "General",   "help": "Public URL of this Callis instance. Used in CLI installer and SSH config."}),
    ("ssh_port",             {"type": "int",    "default": 2222,                  "label": "SSH Port",                     "group": "General",   "help": "Configured at container level. Displayed here for reference.", "readonly": True}),
    ("log_level",            {"type": "choice", "default": "info",                "label": "Log Level",                    "group": "General",   "help": "Server log verbosity. Requires restart to take effect.", "choices": ["debug", "info", "warning", "error"], "readonly": True}),
])


# In-memory cache for DB settings; updated in place on save.
_db_settings_cache: dict[str, str] | None = None


async def load_db_settings() -> dict[str, str]:
    """Load all settings from the database, using cache if available.

    Note: this is an in-process cache. In multi-worker deployments, settings
    saved by one worker are not propagated to other workers until their cache
    is next populated (i.e., after a restart or a cache miss). For single-
    worker/container deployments (the default Callis setup) this is correct.
    """
    global _db_settings_cache
    if _db_settings_cache is not None:
        return _db_settings_cache
    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(select(Setting))
        rows = result.scalars().all()
    _db_settings_cache = {row.key: row.value for row in rows}
    return _db_settings_cache


def invalidate_db_settings_cache() -> None:
    global _db_settings_cache
    _db_settings_cache = None


def update_db_settings_cache(
    upserts: dict[str, str],
    deletes: list[str],
) -> None:
    """Apply committed save mutations directly to the in-memory cache.

    Called after db.commit() in save_settings() so that the post-save
    template render (and any concurrent requests) see the new values
    immediately, while also ensuring the cache is never repopulated from
    stale pre-commit DB state during the save.
    """
    global _db_settings_cache
    if _db_settings_cache is None:
        # Cache was invalidated before save completed; next load_db_settings()
        # call will repopulate from the committed DB state, so this is safe.
        logger.debug("update_db_settings_cache called with empty cache; skipping in-place update")
        return
    for key in deletes:
        _db_settings_cache.pop(key, None)
    _db_settings_cache.update(upserts)


def get_effective_settings(db_settings: dict[str, str]) -> dict[str, Any]:
    """Merge DB overrides on top of env-var / default values."""
    env = get_settings()
    result: dict[str, Any] = {}
    for key, meta in CONFIGURABLE_SETTINGS.items():
        # Never apply DB overrides to read-only settings (configured at container
        # level via env vars; the DB row, if it exists, is ignored for correctness).
        use_db_value = not meta.get("readonly") and key in db_settings
        if use_db_value:
            raw = db_settings[key]
            if meta["type"] == "int":
                try:
                    result[key] = int(raw)
                except (TypeError, ValueError):
                    logger.warning(
                        "Ignoring invalid integer DB override for setting '%s': %r",
                        key,
                        raw,
                    )
                    use_db_value = False
            else:
                result[key] = raw

        if not use_db_value:
            # Fall back to env-var-based Settings object if it has this attr
            env_attr = key.upper()
            if hasattr(env, env_attr):
                val = getattr(env, env_attr)
                # Convert seconds to minutes for the UI fields
                if key == "session_idle_timeout":
                    val = val // 60
                elif key == "session_max_lifetime":
                    val = val // 60
                result[key] = val
            else:
                result[key] = meta["default"]
    return result


async def get_ssh_host() -> str:
    """Hostname users should SSH to, derived from the effective base_url setting."""
    base_url = await get_runtime_setting("base_url") or ""
    return urlparse(base_url).hostname or "localhost"


async def get_runtime_setting(key: str) -> Any:
    """Get a single runtime setting value using a fast single-key path.

    Reads from the in-memory cache (populated by load_db_settings at startup
    and updated in-place after each settings save via update_db_settings_cache)
    and only resolves the requested key, avoiding a full iteration over
    CONFIGURABLE_SETTINGS on every call.  Read-only settings always return
    the env-var / compiled default regardless of any DB row.
    """
    meta = CONFIGURABLE_SETTINGS.get(key)
    if meta is None:
        return None

    db_settings = await load_db_settings()

    if not meta.get("readonly") and key in db_settings:
        raw = db_settings[key]
        if meta["type"] == "int":
            try:
                return int(raw)
            except (TypeError, ValueError):
                logger.warning(
                    "Ignoring invalid integer DB override for setting '%s': %r",
                    key,
                    raw,
                )
        else:
            return raw

    # Fall back to env-var attribute or compiled default
    env = get_settings()
    env_attr = key.upper()
    if hasattr(env, env_attr):
        val = getattr(env, env_attr)
        if key == "session_idle_timeout":
            val = val // 60
        elif key == "session_max_lifetime":
            val = val // 60
        return val
    return meta["default"]
