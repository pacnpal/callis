import base64
import hashlib
import logging
import os
import re
import secrets
import stat as _stat
import struct
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

import pyotp
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic_settings import BaseSettings
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from models import AuditAction, AuditLog

logger = logging.getLogger("callis")


def get_app_version() -> str:
    """Read app version from APP_VERSION env var (set by Docker) or .version file."""
    import os
    v = os.environ.get("APP_VERSION", "").strip()
    if v and v != "dev":
        return v
    # Check sibling path first (works in Docker where core.py and .version are both in /app/)
    # then parent path (works in local dev where core.py is in api/ and .version is at repo root)
    for rel in (".", ".."):
        try:
            with open(os.path.join(os.path.dirname(__file__), rel, ".version")) as f:
                return f.read().strip()
        except FileNotFoundError:
            continue
    return "dev"

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

_SECRET_KEY_FILE = "/data/.secret_key"


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
        pass

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
    LOG_LEVEL: str = "info"
    SSH_PORT: int = 2222

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
        _engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEV_MODE,
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

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


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


def register_template_filters(jinja_templates) -> None:
    """Register custom Jinja2 filters and globals on a Templates instance."""
    jinja_templates.env.filters["slugify"] = slugify
    jinja_templates.env.globals["app_version"] = get_app_version()


# ---------------------------------------------------------------------------
# Rate limiter (shared instance for app and routers)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

JWT_ALGORITHM = "HS256"


def create_jwt(user_id: str) -> str:
    settings = get_settings()
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=settings.SESSION_MAX_LIFETIME)
    payload = {
        "sub": user_id,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "last_activity": issued_at.isoformat(),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict | None:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])
        # Check idle timeout
        last_activity_str = payload.get("last_activity")
        if last_activity_str:
            last_activity = datetime.fromisoformat(last_activity_str)
            idle = (datetime.now(timezone.utc) - last_activity).total_seconds()
            if idle > settings.SESSION_IDLE_TIMEOUT:
                return None
        return payload
    except (JWTError, ValueError, TypeError):
        return None


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


def get_totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Callis")


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
    offset = 4  # skip type length prefix
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
