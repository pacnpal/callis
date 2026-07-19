import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class UserRole(str, enum.Enum):
    admin = "admin"
    operator = "operator"
    readonly = "readonly"


class AuditAction(str, enum.Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOTP_SETUP = "totp_setup"
    TOTP_FAILURE = "totp_failure"
    RECOVERY_CODE_USED = "recovery_code_used"
    RECOVERY_CODES_GENERATED = "recovery_codes_generated"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    SESSION_TERMINATED = "session_terminated"
    KEY_ADDED = "key_added"
    KEY_REVOKED = "key_revoked"
    KEY_USED = "key_used"
    USER_CREATED = "user_created"
    USER_DEACTIVATED = "user_deactivated"
    USER_ACTIVATED = "user_activated"
    USER_DELETED = "user_deleted"
    USER_ROLE_CHANGED = "user_role_changed"
    HOST_CREATED = "host_created"
    HOST_DEACTIVATED = "host_deactivated"
    HOST_DELETED = "host_deleted"
    HOST_ASSIGNED = "host_assigned"
    HOST_UNASSIGNED = "host_unassigned"
    GROUP_CREATED = "group_created"
    GROUP_DELETED = "group_deleted"
    GROUP_HOST_ADDED = "group_host_added"
    GROUP_HOST_REMOVED = "group_host_removed"
    GROUP_USER_ADDED = "group_user_added"
    GROUP_USER_REMOVED = "group_user_removed"
    SETTINGS_CHANGED = "settings_changed"


user_host_assignment = Table(
    "user_host_assignment",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("host_id", String(36), ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True),
)

host_group_hosts = Table(
    "host_group_hosts",
    Base.metadata,
    Column("group_id", String(36), ForeignKey("host_groups.id", ondelete="CASCADE"), primary_key=True),
    Column("host_id", String(36), ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True),
)

host_group_users = Table(
    "host_group_users",
    Base.metadata,
    Column("group_id", String(36), ForeignKey("host_groups.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)


class HostGroup(Base):
    """A named set of hosts assignable to users as a unit.

    A user's effective host access is the union of their direct host
    assignments and the hosts of every group they belong to (see
    core.get_effective_hosts — the single source of truth used by the
    internal API for permitopen enforcement, resolve, and list).
    """

    __tablename__ = "host_groups"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text, nullable=True, default="")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    hosts = relationship("Host", secondary=host_group_hosts, back_populates="groups")
    users = relationship("User", secondary=host_group_users, back_populates="host_groups")


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    username = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=False, default="")
    email = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    totp_secret = Column(Text, nullable=True)  # Fernet-encrypted
    totp_enrolled = Column(Boolean, default=False, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.readonly, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    # Bumped to invalidate all of this user's outstanding session JWTs (which
    # embed the epoch at issue time) — e.g. on logout. See core.create_jwt.
    session_epoch = Column(Integer, default=0, server_default="0", nullable=False)
    # Highest TOTP time-step consumed at login. An atomic compare-and-set on
    # this column enforces single-use of a TOTP code across workers and
    # restarts (durable replay protection). See core.consume_totp_step.
    last_totp_step = Column(BigInteger, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    ssh_keys = relationship("SSHKey", back_populates="user", cascade="all, delete-orphan")
    assigned_hosts = relationship("Host", secondary=user_host_assignment, back_populates="assigned_users")
    recovery_codes = relationship("RecoveryCode", back_populates="user", cascade="all, delete-orphan")
    host_groups = relationship("HostGroup", secondary=host_group_users, back_populates="users")


class SSHKey(Base):
    __tablename__ = "ssh_keys"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    label = Column(String(255), nullable=False)
    public_key_text = Column(Text, nullable=False)
    fingerprint = Column(String(255), nullable=False)
    key_type = Column(String(50), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="ssh_keys")


class RecoveryCode(Base):
    """Single-use 2FA recovery code.

    Codes are stored as HMAC-SHA256 digests keyed by SECRET_KEY (see
    core.hash_recovery_code) — codes are high-entropy random strings, so a
    fast keyed hash is appropriate and allows indexed lookup, unlike
    passwords which need bcrypt.
    """

    __tablename__ = "recovery_codes"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_digest = Column(String(64), nullable=False, index=True)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user = relationship("User", back_populates="recovery_codes")


class Host(Base):
    __tablename__ = "hosts"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    label = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    port = Column(Integer, default=22, nullable=False)
    description = Column(Text, nullable=True, default="")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    assigned_users = relationship("User", secondary=user_host_assignment, back_populates="assigned_hosts")
    groups = relationship("HostGroup", secondary=host_group_hosts, back_populates="hosts")


class SshSession(Base):
    """An SSH connection through the bastion, tracked from the sshd log.

    Rows are created/closed by session_tracker as sshd logs authentication
    accepts and disconnects. username is stored denormalized so the record
    survives user deletion (user_id is SET NULL).
    """

    __tablename__ = "ssh_sessions"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username = Column(String(255), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False)
    source_port = Column(Integer, nullable=False)
    key_fingerprint = Column(String(255), nullable=True)
    started_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    ended_at = Column(DateTime(timezone=True), nullable=True, index=True)
    close_reason = Column(String(50), nullable=True)  # disconnected | terminated | server_restart

    user = relationship("User", foreign_keys=[user_id])


class SessionTrackerState(Base):
    """Single-row bookkeeping for the sshd log follower.

    Stores the last fully processed log position so an API restart resumes
    where it stopped and reconciles sessions accepted while the API was
    down (sshd keeps running under supervisord during api restarts).
    """

    __tablename__ = "session_tracker_state"

    # BigInteger: inodes and file offsets are 64-bit values; PostgreSQL's
    # Integer is signed 32-bit and would overflow on large logs/inodes.
    id = Column(Integer, primary_key=True, default=1)
    log_inode = Column(BigInteger, nullable=True)
    log_offset = Column(BigInteger, nullable=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    actor_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(Enum(AuditAction), nullable=False, index=True)
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(36), nullable=True)
    source_ip = Column(String(45), nullable=True)
    detail = Column(JSON, nullable=True)

    actor = relationship("User", foreign_keys=[actor_id])


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
