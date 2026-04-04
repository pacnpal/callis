import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
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


user_host_assignment = Table(
    "user_host_assignment",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("host_id", String(36), ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True),
)


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
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    ssh_keys = relationship("SSHKey", back_populates="user", cascade="all, delete-orphan")
    assigned_hosts = relationship("Host", secondary=user_host_assignment, back_populates="assigned_users")


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
