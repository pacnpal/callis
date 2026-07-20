"""Pydantic schemas for the /api/v1 JSON API.

The FastAPI backend is the single source of truth: every value the web UI
renders is produced here from the ORM models. The SvelteKit SSR frontend is a
pure view layer over these schemas and performs no business logic of its own.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core import slugify
from models import AuditLog, Host, HostGroup, SSHKey, SshSession, User

# ---------------------------------------------------------------------------
# Users & keys
# ---------------------------------------------------------------------------


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    display_name: str
    email: str | None = None
    role: str
    is_active: bool
    totp_enrolled: bool
    created_at: datetime
    last_login_at: datetime | None = None


def user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        role=user.role.value,
        is_active=user.is_active,
        totp_enrolled=user.totp_enrolled,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


class UserListItem(UserOut):
    key_count: int = 0


class UserRef(BaseModel):
    id: str
    username: str


class SSHKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    label: str
    key_type: str
    fingerprint: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None


class CreateUserIn(BaseModel):
    username: str
    password: str
    display_name: str = ""
    email: str = ""
    role: str = "readonly"


class ChangeRoleIn(BaseModel):
    role: str


class UploadKeyIn(BaseModel):
    label: str
    public_key: str


class GenerateKeyIn(BaseModel):
    label: str = ""


class GeneratedKeyOut(BaseModel):
    private_key: str
    key: SSHKeyOut


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------


class HostOut(BaseModel):
    id: str
    label: str
    alias: str
    hostname: str
    port: int
    username: str | None = None
    description: str | None = None
    is_active: bool
    created_at: datetime
    assigned_users: list[UserRef] = Field(default_factory=list)


def host_out(host: Host) -> HostOut:
    return HostOut(
        id=host.id,
        label=host.label,
        alias=slugify(host.label),
        hostname=host.hostname,
        port=host.port,
        username=host.username,
        description=host.description,
        is_active=host.is_active,
        created_at=host.created_at,
        assigned_users=[
            UserRef(id=u.id, username=u.username) for u in host.assigned_users
        ],
    )


class CreateHostIn(BaseModel):
    label: str
    hostname: str
    port: int = 22
    username: str = ""
    description: str = ""


class DeployKeyOut(BaseModel):
    public_key: str


# ---------------------------------------------------------------------------
# Host groups
# ---------------------------------------------------------------------------


class HostRef(BaseModel):
    id: str
    label: str


class GroupRef(BaseModel):
    id: str
    name: str


class GroupOut(BaseModel):
    id: str
    name: str
    description: str | None = None
    created_at: datetime
    hosts: list[HostRef] = Field(default_factory=list)
    users: list[UserRef] = Field(default_factory=list)


def group_out(group: HostGroup) -> GroupOut:
    return GroupOut(
        id=group.id,
        name=group.name,
        description=group.description,
        created_at=group.created_at,
        hosts=[HostRef(id=h.id, label=h.label) for h in group.hosts],
        users=[UserRef(id=u.id, username=u.username) for u in group.users],
    )


class CreateGroupIn(BaseModel):
    name: str
    description: str = ""


# ---------------------------------------------------------------------------
# SSH sessions
# ---------------------------------------------------------------------------


class SshSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    source_ip: str
    source_port: int
    key_fingerprint: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    close_reason: str | None = None


def ssh_session_out(session: SshSession) -> SshSessionOut:
    return SshSessionOut.model_validate(session)


class SessionsOut(BaseModel):
    active: list[SshSessionOut]
    recent: list[SshSessionOut]


# ---------------------------------------------------------------------------
# 2FA recovery codes
# ---------------------------------------------------------------------------


class RecoveryCodesOut(BaseModel):
    codes: list[str]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditEntryOut(BaseModel):
    id: str
    timestamp: datetime
    action: str
    actor_username: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    source_ip: str | None = None
    detail: dict[str, Any] | list | str | None = None


def audit_entry_out(entry: AuditLog) -> AuditEntryOut:
    return AuditEntryOut(
        id=entry.id,
        timestamp=entry.timestamp,
        action=entry.action.value,
        actor_username=entry.actor.username if entry.actor else None,
        target_type=entry.target_type,
        target_id=entry.target_id,
        source_ip=entry.source_ip,
        detail=entry.detail,
    )


class AuditPageOut(BaseModel):
    entries: list[AuditEntryOut]
    page: int
    total_pages: int
    total: int
    actions: list[str]
    users: list[UserRef]


# ---------------------------------------------------------------------------
# Auth / setup
# ---------------------------------------------------------------------------


class LoginIn(BaseModel):
    username: str
    password: str
    totp_code: str = ""


class SessionOut(BaseModel):
    user: UserOut


class EnrollOut(SessionOut):
    """TOTP enrollment result: the session plus one-time recovery codes.

    The codes are returned exactly once, at enrollment — they are stored
    only as keyed digests server-side and can never be shown again.
    """

    recovery_codes: list[str] = Field(default_factory=list)


class TOTPSetupOut(BaseModel):
    qr_png_b64: str
    secret: str


class TOTPVerifyIn(BaseModel):
    totp_code: str


class SetupIn(BaseModel):
    username: str
    password: str
    password_confirm: str
    display_name: str = "Administrator"


# ---------------------------------------------------------------------------
# Meta / dashboard
# ---------------------------------------------------------------------------


class MetaOut(BaseModel):
    instance_name: str
    version: str
    motd: str = ""
    ssh_host: str
    ssh_port: int
    base_url: str
    setup_needed: bool


class UserDetailOut(BaseModel):
    user: UserOut
    keys: list[SSHKeyOut]
    assigned_hosts: list[HostOut]
    host_groups: list[GroupRef] = Field(default_factory=list)
    recovery_codes_remaining: int = 0
    ssh_host: str
    ssh_port: int
    roles: list[str]


class DashboardOut(BaseModel):
    active_users: int
    active_hosts: int
    active_sessions: int
    user_key_count: int
    recent_audit: list[AuditEntryOut]
    ssh_host: str
    ssh_port: int


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class SettingFieldOut(BaseModel):
    key: str
    label: str
    help: str
    type: str
    value: Any
    group: str
    choices: list[str] | None = None
    min: int | None = None
    max: int | None = None
    readonly: bool = False


class SettingsOut(BaseModel):
    fields: list[SettingFieldOut]
    installer_url: str


def ssh_key_out(key: SSHKey) -> SSHKeyOut:
    return SSHKeyOut.model_validate(key)
