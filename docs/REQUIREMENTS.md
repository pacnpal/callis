# Callis — Requirements

## 1. Overview

Callis is a self-hosted, Dockerized SSH bastion host (jump server) with a web-based management UI. It is designed to be deployed by anyone with Docker and a basic understanding of networking, with no prior bastion host experience required.

The primary deployment target is homelab and small-team infrastructure environments. It must work standalone on a LAN, or behind any standard reverse proxy (Caddy, Nginx, Traefik).

---

## 2. Functional Requirements

### 2.1 SSH Jump Server

- **FR-SSH-01** — The SSH server MUST accept incoming connections and proxy them to configured target hosts (jump/ProxyJump behaviour).
- **FR-SSH-02** — The SSH server MUST support one user account per registered Callis user. Accounts are created and deleted automatically based on user status in the database.
- **FR-SSH-03** — The SSH server MUST authenticate users via SSH public key only. Password authentication MUST be disabled.
- **FR-SSH-04** — The SSH server MUST NOT provide an interactive shell to any user. It is a pure jump point.
- **FR-SSH-05** — The SSH server MUST use `AuthorizedKeysCommand` to fetch active public keys from the API at connection time. This ensures key revocation is instant.
- **FR-SSH-06** — The SSH server MUST disable agent forwarding (`AllowAgentForwarding no`) to limit blast radius if the bastion is compromised.
- **FR-SSH-07** — The SSH server MUST log all connection attempts (accepted and rejected) with timestamp, username, source IP, and source port.
- **FR-SSH-08** — The SSH server MUST only accept Ed25519 host keys. RSA, DSA, and ECDSA host keys MUST NOT be generated or accepted.
- **FR-SSH-09** — SSH host keys MUST be generated on first run and persisted in a named Docker volume. They MUST NOT be regenerated on container restart.
- **FR-SSH-10** — The SSH server MUST listen on a configurable port (default: 2222).

### 2.2 User Management

- **FR-USER-01** — The web UI MUST allow an admin to create user accounts with: username, display name, email, and role.
- **FR-USER-02** — The web UI MUST allow an admin to deactivate and reactivate user accounts. Deactivated users are immediately denied SSH access.
- **FR-USER-03** — The web UI MUST allow an admin to delete user accounts. Deletion permanently removes the user, their keys, and their OS account.
- **FR-USER-04** — Users MUST be assigned one of three roles: `admin`, `operator`, or `readonly`.
- **FR-USER-05** — Roles MUST be enforced at the API level as a dependency, not as inline checks scattered through route handlers.
- **FR-USER-06** — A user MUST NOT be able to elevate their own role.
- **FR-USER-07** — The first user MUST be created via a web-based setup wizard on first load. The wizard MUST require username, password, and TOTP enrollment. The user MUST be assigned the `admin` role automatically.

### 2.3 SSH Key Management

- **FR-KEY-01** — Users MAY upload one or more SSH public keys via the web UI.
- **FR-KEY-02** — Each uploaded key MUST be validated as a syntactically correct OpenSSH public key before being accepted.
- **FR-KEY-03** — Only Ed25519 and RSA (≥ 4096 bit) public keys MUST be accepted. All other key types MUST be rejected with a clear error message.
- **FR-KEY-04** — Keys MUST be stored in the database as their full public key text.
- **FR-KEY-05** — The web UI MUST display keys to their owner as: label, fingerprint (SHA-256), date added, and last used. The full public key text MUST NOT be displayed in the UI after upload.
- **FR-KEY-06** — Admins MUST be able to view key metadata (fingerprint, label, date) for any user. Admins MUST NOT be able to see the full public key text of another user's key.
- **FR-KEY-07** — Any user MUST be able to revoke their own keys. Admins MUST be able to revoke any user's keys.
- **FR-KEY-08** — Revoked keys MUST be denied at the next SSH connection attempt. Because `AuthorizedKeysCommand` is used, revocation is effective immediately — no polling lag.
- **FR-KEY-09** — Each user MUST have a configurable maximum number of active keys (default: 5).
- **FR-KEY-10** — Private keys MUST NEVER be stored by Callis under any circumstances. If a keypair generation feature is provided, the private key MUST be shown once in the UI and then permanently discarded. It MUST NOT be written to the database, logged, or transmitted again.

### 2.4 Host Management

- **FR-HOST-01** — Admins MUST be able to define jump targets (hosts) with: label, hostname/IP, port, and description.
- **FR-HOST-02** — Hosts MUST be assignable to users or groups, restricting which targets each user may jump to.
- **FR-HOST-03** — The web UI MUST display per-host the SSH client config snippet needed to use Callis as a ProxyJump for that host.
- **FR-HOST-04** — Hosts MAY be deactivated without deletion.

### 2.5 Web UI Authentication

- **FR-AUTH-01** — All web UI routes MUST require an authenticated session. The only unauthenticated routes are `/login` and `/health`.
- **FR-AUTH-02** — Authentication MUST use username and password. Passwords MUST be hashed with bcrypt at cost factor ≥ 12.
- **FR-AUTH-03** — TOTP (RFC 6238) 2FA MUST be mandatory for all users. A user MUST complete TOTP enrollment before accessing any other page.
- **FR-AUTH-04** — TOTP enrollment MUST present a QR code and manual secret entry on first login. The TOTP secret MUST be stored encrypted in the database. Backup codes are a future enhancement.
- **FR-AUTH-05** — Sessions MUST be stored as JWTs in an `httpOnly`, `Secure`, `SameSite=Strict` cookie. JWTs MUST NOT be returned in response bodies or stored in localStorage.
- **FR-AUTH-06** — Sessions MUST expire after a configurable idle timeout (default: 30 minutes).
- **FR-AUTH-07** — Sessions MUST have a configurable absolute maximum lifetime regardless of activity (default: 8 hours).
- **FR-AUTH-08** — Failed login attempts (wrong password OR wrong TOTP code) MUST return the same error message and take the same response time (constant-time comparison) to prevent user enumeration and timing attacks.
- **FR-AUTH-09** — The `/auth/login` endpoint MUST be rate-limited: maximum 5 attempts per 15 minutes per IP address.
- **FR-AUTH-10** — Optional OIDC integration MUST be supported via `AUTH_MODE=oidc` in `.env`. When enabled, the built-in password auth flow is replaced by OIDC redirect. TOTP enforcement is the responsibility of the OIDC provider in this mode.

### 2.6 Audit Logging

- **FR-AUDIT-01** — The following events MUST be logged with timestamp, actor, action, target, and source IP:
  - Login attempt (success/failure)
  - TOTP failure
  - Logout
  - Session expiry
  - Key added
  - Key revoked
  - Key used for SSH auth
  - User created
  - User deactivated/reactivated
  - User deleted
  - Role changed
  - Host added
  - Host deactivated/deleted
- **FR-AUDIT-02** — Audit log entries MUST be append-only. No UI action or API call MUST be able to delete or modify audit log entries.
- **FR-AUDIT-03** — The audit log MUST be viewable in the web UI with filtering by event type, user, and date range.
- **FR-AUDIT-04** — Audit logs MUST be written to a persistent Docker volume.

### 2.7 Deployment

- **FR-DEPLOY-01** — The full stack MUST be deployable with a single `docker compose up -d` command. No `.env` file is required for basic operation — `SECRET_KEY` is auto-generated and the admin account is created via the web-based setup wizard on first load.
- **FR-DEPLOY-02** — The stack MUST work with no domain name on a LAN (accessing the UI via IP and port).
- **FR-DEPLOY-03** — The stack MUST work behind any standard reverse proxy. Callis MUST NOT assume a specific reverse proxy is present.
- **FR-DEPLOY-04** — The stack MUST work behind any standard reverse proxy (Caddy, Nginx, Traefik). TLS termination is the user's responsibility.
- **FR-DEPLOY-05** — All configuration MUST be driven by environment variables documented in `.env.example`. No configuration file editing inside containers MUST be required.
- **FR-DEPLOY-06** — The SSH port and web UI port MUST both be configurable via `.env`.
- **FR-DEPLOY-07** — The stack MUST support `AUTH_MODE=local` (default) and `AUTH_MODE=oidc`.

---

## 3. Non-Functional Requirements

### 3.1 Security

- **NFR-SEC-01** — The sshd container MUST be based on Alpine Linux to minimise attack surface.
- **NFR-SEC-02** — The sshd container MUST run as a non-root user where possible. Only the entrypoint that creates OS user accounts requires elevated privilege.
- **NFR-SEC-03** — The API's internal key-serving endpoint (`/internal/keys/{username}`) MUST be bound to a separate internal port not exposed outside the Docker network. It MUST NOT be accessible via the public-facing web UI port.
- **NFR-SEC-04** — All HTTP responses MUST include security headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security` (when behind TLS).
- **NFR-SEC-05** — The Content Security Policy MUST disallow inline scripts and restrict script sources to the CDN allowlist (htmx, Pico CSS).
- **NFR-SEC-06** — Stack traces and internal error details MUST NEVER be exposed to the browser. Unexpected errors (5xx) MUST render a generic error page; expected HTTP errors (4xx) MAY include a user-safe detail message.
- **NFR-SEC-07** — User IDs in URLs MUST use opaque UUIDs, not sequential integers.
- **NFR-SEC-08** — Fail2ban MUST be included as an optional sidecar (opt-in via Compose profile) that watches sshd logs and bans IPs after 3 failed attempts within 10 minutes. Ban duration: 24 hours first offense, permanent after 3 offenses (recidive).

### 3.2 Usability

- **NFR-USE-01** — The web UI SHOULD degrade gracefully without JavaScript where practical. Core read-only flows work without JS; admin actions (create user/host) require JS for dialog interaction.
- **NFR-USE-02** — The web UI MUST be accessible on mobile screen sizes.
- **NFR-USE-03** — The web UI MUST display the SSH client config snippet a user needs to connect through Callis, pre-filled with their username and the configured hostname.
- **NFR-USE-04** — First-run setup MUST guide the admin through: setting admin password, completing TOTP enrollment, and adding a first host — before the system is considered ready.

### 3.3 Maintainability

- **NFR-MAINT-01** — The Python backend MUST use `uv` for dependency management.
- **NFR-MAINT-02** — All Python dependencies MUST be pinned in `pyproject.toml` with a locked `uv.lock`.
- **NFR-MAINT-03** — There MUST be no Node.js, npm, or frontend build step of any kind.
- **NFR-MAINT-04** — The codebase MUST be structured so that adding a new page requires: one route function, one template file, and entries in the nav — nothing else.

### 3.4 Performance

- **NFR-PERF-01** — The `AuthorizedKeysCommand` MUST respond in under 500ms under normal load to avoid SSH connection delays.
- **NFR-PERF-02** — The web UI MUST load initial pages in under 2 seconds on a local network.
- **NFR-PERF-03** — SQLite is the default database and is sufficient for single-server deployments. PostgreSQL MUST be supported as an alternative via `DATABASE_URL` in `.env` for larger deployments.
