# Callis — Security Model

## 1. Security Contracts

These are non-negotiable rules enforced in code, not guidelines.

### 1.1 Private Key Handling

- Private keys are **never stored** by Callis. Ever.
- If a keypair generation feature is offered in the UI, the private key is shown **once** in a modal immediately after generation, then permanently discarded. It is never written to the database, never logged, never transmitted again after that single display.
- Public key text is stored in the database but is **never returned in any API response or rendered in the UI** after the initial upload. Only metadata is shown: fingerprint (SHA-256), label, key type, date added, last used.
- Admins can view key metadata for any user. They cannot see full public key text for another user's key.
- The `AuthorizedKeysCommand` endpoint returns raw public key text to `sshd` — but this endpoint is network-isolated (internal Docker network only) and is never accessible through the public web UI port.

### 1.2 First-Run Setup

- On first start with an empty database, all web requests redirect to `/setup` (enforced by `SetupGuardMiddleware`).
- The setup wizard creates the initial admin account and requires TOTP enrollment before granting access.
- Once any user exists in the database, the account-creation step (`GET /setup` and `POST /setup`) returns 404 and cannot be re-triggered. The TOTP enrollment step (`/setup/totp`) remains accessible only to the session established during that wizard run, until enrollment is completed.
- `SECRET_KEY` is auto-generated using `openssl rand -hex 32` if not provided in `.env`, and persisted to `/data/.secret_key`.
- File permissions are enforced on **every boot**: `/data` (700), `.secret_key` (600), `callis.db` (600), SSH host key (600).

### 1.3 Authentication

- Every route except `/login`, `/setup*`, and `/health` requires a valid session. This is enforced in middleware, not in individual route handlers.
- Sessions are JWTs stored in `httpOnly`, `Secure`, `SameSite=Strict` cookies.
- JWTs are never returned in response bodies, never stored in localStorage, never embedded in URLs.
- TOTP is mandatory. No user may access any page other than `/totp/setup` until TOTP is enrolled. This is enforced in `TOTPGuardMiddleware`.
- After TOTP setup, every login requires password AND TOTP code. There is no "remember this device."
- Failed login attempts (wrong password or wrong TOTP) return the same error message and take the same time to respond (constant-time comparison). This prevents both user enumeration and timing attacks.
- Sessions expire after idle timeout (default: 30 minutes) and have an absolute maximum lifetime (default: 8 hours).

### 1.4 Authorization

- Role hierarchy: `admin` > `operator` > `readonly`.
- Role checks use FastAPI dependencies (`require_role("admin")`), applied at the route level — never scattered inline.
- Users cannot elevate their own role.
- `readonly` users can only view the audit log.
- `operator` users can manage hosts assigned to them.
- `admin` users have full access.
- A user can never view another user's key text, only fingerprints and metadata.

### 1.5 Audit

- Audit log entries are append-only. No API route or UI action can delete or modify them.
- All auth events, key events, and admin actions are logged.
- Logs include: timestamp, actor, action, target, source IP, and action-specific metadata.

### 1.6 Transport and Headers

Every HTTP response carries:

```
Content-Security-Policy: default-src 'self';
  script-src 'self' https://unpkg.com https://cdn.jsdelivr.net;
  style-src 'self' https://unpkg.com https://cdn.jsdelivr.net;
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains  (when HTTPS)
```

Inline scripts are disallowed by CSP. htmx is loaded from a CDN allowlisted in the CSP. No eval, no inline event handlers.

---

## 2. SSH Hardening

### sshd_config (non-negotiable settings)

```
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile none
AuthorizedKeysCommand /etc/ssh/auth-keys.sh %u
AuthorizedKeysCommandUser root

HostKey /etc/ssh/host_keys/ssh_host_ed25519_key
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

AllowTcpForwarding local
GatewayPorts no
X11Forwarding no
PermitTunnel no
AllowAgentForwarding no
PermitTTY no
ForceCommand /etc/ssh/callis-cmd.sh
MaxAuthTries 2
LoginGraceTime 15
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/ssh/banner.txt
```

Note on `PermitTTY no` + `ForceCommand /etc/ssh/callis-cmd.sh`: ForceCommand applies only to shell/exec SSH requests, not to `direct-tcpip` channel requests (which is what ProxyJump uses). The command router allows only two whitelisted commands (`resolve <tag>` and `list`) — all other input is denied with "This account is not available." Tag input is sanitized to `[a-z0-9-]` only.

### Key algorithm policy

- Only Ed25519 host keys are generated and used.
- Only Ed25519 and RSA ≥ 4096 bit client public keys are accepted. This is enforced in the API on upload, before the key is stored.
- The strict KexAlgorithms, Ciphers, and MACs list above eliminates all deprecated or weak algorithms.

---

## 3. Threat Model

### Threat: Brute force SSH

**Mitigations:**
- `MaxAuthTries 2` — limits attempts per connection
- `LoginGraceTime 15` — short window for auth
- Fail2ban sidecar — bans IPs after 3 failures in 10 minutes
- Non-standard port (default 2222) — reduces automated scanner hits

### Threat: Brute force web UI

**Mitigations:**
- `slowapi` rate limiting: 5 attempts per 15 minutes per IP on `/auth/login`
- TOTP required — even correct password is insufficient alone
- Constant-time comparison — no user enumeration via timing

### Threat: Stolen session cookie

**Mitigations:**
- `httpOnly` — not accessible to JavaScript
- `Secure` — only sent over HTTPS
- `SameSite=Strict` — not sent on cross-site requests
- Short idle timeout (30 minutes default)
- Absolute session lifetime (8 hours default)

### Threat: Compromised user account

**Mitigations:**
- Instant key revocation via `AuthorizedKeysCommand` — no polling lag
- Per-user OS accounts — compromised account is isolated
- Admin can deactivate account immediately from web UI

### Threat: Exposed internal API

**Mitigations (defense-in-depth, three layers):**
1. **Network isolation** — port 8081 bound separately, never exposed in `docker-compose.yml`, only reachable within the Docker network
2. **Internal shared secret** — all internal API requests (`/internal/keys/`, `/internal/resolve/`, `/internal/hosts/`) require a valid `X-Internal-Secret` header. The secret is derived deterministically from `SECRET_KEY` via `HMAC-SHA256(SECRET_KEY, "callis-internal")`, so no additional env var is needed. Requests with missing or invalid secrets are rejected with 403.
3. **SSH key authentication** — `callis-cmd.sh` only executes after SSH key auth succeeds. The username comes from `$(whoami)` (the OS user created by `auth-keys.sh` after key verification), not from client input.

### Threat: Command injection via ForceCommand

**Mitigations:**
- `callis-cmd.sh` uses a strict `case` statement — only `resolve <tag>` and `list` are allowed
- Tag input is sanitized via `tr -cd 'a-z0-9-'` — all other characters are stripped
- Default case denies access (same behavior as previous `/sbin/nologin`)

### Threat: XSS

**Mitigations:**
- Server-side rendering via Jinja2 — output is auto-escaped
- Strict CSP — no inline scripts, CDN allowlist only
- No user-controlled content is rendered unescaped anywhere

### Threat: CSRF

**Mitigations:**
- `SameSite=Strict` cookies prevent cross-site form submissions from including the session cookie
- htmx uses standard form submissions — no JSON API that could be hit cross-origin

### Threat: SSH host key spoofing

**Mitigations:**
- Host keys generated once and persisted in a named volume
- Not regenerated on container restart
- Users instructed to verify host key fingerprint on first connection (displayed in web UI)

---

## 4. What Callis Does Not Protect Against

- **Network-layer attacks** — DDoS, IP spoofing. These must be handled at the network/firewall layer (OPNsense, AWS security groups, etc.).
- **Compromised host machines** — Callis controls access to hosts, not security on those hosts.
- **Physical access** — out of scope.
- **Supply chain attacks on dependencies** — mitigated by pinned dependencies in `uv.lock` but not eliminated.
- **A compromised admin account** — a compromised admin can revoke other users' access. Protect admin accounts accordingly.
