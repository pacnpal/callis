# Callis

> *callis (n.) — a narrow, beaten track through rough terrain; in Roman law, a granted right of passage through territory not your own.*

Callis is a self-hosted SSH jump server (bastion host) with a web UI. It provides secure, audited SSH access to internal infrastructure through a single hardened entry point, with full user management, public key management, and connection logging — all configurable through a browser.

---

## Features

- Hardened OpenSSH jump server (Ed25519 and RSA 4096+, no passwords, no shell)
- Web UI built with FastAPI + Jinja2 + htmx — no build step, no Node.js
- Per-user OS accounts with instant key revocation
- Mandatory TOTP 2FA for all web UI users
- Role-based access control (admin, operator, readonly)
- Full audit log of every connection attempt and admin action
- Fail2ban sidecar for SSH brute force protection
- Rate limiting on web UI login
- Works on a LAN or behind any reverse proxy
- Single `docker compose up` deployment

---

## Prerequisites

- Docker Engine 24.0+
- Docker Compose v2.0+
- A server or machine with a static IP or hostname

---

## Quick Start

```bash
git clone https://github.com/pacnpal/callis.git
cd callis
cp .env.example .env
```

Edit `.env` — set these two required values:

```bash
# Generate a secret key
openssl rand -hex 32

# Set in .env:
SECRET_KEY=<paste-your-key-here>
ADMIN_PASSWORD=<choose-a-strong-password>
```

Start Callis:

```bash
docker compose up -d
```

- **Web UI:** `http://<your-server-ip>:8080`
- **SSH jump port:** `2222`

---

## First-Run Walkthrough

1. Open the web UI at `http://<server>:8080`
2. Log in with your admin credentials (username: `admin`, password: from `.env`)
3. You'll be prompted to **set up TOTP 2FA** — scan the QR code with your authenticator app
4. Enter the 6-digit code to complete enrollment
5. You're now on the dashboard

**Next steps:**

6. Go to **Users** and create accounts for your team
7. Each user should log in, set up TOTP, then go to **My Keys** to upload SSH public keys
8. Go to **Hosts** and add your internal servers as jump targets
9. **Assign users to hosts** — use the assignment dropdown on each host row to grant access (users can only jump to hosts they're assigned to)
10. Users can now SSH through Callis to reach their assigned hosts

---

## Deployment Modes

### Mode A — LAN Only (no domain, no TLS)

The default. Good for home labs and internal networks.

```bash
cp .env.example .env
# Set SECRET_KEY and ADMIN_PASSWORD
docker compose up -d
```

Access via `http://<server-ip>:8080` (web) and `<server-ip>:2222` (SSH).

### Mode B — Behind an Existing Reverse Proxy

If you already have Nginx, Caddy, Traefik, etc. handling TLS:

```bash
# In .env:
BASE_URL=https://callis.example.com
HTTPS_ENABLED=true
```

Your reverse proxy config (example for Caddy):

```
callis.example.com {
    reverse_proxy localhost:8080
}
```

SSH port (2222) must be forwarded separately at the network/firewall level.

### Mode C — With Caddy Sidecar (Automatic TLS)

Callis includes a Caddy sidecar that handles TLS automatically via Let's Encrypt.

1. Create a `caddy/Caddyfile`:

```
{$CALLIS_DOMAIN} {
    reverse_proxy api:8080
}
```

2. Set in `.env`:

```bash
CALLIS_DOMAIN=callis.example.com
BASE_URL=https://callis.example.com
HTTPS_ENABLED=true
```

3. Start with the Caddy profile:

```bash
docker compose --profile caddy up -d
```

Ports 80 and 443 must be reachable from the internet for certificate issuance.

---

## SSH Client Configuration

After uploading your public key through the web UI, add this to `~/.ssh/config`:

```
Host callis
    HostName <your-callis-server>
    Port 2222
    User <your-callis-username>
    IdentityFile ~/.ssh/your_ed25519_key

Host my-internal-server
    HostName 192.168.1.50
    User ubuntu
    ProxyJump callis
```

Then connect:

```bash
# Direct jump
ssh -J username@callis-host:2222 ubuntu@192.168.1.50

# Or using the config above
ssh my-internal-server
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | Yes | — | 32+ byte hex string for JWT signing and TOTP encryption |
| `ADMIN_PASSWORD` | Yes | — | Initial admin password (first startup only) |
| `ADMIN_USERNAME` | No | `admin` | Initial admin username |
| `DATABASE_URL` | No | `sqlite+aiosqlite:////data/callis.db` | Database URL (PostgreSQL supported) |
| `SSH_PORT` | No | `2222` | External SSH port |
| `WEB_PORT` | No | `8080` | External web UI port |
| `BASE_URL` | No | `http://localhost:8080` | Public URL (used in SSH config snippets) |
| `SESSION_IDLE_TIMEOUT` | No | `1800` | Idle timeout in seconds (30 min) |
| `SESSION_MAX_LIFETIME` | No | `28800` | Max session lifetime in seconds (8 hrs) |
| `MAX_KEYS_PER_USER` | No | `5` | Maximum SSH keys per user |
| `AUTH_MODE` | No | `local` | `local` or `oidc` |
| `HTTPS_ENABLED` | No | `false` | Enable HSTS and Secure cookie flag |
| `DEV_MODE` | No | `false` | Enable development mode features (verbose SQL logging) |
| `LOG_LEVEL` | No | `info` | Logging level |
| `TZ` | No | `UTC` | Timezone |
| `CALLIS_DOMAIN` | If Caddy | — | Domain for Caddy TLS (Mode C only) |

---

## Ports

| Port | Service | Exposed to Host |
|---|---|---|
| `WEB_PORT` (8080) | Web UI | Yes |
| `SSH_PORT` (2222) | SSH jump server | Yes |
| 8081 | Internal key endpoint | **No** (Docker network only) |

Port 8081 serves the internal API used by the SSH server to fetch authorized keys. It is never exposed outside the Docker network.

---

## Backup & Restore

### Backup the database

```bash
docker run --rm -v callis_db:/data -v $(pwd):/backup alpine \
  tar czf /backup/callis-db-$(date +%Y%m%d).tar.gz /data
```

### Backup SSH host keys

```bash
docker run --rm -v callis_hostkeys:/data -v $(pwd):/backup alpine \
  tar czf /backup/callis-hostkeys-$(date +%Y%m%d).tar.gz /data
```

### Restore

```bash
docker run --rm -v callis_db:/data -v $(pwd):/backup alpine \
  tar xzf /backup/callis-db-YYYYMMDD.tar.gz -C /
```

---

## Upgrading

```bash
docker compose pull
docker compose up -d
```

Database tables are created automatically on startup. Back up your database before upgrading.

---

## Security Notes

- **Private keys are never stored.** Callis accepts uploaded public keys only and does not collect, generate, or retain private keys.
- **Public key text is write-only.** After upload, only the fingerprint, label, type, and dates are shown.
- **Port 8081 is internal only.** It serves SSH authorized keys to the sshd container via the Docker network and is never exposed to the host.
- **TOTP is mandatory.** Every user must enroll in 2FA before accessing any page.
- **Audit log is append-only.** No API or UI can delete or modify audit entries.
- **Authentication checks are hardened.** Login applies secure password verification and enforces TOTP-based 2FA.
- **sshd is hardened.** Ed25519 and RSA (4096+ bit) keys accepted, no passwords, no root login, no shell access, modern cipher suite.

---

## Architecture

See the `docs/` directory for detailed documentation:

- [Requirements](docs/REQUIREMENTS.md) — functional and security requirements
- [Architecture](docs/ARCHITECTURE.md) — system design and component overview
- [Security](docs/SECURITY.md) — security model, contracts, and threat model
- [Deployment](docs/DEPLOYMENT.md) — deployment modes and configuration reference
- [Development](docs/DEVELOPMENT.md) — local dev setup and contribution guide

---

## Fail2ban

Callis includes a fail2ban sidecar that monitors SSH authentication failures. Default settings:

- **3 failures** within **10 minutes** triggers a ban
- **24-hour** ban duration
- Monitors sshd logs via shared Docker volume

If you change `SSH_PORT` from the default 2222, update `fail2ban/jail.local` to match.

---

## License

MIT
