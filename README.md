# Callis

> *callis (n.) — a narrow, beaten track through rough terrain; in Roman law, a granted right of passage through territory not your own.*

[![GitHub Release](https://img.shields.io/github/v/release/pacnpal/callis?style=flat&logo=github&label=GitHub)](https://github.com/pacnpal/callis/releases)
[![GHCR](https://img.shields.io/badge/ghcr.io-pacnpal%2Fcallis-blue?style=flat&logo=github)](https://ghcr.io/pacnpal/callis)
[![Docker Hub](https://img.shields.io/docker/v/pacnpal/callis?style=flat&logo=docker&label=Docker%20Hub)](https://hub.docker.com/r/pacnpal/callis)
[![License](https://img.shields.io/github/license/pacnpal/callis?style=flat)](LICENSE)

Callis is a self-hosted SSH jump server (bastion host) with a web UI. It provides secure, audited SSH access to internal infrastructure through a single hardened entry point, with full user management, public key management, and connection logging — all configurable through a browser.

---

## Features

- Hardened OpenSSH jump server (Ed25519 host key; Ed25519 or RSA 4096+ user keys; no passwords, no interactive shell)
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

### Option A — Docker Hub / GHCR (recommended)

```bash
docker pull ghcr.io/pacnpal/callis:latest
# or: docker pull pacnpal/callis:latest
# or pin a version: docker pull ghcr.io/pacnpal/callis:0.1.0
```

```bash
git clone https://github.com/pacnpal/callis.git
cd callis
cp .env.example .env
```

### Option B — Build from source

```bash
git clone https://github.com/pacnpal/callis.git
cd callis
cp .env.example .env
docker compose up -d --build
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

Or use this minimal `docker-compose.yml`:

```yaml
services:
  callis:
    image: ghcr.io/pacnpal/callis:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "2222:22"
    volumes:
      - callis_db:/data
      - callis_hostkeys:/etc/ssh/host_keys
    env_file: .env

volumes:
  callis_db:
  callis_hostkeys:
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
7. Each user should log in, set up TOTP, then go to **My Profile** to upload SSH public keys
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

### Mode B — Behind a Reverse Proxy (Caddy, Nginx, Traefik, etc.)

Callis serves plain HTTP on port 8080. TLS termination is handled by your reverse proxy — Callis does not manage certificates.

**1. Set these in `.env`:**

```bash
BASE_URL=https://callis.example.com
HTTPS_ENABLED=true
```

`HTTPS_ENABLED=true` enables HSTS headers and sets the `Secure` flag on session cookies (required when serving over HTTPS).

**2. Point your reverse proxy at Callis port 8080:**

<details>
<summary>Caddy</summary>

```
callis.example.com {
    reverse_proxy localhost:8080
}
```
Caddy handles TLS automatically via Let's Encrypt.
</details>

<details>
<summary>Nginx</summary>

```nginx
server {
    listen 443 ssl;
    server_name callis.example.com;

    ssl_certificate     /etc/letsencrypt/live/callis.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/callis.example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name callis.example.com;
    return 301 https://$host$request_uri;
}
```
</details>

<details>
<summary>Traefik (Docker labels)</summary>

Add these labels to the `callis` service in `docker-compose.yml`:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.callis.rule=Host(`callis.example.com`)"
  - "traefik.http.routers.callis.entrypoints=websecure"
  - "traefik.http.routers.callis.tls.certresolver=letsencrypt"
  - "traefik.http.services.callis.loadbalancer.server.port=8080"
```
</details>

**3. SSH port forwarding**

The SSH jump port (default 2222) is **not** proxied — it must be forwarded at the network/firewall level:

```bash
# Or simply expose it in docker-compose.yml (already the default):
ports:
  - "2222:22"
```

Users connect directly to the SSH port; only the web UI goes through the reverse proxy.

---

## Quick Connect (Callis CLI)

The Callis CLI lets you SSH to any assigned host by tag — no manual SSH config needed:

```bash
# Add to your shell rc file (~/.bashrc, ~/.zshrc, etc.)
source /path/to/callis/scripts/callis.sh

# One-time setup
callis setup

# List your assigned hosts
callis list
# mac-mini   192.168.1.50   22   Mac Mini Server
# web-prod   10.0.1.20      22   Production Web

# Connect by tag
callis mac-mini

# Pass extra SSH options
callis web-prod -L 8080:localhost:8080
```

The CLI resolves host tags over SSH (no HTTP API calls from the client), then connects through the bastion via ProxyJump.

---

## SSH Client Configuration (Manual)

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

---

## Ports

| Port | Service | Exposed to Host |
|---|---|---|
| `WEB_PORT` (8080) | Web UI | Yes |
| `SSH_PORT` (2222) | SSH jump server | Yes |
| 8081 | Internal API (keys, resolve, hosts) | **No** (container-internal only) |

Port 8081 serves the internal API used by the SSH server to fetch authorized keys, resolve host tags, and list assigned hosts. It is bound within the container and never exposed outside. All requests require a valid `X-Internal-Secret` header (HMAC-SHA256 derived from `SECRET_KEY`).

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
- **sshd is hardened.** Ed25519 and RSA (4096+ bit) keys accepted, no passwords, no root login, no interactive shell (ForceCommand allows only `resolve` and `list`), modern cipher suite.

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
