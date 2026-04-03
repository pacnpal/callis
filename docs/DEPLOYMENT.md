# Callis — Deployment Guide

## 1. Prerequisites

- Docker Engine 24.0+
- Docker Compose v2.0+
- A server or machine with a static IP or hostname (for SSH access from outside your LAN)

---

## 2. Deployment Modes

### Mode A — LAN Only (no domain, no TLS)

The simplest setup. Access the web UI via IP and port on your local network.

```bash
git clone https://github.com/yourname/callis.git
cd callis
cp .env.example .env
```

Edit `.env`:
```env
SECRET_KEY=<generate with: openssl rand -hex 32>
ADMIN_PASSWORD=<strong password>
```

Start:
```bash
docker compose up -d
```

- Web UI: `http://<your-server-ip>:8080`
- SSH: `<your-server-ip>:2222`

### Mode B — Behind Your Own Reverse Proxy (Caddy, Nginx, Traefik, etc.)

Callis exposes the web UI on port 8080. Point your reverse proxy at it. Callis does not need to know about your reverse proxy.

Example Caddy block (add to your existing Caddyfile):
```
callis.example.com {
    reverse_proxy localhost:8080
}
```

Set in `.env`:
```env
SECRET_KEY=<generate with: openssl rand -hex 32>
ADMIN_PASSWORD=<strong password>
BASE_URL=https://callis.example.com
```

Start:
```bash
docker compose up -d
```

The SSH port (2222) must be forwarded separately at the network/firewall level. It does not go through the reverse proxy.

### Mode C — With Included Caddy Sidecar

For users without an existing reverse proxy who want automatic TLS via Let's Encrypt.

Set in `.env`:
```env
SECRET_KEY=<generate with: openssl rand -hex 32>
ADMIN_PASSWORD=<strong password>
CALLIS_DOMAIN=callis.example.com
BASE_URL=https://callis.example.com
```

Start with the caddy profile:
```bash
docker compose --profile caddy up -d
```

Port 80 and 443 must be reachable from the internet for Let's Encrypt to issue a certificate.

### Mode D — OIDC Authentication

Replace built-in password auth with an external OIDC provider (Authentik, Keycloak, Okta, etc.).

Set in `.env`:
```env
AUTH_MODE=oidc
OIDC_ISSUER=https://auth.example.com/application/o/callis/
OIDC_CLIENT_ID=<your client ID>
OIDC_CLIENT_SECRET=<your client secret>
```

In OIDC mode, Callis delegates authentication entirely to the OIDC provider. TOTP enforcement is the OIDC provider's responsibility. Users are created in Callis automatically on first OIDC login (JIT provisioning).

---

## 3. Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | **Yes** | — | 32+ byte hex string. Generate: `openssl rand -hex 32` |
| `ADMIN_PASSWORD` | **Yes** | — | Initial admin account password |
| `ADMIN_USERNAME` | No | `admin` | Initial admin account username |
| `DATABASE_URL` | No | `sqlite:///./callis.db` | SQLAlchemy DB URL. Use `postgresql://...` for Postgres |
| `SSH_PORT` | No | `2222` | External SSH port |
| `WEB_PORT` | No | `8080` | External web UI port |
| `BASE_URL` | No | `http://localhost:8080` | Public base URL — used in SSH config snippets shown to users |
| `SESSION_IDLE_TIMEOUT` | No | `1800` | Session idle timeout in seconds (default: 30 min) |
| `SESSION_MAX_LIFETIME` | No | `28800` | Absolute session max lifetime in seconds (default: 8 hours) |
| `MAX_KEYS_PER_USER` | No | `5` | Maximum SSH public keys per user |
| `AUTH_MODE` | No | `local` | `local` or `oidc` |
| `OIDC_ISSUER` | If OIDC | — | OIDC issuer URL |
| `OIDC_CLIENT_ID` | If OIDC | — | OIDC client ID |
| `OIDC_CLIENT_SECRET` | If OIDC | — | OIDC client secret |
| `CALLIS_DOMAIN` | If Caddy | — | Domain for Caddy TLS (Mode C only) |
| `TZ` | No | `UTC` | Timezone for log timestamps |

---

## 4. Ports

| Port | Protocol | Service | Exposed |
|---|---|---|---|
| `${WEB_PORT}` (8080) | TCP | Web UI | Yes — to host |
| `${SSH_PORT}` (2222) | TCP | SSH jump server | Yes — to host |
| `8081` | TCP | Internal key endpoint | **No** — Docker network only |

The internal key endpoint (8081) is used exclusively by the sshd container to fetch authorized keys. It must never be exposed outside the Docker network.

---

## 5. Volumes

| Volume | Purpose |
|---|---|
| `callis_db` | SQLite database (or Postgres data if self-hosted) |
| `callis_hostkeys` | SSH host keys — persisted across container restarts |
| `callis_sshd_logs` | sshd log output — shared with fail2ban sidecar |
| `callis_audit_logs` | Audit log files |
| `caddy_data` | Caddy TLS certificates (Mode C only) |

---

## 6. SSH Client Configuration

After deployment, add this to your `~/.ssh/config` to use Callis as a jump host:

```
Host callis
    HostName <your-callis-server>
    Port 2222
    User <your-callis-username>
    IdentityFile ~/.ssh/your_ed25519_key

Host my-server
    HostName 192.168.1.50
    User ubuntu
    ProxyJump callis
```

Then connect with:
```bash
ssh my-server
```

Or without config:
```bash
ssh -J username@callis-host:2222 ubuntu@192.168.1.50
```

---

## 7. Upgrading

```bash
docker compose pull
docker compose up -d
```

Database migrations run automatically on startup.

---

## 8. Backup

Back up the `callis_db` volume (contains all users, keys, hosts, and audit logs) and the `callis_hostkeys` volume (contains SSH host keys — losing this causes host key warnings for all users).

```bash
# Backup database
docker run --rm -v callis_db:/data -v $(pwd):/backup alpine \
  tar czf /backup/callis-db-$(date +%Y%m%d).tar.gz /data

# Backup host keys
docker run --rm -v callis_hostkeys:/data -v $(pwd):/backup alpine \
  tar czf /backup/callis-hostkeys-$(date +%Y%m%d).tar.gz /data
```
