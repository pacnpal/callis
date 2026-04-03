# Callis

> *callis (n.) — a narrow, beaten track through rough terrain; in Roman law, a granted right of passage through territory not your own.*

Callis is a self-hosted SSH jump server (bastion host) with a web UI. It provides secure, audited SSH access to internal infrastructure through a single hardened entry point, with full user management, public key management, and connection logging — all configurable through a browser.

---

## Features

- Hardened OpenSSH jump server (Ed25519 only, no passwords, no shell)
- Web UI built with FastAPI + Jinja2 + htmx — no build step, no Node.js
- Per-user OS accounts with instant key revocation
- Mandatory TOTP 2FA for all web UI users
- Optional OIDC/SSO integration (Authentik, Keycloak, etc.)
- Full audit log of every connection attempt and admin action
- Fail2ban sidecar for SSH brute force protection
- Rate limiting on web UI login
- Works on a LAN or behind any reverse proxy
- Single `docker compose up` deployment

---

## Quick Start

```bash
git clone https://github.com/yourname/callis.git
cd callis
cp .env.example .env
# Edit .env — set SECRET_KEY and ADMIN_PASSWORD at minimum
docker compose up -d
```

Web UI: `http://localhost:8080`
SSH jump port: `2222`

---

## Documentation

- [Requirements](docs/REQUIREMENTS.md) — full functional and security requirements
- [Architecture](docs/ARCHITECTURE.md) — system design and component overview
- [Security](docs/SECURITY.md) — security model, contracts, and threat model
- [Deployment](docs/DEPLOYMENT.md) — deployment modes and configuration reference
- [Development](docs/DEVELOPMENT.md) — local dev setup and contribution guide

---

## License

MIT
