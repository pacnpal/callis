#!/bin/sh
set -e

# Set defaults for unified container
export CALLIS_API_HOST="${CALLIS_API_HOST:-localhost}"
export CALLIS_SSHD_LOG="${CALLIS_SSHD_LOG:-/var/log/callis/auth.log}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

# Harden /data permissions (mounted volume may have loose defaults)
chmod 700 /data 2>/dev/null || true

# Resolve SECRET_KEY: env var → persisted file → generate and persist for first start
SECRET_KEY_FILE="/data/.secret_key"
if [ -n "${SECRET_KEY:-}" ]; then
    # Env var is authoritative — always persist it so the API and sshd stay in sync
    umask 077
    printf '%s' "$SECRET_KEY" > "$SECRET_KEY_FILE"
elif [ -f "$SECRET_KEY_FILE" ]; then
    chmod 600 "$SECRET_KEY_FILE"
    export SECRET_KEY=$(cat "$SECRET_KEY_FILE")
else
    export SECRET_KEY=$(openssl rand -hex 32)
    umask 077
    printf '%s' "$SECRET_KEY" > "$SECRET_KEY_FILE"
fi

# Enforce permissions on secret key file every boot
chmod 600 "$SECRET_KEY_FILE" 2>/dev/null || true

# Derive internal API shared secret from SECRET_KEY via HMAC-SHA256
if [ -n "${SECRET_KEY:-}" ] && [ -z "${CALLIS_INTERNAL_SECRET:-}" ]; then
    export CALLIS_INTERNAL_SECRET=$(printf 'callis-internal' | openssl dgst -sha256 -hmac "$SECRET_KEY" -hex 2>/dev/null | awk '{print $NF}')
fi

# Generate SSH host key if not present
HOST_KEY="/etc/ssh/host_keys/ssh_host_ed25519_key"
if [ ! -f "$HOST_KEY" ]; then
    echo "Generating Ed25519 host key..."
    ssh-keygen -t ed25519 -f "$HOST_KEY" -N "" -q
fi

chmod 600 "$HOST_KEY"
if [ -f "${HOST_KEY}.pub" ]; then
    chmod 644 "${HOST_KEY}.pub"
else
    ssh-keygen -y -f "$HOST_KEY" > "${HOST_KEY}.pub"
    chmod 644 "${HOST_KEY}.pub"
fi

# Default env vars consumed by supervisord %(ENV_...)s interpolation
export APP_VERSION="${APP_VERSION:-$(cat /app/.version 2>/dev/null || echo 'dev')}"

# Harden database file permissions if it exists
if [ -f /data/callis.db ]; then
    chmod 600 /data/callis.db
fi

# Ensure log directory exists
mkdir -p /var/log/callis

echo "Starting Callis v$(cat /app/.version 2>/dev/null || echo 'dev')..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/callis.conf
