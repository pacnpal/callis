#!/bin/bash
set -e

# Set defaults for unified container
export CALLIS_API_HOST="${CALLIS_API_HOST:-localhost}"
export CALLIS_SSHD_LOG="${CALLIS_SSHD_LOG:-/var/log/callis/auth.log}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

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

# Ensure log directory exists
mkdir -p /var/log/callis

echo "Starting Callis v$(cat /app/.version 2>/dev/null || echo 'dev')..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/callis.conf
