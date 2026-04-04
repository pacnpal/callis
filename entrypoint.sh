#!/bin/sh
set -e

# Set defaults for unified container
export CALLIS_API_HOST="${CALLIS_API_HOST:-localhost}"
export CALLIS_SSHD_LOG="${CALLIS_SSHD_LOG:-/var/log/callis/auth.log}"

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
export LOG_LEVEL="${LOG_LEVEL:-info}"
export APP_VERSION="${APP_VERSION:-$(cat /app/.version 2>/dev/null || echo 'dev')}"

# Ensure log directory exists
mkdir -p /var/log/callis

echo "Starting Callis v$(cat /app/.version 2>/dev/null || echo 'dev')..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/callis.conf
