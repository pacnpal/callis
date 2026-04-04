#!/bin/sh
set -e

# Derive internal API shared secret from SECRET_KEY via HMAC-SHA256
if [ -n "${SECRET_KEY:-}" ] && [ -z "${CALLIS_INTERNAL_SECRET:-}" ]; then
    export CALLIS_INTERNAL_SECRET=$(printf 'callis-internal' | openssl dgst -sha256 -hmac "$SECRET_KEY" -hex 2>/dev/null | awk '{print $NF}')
fi

HOST_KEY="/etc/ssh/host_keys/ssh_host_ed25519_key"

# Generate Ed25519 host key if not present
if [ ! -f "$HOST_KEY" ]; then
    echo "Generating Ed25519 host key..."
    ssh-keygen -t ed25519 -f "$HOST_KEY" -N "" -q
fi

# Ensure correct permissions on host key
chmod 600 "$HOST_KEY"
if [ -f "${HOST_KEY}.pub" ]; then
    chmod 644 "${HOST_KEY}.pub"
else
    ssh-keygen -y -f "$HOST_KEY" > "${HOST_KEY}.pub"
    chmod 644 "${HOST_KEY}.pub"
fi

# Ensure log directory exists
mkdir -p /var/log

echo "Starting sshd..."
SSHD_LOG="${CALLIS_SSHD_LOG:-/var/log/auth.log}"
exec /usr/sbin/sshd -D -E "$SSHD_LOG"
