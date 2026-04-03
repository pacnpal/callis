#!/bin/sh
set -e

HOST_KEY="/etc/ssh/host_keys/ssh_host_ed25519_key"

# Generate Ed25519 host key if not present
if [ ! -f "$HOST_KEY" ]; then
    echo "Generating Ed25519 host key..."
    ssh-keygen -t ed25519 -f "$HOST_KEY" -N "" -q
fi

# Ensure correct permissions on host key
chmod 600 "$HOST_KEY"
chmod 644 "${HOST_KEY}.pub"

# Ensure log directory exists
mkdir -p /var/log

echo "Starting sshd..."
exec /usr/sbin/sshd -D -e
