#!/bin/sh
set -e

# Set defaults for unified container
export CALLIS_API_HOST="${CALLIS_API_HOST:-localhost}"
export CALLIS_SSHD_LOG="${CALLIS_SSHD_LOG:-/var/log/callis/auth.log}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

# Harden /data permissions (mounted volume may have loose defaults)
if ! chmod 700 /data 2>/dev/null; then
    echo "WARNING: Could not set permissions on /data. Continuing with existing permissions." >&2
fi

# Resolve SECRET_KEY: env var → persisted file → generate and persist for first start
SECRET_KEY_FILE="/data/.secret_key"
if [ -n "${SECRET_KEY:-}" ]; then
    if [ -f "$SECRET_KEY_FILE" ]; then
        chmod 600 "$SECRET_KEY_FILE"
        PERSISTED_KEY=$(cat "$SECRET_KEY_FILE" 2>/dev/null)
        if [ -z "${PERSISTED_KEY:-}" ]; then
            echo "FATAL: $SECRET_KEY_FILE exists but is empty. Remove it and restart." >&2
            exit 1
        fi
        if [ "$SECRET_KEY" != "$PERSISTED_KEY" ]; then
            if [ "${CALLIS_ROTATE_SECRET_KEY:-false}" != "true" ]; then
                echo "FATAL: SECRET_KEY env var does not match the persisted key in $SECRET_KEY_FILE." >&2
                echo "Refusing to overwrite. Set CALLIS_ROTATE_SECRET_KEY=true to rotate the key." >&2
                echo "WARNING: Rotating the key will invalidate all active sessions and stored TOTP secrets." >&2
                exit 1
            fi
            (
                umask 077
                printf '%s' "$SECRET_KEY" > "$SECRET_KEY_FILE"
            )
        fi
    else
        (
            umask 077
            printf '%s' "$SECRET_KEY" > "$SECRET_KEY_FILE"
        )
    fi
elif [ -f "$SECRET_KEY_FILE" ]; then
    chmod 600 "$SECRET_KEY_FILE"
    export SECRET_KEY=$(cat "$SECRET_KEY_FILE")
    if [ -z "${SECRET_KEY:-}" ]; then
        echo "FATAL: $SECRET_KEY_FILE exists but is empty. Remove it and restart." >&2
        exit 1
    fi
else
    export SECRET_KEY=$(openssl rand -hex 32)
    (
        umask 077
        printf '%s' "$SECRET_KEY" > "$SECRET_KEY_FILE"
    )
fi

# Enforce permissions on secret key file every boot
if ! chmod 600 "$SECRET_KEY_FILE" 2>/dev/null; then
    echo "WARNING: Could not set permissions on $SECRET_KEY_FILE. Continuing with existing permissions." >&2
fi

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
