#!/bin/sh
set -e

# Derive internal API shared secret from SECRET_KEY via HMAC-SHA256
if [ -n "${SECRET_KEY:-}" ] && [ -z "${CALLIS_INTERNAL_SECRET:-}" ]; then
    CALLIS_INTERNAL_SECRET=$(printf 'callis-internal' | openssl dgst -sha256 -hmac "$SECRET_KEY" -hex 2>/dev/null | awk '{print $NF}')
    if [ -z "$CALLIS_INTERNAL_SECRET" ]; then
        echo "FATAL: Could not derive CALLIS_INTERNAL_SECRET from SECRET_KEY." >&2
        exit 1
    fi
    export CALLIS_INTERNAL_SECRET
fi

# Persist the internal secret to a root-only file. OpenSSH runs
# AuthorizedKeysCommand (and everything sshd spawns) with a sanitized
# environment, so auth-keys.sh and user-sync.sh cannot rely on inheriting
# CALLIS_INTERNAL_SECRET — they read it from here. This works in both the
# unified image and a standalone sshd sidecar (which may not mount /data).
if [ -n "${CALLIS_INTERNAL_SECRET:-}" ]; then
    mkdir -p /run/callis
    (umask 077; printf '%s' "$CALLIS_INTERNAL_SECRET" > /run/callis/internal_secret)
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

# Start the OS account reconciler as a child of this shell, then run sshd in the
# foreground under a signal trap. It pre-creates accounts for users with keys so
# OpenSSH can look them up on first connection (sshd will not run
# AuthorizedKeysCommand for a username missing from the OS user database).
#
# Binding both to this shell (rather than `exec`-ing sshd and orphaning the
# reconciler) means the reconciler is terminated whenever sshd stops or is
# restarted by supervisord — otherwise each restart would orphan the old loop
# and accumulate duplicate reconcilers.
SYNC_PID=""
if [ -x /etc/ssh/user-sync.sh ]; then
    # Best-effort initial reconciliation (bounded) so existing key-bearing users
    # are provisioned before sshd accepts connections. Then start the background
    # reconciler for the steady state and users added later.
    /etc/ssh/user-sync.sh --once || true
    /etc/ssh/user-sync.sh &
    SYNC_PID=$!
fi

/usr/sbin/sshd -D -E "$SSHD_LOG" &
SSHD_PID=$!

# Bind the reconciler's lifetime to sshd. `|| _rc=$?` keeps `set -e` from exiting
# on a non-zero sshd status before cleanup runs (which would orphan the
# reconciler across supervisord restarts).
trap 'kill "$SSHD_PID" ${SYNC_PID:+"$SYNC_PID"} 2>/dev/null' TERM INT
_rc=0
wait "$SSHD_PID" || _rc=$?
[ -n "$SYNC_PID" ] && kill "$SYNC_PID" 2>/dev/null
exit "$_rc"
