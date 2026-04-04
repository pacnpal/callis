#!/bin/sh
# AuthorizedKeysCommand script for sshd
# Fetches public keys from the Callis API internal endpoint.
# Runs as root (AuthorizedKeysCommandUser root) to allow on-the-fly user creation.
# Exits 0 with empty output on any failure (denies access without crashing sshd).

set -e

USERNAME="$1"

if [ -z "$USERNAME" ]; then
    exit 0
fi

# Validate username (must match server-side regex: ^[a-z][a-z0-9_-]{0,31}$)
if ! printf '%s' "$USERNAME" | grep -Eq '^[a-z][a-z0-9_-]{0,31}$'; then
    exit 0
fi

# Fetch authorized keys from internal API first (before creating OS user)
API_HOST="${CALLIS_API_HOST:-localhost}"
KEYS=$(curl -sf --max-time 5 "http://${API_HOST}:8081/internal/keys/${USERNAME}" 2>/dev/null) || true

# Only create the OS user if the API returned keys (prevents /etc/passwd growth from invalid usernames)
if [ -n "$KEYS" ]; then
    if ! id -- "$USERNAME" >/dev/null 2>&1; then
        useradd --no-create-home --shell /usr/sbin/nologin "$USERNAME" 2>/dev/null || true
    fi
    # Only output keys if the OS user exists (adduser may have failed)
    if id -- "$USERNAME" >/dev/null 2>&1; then
        printf '%s\n' "$KEYS"
    fi
fi
