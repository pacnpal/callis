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

# Validate username (must match server-side regex: lowercase alpha start, alphanumeric/hyphens/underscores, max 32 chars)
case "$USERNAME" in
    [a-z][a-z0-9_-]*) ;;
    *) exit 0 ;;
esac
if [ "${#USERNAME}" -gt 32 ]; then
    exit 0
fi

# Fetch authorized keys from internal API first (before creating OS user)
KEYS=$(curl -sf --max-time 5 "http://api:8081/internal/keys/${USERNAME}" 2>/dev/null) || true

# Only create the OS user if the API returned keys (prevents /etc/passwd growth from invalid usernames)
if [ -n "$KEYS" ]; then
    if ! id -- "$USERNAME" >/dev/null 2>&1; then
        adduser -D -H -s /sbin/nologin -- "$USERNAME" 2>/dev/null || true
    fi
    printf '%s\n' "$KEYS"
fi
