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

# Create OS user on-the-fly if they don't exist (nologin shell, no password)
if ! id -- "$USERNAME" >/dev/null 2>&1; then
    adduser -D -s /sbin/nologin -- "$USERNAME" 2>/dev/null || true
fi

# Fetch authorized keys from internal API
curl -sf --max-time 5 "http://api:8081/internal/keys/${USERNAME}" 2>/dev/null || true
