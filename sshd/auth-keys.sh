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
INTERNAL_SECRET="${CALLIS_INTERNAL_SECRET:-}"
KEYS=$(curl -sf --max-time 5 \
  -H "X-Internal-Secret: ${INTERNAL_SECRET}" \
  "http://${API_HOST}:8081/internal/keys/${USERNAME}" 2>/dev/null) || true

# Only create the OS user if the API returned keys (prevents /etc/passwd growth from invalid usernames)
if [ -n "$KEYS" ]; then
    if ! id -- "$USERNAME" >/dev/null 2>&1; then
        NOLOGIN_SHELL=$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)
        if command -v adduser >/dev/null 2>&1 && ! command -v useradd >/dev/null 2>&1; then
            adduser -D -H -s "$NOLOGIN_SHELL" "$USERNAME" 2>/dev/null || true
        else
            useradd --no-create-home --shell "$NOLOGIN_SHELL" "$USERNAME" 2>/dev/null || true
        fi
    fi
    # Only output keys if the OS user exists (adduser may have failed)
    if id "$USERNAME" >/dev/null 2>&1; then
        printf '%s\n' "$KEYS"
    fi
fi
