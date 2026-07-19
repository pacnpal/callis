#!/bin/sh
# AuthorizedKeysCommand script for sshd
# Fetches public keys from the Callis API internal endpoint.
# Runs as root (AuthorizedKeysCommandUser root) to allow on-the-fly user creation.
# Exits 0 with empty output on any failure (denies access without crashing sshd).
#
# Invoked as: auth-keys.sh %u %f — the second argument is the SHA-256
# fingerprint of the key the client offered, which the API uses to record
# key usage (last-used timestamp + audit trail).

set -e

USERNAME="$1"
KEY_FP="${2:-}"

if [ -z "$USERNAME" ]; then
    exit 0
fi

# Validate username (must match server-side regex: ^[a-z][a-z0-9_-]{0,31}$)
if ! printf '%s' "$USERNAME" | grep -Eq '^[a-z][a-z0-9_-]{0,31}$'; then
    exit 0
fi

# Validate fingerprint format (e.g. SHA256:<base64>); drop anything unexpected
if [ -n "$KEY_FP" ] && ! printf '%s' "$KEY_FP" | grep -Eq '^[A-Za-z0-9:+/=]{1,128}$'; then
    KEY_FP=""
fi

# Fetch authorized keys from internal API first (before creating OS user)
API_HOST="${CALLIS_API_HOST:-localhost}"
INTERNAL_SECRET="${CALLIS_INTERNAL_SECRET:-}"
KEYS=""
KEYS_TMP=$(mktemp) || exit 0
CURL_EXIT=0
HTTP_STATUS=$(curl -sS --max-time 5 \
  -o "$KEYS_TMP" \
  -w '%{http_code}' \
  -H "X-Internal-Secret: ${INTERNAL_SECRET}" \
  -G ${KEY_FP:+--data-urlencode "fp=${KEY_FP}"} \
  "http://${API_HOST}:8081/internal/keys/${USERNAME}" 2>/dev/null) || CURL_EXIT=$?

if [ "$CURL_EXIT" -eq 0 ] && [ "$HTTP_STATUS" = "200" ]; then
    KEYS=$(cat "$KEYS_TMP")
else
    if [ "$HTTP_STATUS" = "403" ]; then
        printf '%s\n' "auth-keys.sh: internal key lookup forbidden for ${USERNAME} (check CALLIS_INTERNAL_SECRET)" >&2
    elif [ "$CURL_EXIT" -eq 28 ]; then
        printf '%s\n' "auth-keys.sh: internal key lookup timed out for ${USERNAME}" >&2
    elif [ "$CURL_EXIT" -ne 0 ]; then
        printf '%s\n' "auth-keys.sh: internal key lookup failed for ${USERNAME} (curl exit ${CURL_EXIT})" >&2
    fi
fi
rm -f "$KEYS_TMP"

# Only create the OS user if the API returned keys (prevents /etc/passwd growth from invalid usernames)
if [ -n "$KEYS" ]; then
    if ! id "$USERNAME" >/dev/null 2>&1; then
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
