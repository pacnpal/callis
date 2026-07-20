#!/bin/sh
# Ensure an UNLOCKED, nologin OS account exists for the given username.
#
# Shared by auth-keys.sh (per-authentication) and user-sync.sh (reconciler).
# These accounts exist only to satisfy OpenSSH's per-user key lookup; real
# access is port forwarding (ProxyJump), which never invokes the login shell.
#
# Two things matter for OpenSSH to accept the account:
#   - It must exist in the OS user database before the connection: sshd will not
#     invoke AuthorizedKeysCommand for a username it cannot resolve.
#   - Its password field must NOT be locked. useradd/adduser default to a locked
#     ('!') password, which sshd refuses ("account is locked") even for pubkey
#     auth. We set it to '*' (no password, not locked) so key auth is allowed.
set -e

USERNAME="$1"
if [ -z "$USERNAME" ]; then
    exit 1
fi

# Validate username (defense in depth; matches the server-side regex).
if ! printf '%s' "$USERNAME" | grep -Eq '^[a-z][a-z0-9_-]{0,31}$'; then
    exit 1
fi

# Already present — nothing to do.
if id "$USERNAME" >/dev/null 2>&1; then
    exit 0
fi

NOLOGIN_SHELL=$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)

if command -v useradd >/dev/null 2>&1; then
    # -p '*' → shadow password '*' (no password, but NOT locked) so sshd accepts it.
    useradd --no-create-home --shell "$NOLOGIN_SHELL" -p '*' "$USERNAME" 2>/dev/null || true
elif command -v adduser >/dev/null 2>&1; then
    # BusyBox/Alpine adduser creates the account with login disabled; clear any
    # lock marker afterwards when a tool to do so is available.
    adduser -D -H -s "$NOLOGIN_SHELL" "$USERNAME" 2>/dev/null || true
    if command -v usermod >/dev/null 2>&1; then
        usermod -p '*' "$USERNAME" 2>/dev/null || true
    fi
fi

# Exit status reflects whether the account now exists.
id "$USERNAME" >/dev/null 2>&1
