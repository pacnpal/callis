#!/bin/sh
# OS account reconciler.
#
# OpenSSH does not invoke AuthorizedKeysCommand for a username that is missing
# from the OS user database — it rejects it as an invalid user before the key
# lookup runs — so auth-keys.sh cannot bootstrap a brand-new user on its own.
# This loop closes that gap: it periodically asks the internal API for the list
# of active users that have an active SSH key and pre-creates an (unlocked,
# nologin) OS account for each, so the account already exists when the user
# first connects.
#
# Runs in the background alongside sshd. Failures are non-fatal — a missed cycle
# only delays account creation until the next pass. No `set -e`: this loop must
# never exit on a transient error (e.g. the API not being ready yet at startup).

API_HOST="${CALLIS_API_HOST:-localhost}"
SYNC_INTERVAL="${CALLIS_USER_SYNC_INTERVAL:-30}"

# Resolve the internal API secret. Prefer the env var; fall back to deriving it
# from the persisted SECRET_KEY the same way entrypoint.sh does. The env var is
# not always present here, and OpenSSH strips it from the AuthorizedKeysCommand
# environment, so the file fallback is what makes lookups reliable.
resolve_secret() {
    _secret="${CALLIS_INTERNAL_SECRET:-}"
    if [ -z "$_secret" ] && [ -r /run/callis/internal_secret ]; then
        _secret=$(cat /run/callis/internal_secret 2>/dev/null)
    fi
    if [ -z "$_secret" ] && [ -r /data/.secret_key ]; then
        _secret=$(printf 'callis-internal' \
            | openssl dgst -sha256 -hmac "$(cat /data/.secret_key)" -hex 2>/dev/null \
            | awk '{print $NF}')
    fi
    printf '%s' "$_secret"
}

# Returns 0 when it successfully reached the API (HTTP 200), non-zero otherwise.
sync_once() {
    _sec=$(resolve_secret)
    [ -n "$_sec" ] || return 1

    _tmp=$(mktemp 2>/dev/null) || return 1
    _status=$(curl -sS --max-time 5 \
        -o "$_tmp" -w '%{http_code}' \
        -H "X-Internal-Secret: ${_sec}" \
        "http://${API_HOST}:8081/internal/users" 2>/dev/null) || _status="000"

    _rc=1
    if [ "$_status" = "200" ]; then
        while IFS= read -r _u; do
            [ -n "$_u" ] || continue
            /etc/ssh/ensure-user.sh "$_u" >/dev/null 2>&1 || true
        done < "$_tmp"
        _rc=0
    fi

    rm -f "$_tmp"
    return "$_rc"
}

# Retry sync_once every 5s until it reaches the API or hits the attempt cap.
# Returns 0 once a reconciliation succeeded, 1 if the cap was exhausted.
initial_sync() {
    _tries=0
    until sync_once; do
        _tries=$((_tries + 1))
        [ "$_tries" -ge "${1:-12}" ] && return 1
        sleep 5
    done
    return 0
}

# --once: a bounded, blocking reconciliation used by the entrypoint to gate sshd
# startup, so existing key-bearing users are provisioned before connections are
# accepted. Bounded low so a slow/unavailable API cannot stall sshd for long.
if [ "${1:-}" = "--once" ]; then
    initial_sync 3 || true
    exit 0
fi

# Background mode: converge at startup, then reconcile on the steady interval.
initial_sync 12 || true
while true; do
    sleep "$SYNC_INTERVAL"
    sync_once || true
done
