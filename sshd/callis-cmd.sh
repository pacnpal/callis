#!/bin/sh
# ForceCommand script: routes SSH exec requests.
# ProxyJump/port-forwarding connections bypass this entirely (direct-tcpip).
set -e

USERNAME=$(whoami)
CMD="${SSH_ORIGINAL_COMMAND:-}"
API_HOST="${CALLIS_API_HOST:-localhost}"
INTERNAL_SECRET="${CALLIS_INTERNAL_SECRET:-}"

_curl_with_status() {
    # Usage: _curl_with_status <url>
    # Writes body to stdout, HTTP status code to $HTTP_CODE
    TMPBODY=$(mktemp "${TMPDIR:-/tmp}/callis.XXXXXX") || { echo "ERR failed to create temp file" >&2; exit 1; }
    trap 'rm -f "$TMPBODY"' EXIT INT TERM
    HTTP_CODE=$(curl -s --max-time 5 \
      -H "X-Internal-Secret: ${INTERNAL_SECRET}" \
      -o "$TMPBODY" -w '%{http_code}' \
      "$1" 2>/dev/null) || HTTP_CODE="000"
    cat "$TMPBODY" 2>/dev/null
    rm -f "$TMPBODY"
    trap - EXIT INT TERM
}

case "$CMD" in
  resolve\ *)
    TAG=$(echo "$CMD" | cut -d' ' -f2 | tr -cd 'a-z0-9-')
    if [ -z "$TAG" ]; then
      echo "ERR missing or invalid host tag" >&2
      exit 1
    fi
    RESULT=$(_curl_with_status \
      "http://${API_HOST}:8081/internal/resolve/${USERNAME}/${TAG}")
    if [ "$HTTP_CODE" = "403" ]; then
      echo "ERR internal auth failed" >&2
      exit 1
    elif [ "$HTTP_CODE" = "409" ]; then
      echo "ERR ambiguous host tag: multiple hosts share that tag" >&2
      exit 1
    elif [ "$HTTP_CODE" = "000" ]; then
      echo "ERR service unavailable" >&2
      exit 1
    elif [ "$HTTP_CODE" = "200" ] && [ -n "$RESULT" ]; then
      echo "$RESULT"
    elif [ "$HTTP_CODE" = "200" ]; then
      echo "ERR host not found or not authorized" >&2
      exit 1
    else
      echo "ERR internal API error (${HTTP_CODE})" >&2
      exit 1
    fi
    ;;
  list)
    RESULT=$(_curl_with_status \
      "http://${API_HOST}:8081/internal/hosts/${USERNAME}")
    if [ "$HTTP_CODE" = "403" ]; then
      echo "ERR internal auth failed" >&2
      exit 1
    elif [ "$HTTP_CODE" = "000" ]; then
      echo "ERR service unavailable" >&2
      exit 1
    elif [ "$HTTP_CODE" = "200" ]; then
      if [ -n "$RESULT" ]; then
        printf '%s\n' "$RESULT"
      else
        echo "No hosts assigned to user" >&2
        exit 2
      fi
    else
      echo "ERR internal API error (${HTTP_CODE})" >&2
      exit 1
    fi
    ;;
  *)
    echo "This account is not available." >&2
    exit 1
    ;;
esac
