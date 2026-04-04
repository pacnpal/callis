#!/bin/sh
# ForceCommand script: routes SSH exec requests.
# ProxyJump/port-forwarding connections bypass this entirely (direct-tcpip).
set -e

USERNAME=$(whoami)
CMD="${SSH_ORIGINAL_COMMAND:-}"
API_HOST="${CALLIS_API_HOST:-localhost}"
INTERNAL_SECRET="${CALLIS_INTERNAL_SECRET:-}"

case "$CMD" in
  resolve\ *)
    TAG=$(echo "$CMD" | cut -d' ' -f2 | tr -cd 'a-z0-9-')
    RESULT=$(curl -sf --max-time 5 \
      -H "X-Internal-Secret: ${INTERNAL_SECRET}" \
      "http://${API_HOST}:8081/internal/resolve/${USERNAME}/${TAG}" 2>/dev/null)
    if [ -n "$RESULT" ]; then
      echo "$RESULT"
    else
      echo "ERR host not found or not authorized" >&2
      exit 1
    fi
    ;;
  list)
    curl -sf --max-time 5 \
      -H "X-Internal-Secret: ${INTERNAL_SECRET}" \
      "http://${API_HOST}:8081/internal/hosts/${USERNAME}" 2>/dev/null
    ;;
  *)
    echo "This account is not available." >&2
    exit 1
    ;;
esac
