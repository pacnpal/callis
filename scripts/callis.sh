#!/bin/sh
# Callis CLI — tag-based SSH access through your Callis bastion.
#
# Usage:
#   source /path/to/callis.sh   (or add to your shell rc file)
#   callis setup                 — configure connection details
#   callis list                  — show available hosts
#   callis <tag> [ssh args...]   — connect to a host by tag
#
# Configuration is stored in ~/.config/callis/config

CALLIS_CONFIG_DIR="${HOME}/.config/callis"
CALLIS_CONFIG_FILE="${CALLIS_CONFIG_DIR}/config"

callis() {
    case "${1:-}" in
        setup)
            _callis_setup
            ;;
        list)
            _callis_list
            ;;
        ""|help|-h|--help)
            _callis_help
            ;;
        *)
            _callis_connect "$@"
            ;;
    esac
}

_callis_help() {
    cat <<'USAGE'
Usage: callis <command>

Commands:
  setup              Configure Callis connection details
  list               Show available hosts
  <tag> [ssh args]   Connect to a host by tag

Examples:
  callis setup
  callis list
  callis macmini
  callis web-prod -L 8080:localhost:8080
USAGE
}

_callis_setup() {
    mkdir -p "$CALLIS_CONFIG_DIR"

    printf "Callis server hostname: "
    read CALLIS_HOST
    printf "Callis SSH port [2222]: "
    read CALLIS_PORT
    CALLIS_PORT="${CALLIS_PORT:-2222}"
    printf "Your Callis username: "
    read CALLIS_USER
    printf "Path to your SSH key [~/.ssh/id_ed25519]: "
    read CALLIS_KEY
    CALLIS_KEY="${CALLIS_KEY:-~/.ssh/id_ed25519}"

    cat > "$CALLIS_CONFIG_FILE" <<EOF
CALLIS_HOST=${CALLIS_HOST}
CALLIS_PORT=${CALLIS_PORT}
CALLIS_USER=${CALLIS_USER}
CALLIS_KEY=${CALLIS_KEY}
EOF

    echo "Configuration saved to ${CALLIS_CONFIG_FILE}"
}

_callis_load_config() {
    if [ ! -f "$CALLIS_CONFIG_FILE" ]; then
        echo "Error: not configured. Run 'callis setup' first." >&2
        return 1
    fi
    . "$CALLIS_CONFIG_FILE"
}

_callis_list() {
    _callis_load_config || return 1
    ssh -i "$CALLIS_KEY" -p "$CALLIS_PORT" \
        -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        "${CALLIS_USER}@${CALLIS_HOST}" list
}

_callis_connect() {
    _callis_load_config || return 1
    TAG="$1"
    shift

    DEST=$(ssh -i "$CALLIS_KEY" -p "$CALLIS_PORT" \
        -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        "${CALLIS_USER}@${CALLIS_HOST}" "resolve ${TAG}" 2>/dev/null)

    if [ -z "$DEST" ]; then
        echo "Error: host '${TAG}' not found or not authorized" >&2
        return 1
    fi

    TARGET_HOST=$(echo "$DEST" | awk '{print $1}')
    TARGET_PORT=$(echo "$DEST" | awk '{print $2}')

    ssh -i "$CALLIS_KEY" \
        -J "${CALLIS_USER}@${CALLIS_HOST}:${CALLIS_PORT}" \
        "${CALLIS_USER}@${TARGET_HOST}" -p "$TARGET_PORT" "$@"
}
