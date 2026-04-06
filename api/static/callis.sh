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
  callis mac-mini
  callis web-prod -L 8080:localhost:8080
USAGE
}

_callis_setup() {
    mkdir -p "$CALLIS_CONFIG_DIR"

    printf "Callis server hostname: "
    read -r CALLIS_HOST
    printf "Callis SSH port [2222]: "
    read -r CALLIS_PORT
    CALLIS_PORT="${CALLIS_PORT:-2222}"
    printf "Your Callis username: "
    read -r CALLIS_USER
    printf "Path to your SSH key [$HOME/.ssh/id_ed25519]: "
    read -r CALLIS_KEY
    CALLIS_KEY="${CALLIS_KEY:-$HOME/.ssh/id_ed25519}"

    # Write values as plain key=value pairs (not sourced — parsed safely below)
    {
        printf 'CALLIS_HOST=%s\n' "$CALLIS_HOST"
        printf 'CALLIS_PORT=%s\n' "$CALLIS_PORT"
        printf 'CALLIS_USER=%s\n' "$CALLIS_USER"
        printf 'CALLIS_KEY=%s\n'  "$CALLIS_KEY"
    } > "$CALLIS_CONFIG_FILE"
    chmod 600 "$CALLIS_CONFIG_FILE"

    echo "Configuration saved to ${CALLIS_CONFIG_FILE}"
}

_callis_load_config() {
    if [ ! -f "$CALLIS_CONFIG_FILE" ]; then
        echo "Error: not configured. Run 'callis setup' first." >&2
        return 1
    fi
    # Reset variables before parsing so partial/corrupt config is detected below
    CALLIS_HOST=""
    CALLIS_PORT=""
    CALLIS_USER=""
    CALLIS_KEY=""
    # Parse key=value pairs without sourcing the file (prevents code injection)
    while IFS= read -r line; do
        case "$line" in
            CALLIS_HOST=*) CALLIS_HOST="${line#CALLIS_HOST=}" ;;
            CALLIS_PORT=*) CALLIS_PORT="${line#CALLIS_PORT=}" ;;
            CALLIS_USER=*) CALLIS_USER="${line#CALLIS_USER=}" ;;
            CALLIS_KEY=*)  CALLIS_KEY="${line#CALLIS_KEY=}"  ;;
        esac
    done < "$CALLIS_CONFIG_FILE"
    # Validate all required fields are present
    if [ -z "$CALLIS_HOST" ] || [ -z "$CALLIS_PORT" ] || [ -z "$CALLIS_USER" ] || [ -z "$CALLIS_KEY" ]; then
        echo "Error: config file is incomplete or corrupt. Run 'callis setup' to reconfigure." >&2
        return 1
    fi
    # Expand a leading ~ in the key path (for backwards compatibility)
    case "$CALLIS_KEY" in
        "~")   CALLIS_KEY="$HOME" ;;
        "~/"*) CALLIS_KEY="$HOME/${CALLIS_KEY#~/}" ;;
    esac
}

_callis_list() {
    _callis_load_config || return 1
    ssh -i "$CALLIS_KEY" -p "$CALLIS_PORT" \
        -o BatchMode=yes -o StrictHostKeyChecking=ask \
        "${CALLIS_USER}@${CALLIS_HOST}" list
}

_callis_connect() {
    _callis_load_config || return 1
    TAG="$1"
    shift

    case "$TAG" in
        ''|*[!a-z0-9-]*|-*)
            echo "Error: invalid host tag — tags may only contain lowercase letters, digits, and hyphens" >&2
            return 1 ;;
    esac

    STDERR_TMP_CREATED=0
    if STDERR_TMP=$(mktemp "${TMPDIR:-/tmp}/callis-err.XXXXXX"); then
        STDERR_TMP_CREATED=1
    else
        STDERR_TMP="/dev/null"
    fi

    DEST=$(ssh -i "$CALLIS_KEY" -p "$CALLIS_PORT" \
        -o BatchMode=yes \
        "${CALLIS_USER}@${CALLIS_HOST}" "resolve ${TAG}" 2>"$STDERR_TMP")

    if [ -z "$DEST" ]; then
        if [ "$STDERR_TMP_CREATED" -eq 1 ] && [ -s "$STDERR_TMP" ]; then
            cat "$STDERR_TMP" >&2
        else
            echo "Error: host '${TAG}' not found or not authorized" >&2
        fi
        if [ "$STDERR_TMP_CREATED" -eq 1 ]; then
            rm -f "$STDERR_TMP"
        fi
        return 1
    fi
    if [ "$STDERR_TMP_CREATED" -eq 1 ]; then
        rm -f "$STDERR_TMP"
    fi

    TARGET_HOST=$(echo "$DEST" | awk '{print $1}')
    TARGET_PORT=$(echo "$DEST" | awk '{print $2}')

    ssh -i "$CALLIS_KEY" \
        -J "${CALLIS_USER}@${CALLIS_HOST}:${CALLIS_PORT}" \
        -p "$TARGET_PORT" "$@" \
        "${CALLIS_USER}@${TARGET_HOST}"
}
