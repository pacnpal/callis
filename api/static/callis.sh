#!/bin/sh
# Callis CLI — tag-based SSH access through your Callis bastion.
#
# Usage:
#   . /path/to/callis.sh        (or add to your shell rc file)
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
    mkdir -m 700 -p "$CALLIS_CONFIG_DIR"
    chmod 700 "$CALLIS_CONFIG_DIR"

    printf "Callis server hostname: "
    read -r CALLIS_HOST
    if [ -z "$CALLIS_HOST" ]; then
        echo "Error: hostname is required." >&2
        return 1
    fi
    # Reject hostnames that start with '-' (would be parsed as options by
    # ssh-keyscan/ssh) or contain whitespace (not valid in a hostname).
    case "$CALLIS_HOST" in
        -*|*' '*|*'	'*)
            echo "Error: invalid hostname — must not start with '-' or contain whitespace." >&2
            return 1 ;;
    esac
    printf "Callis SSH port [2222]: "
    read -r CALLIS_PORT
    CALLIS_PORT="${CALLIS_PORT:-2222}"
    # Validate port: must be a plain positive integer in range 1-65535 with no
    # leading zeros (which could be misinterpreted as octal on some systems).
    case "$CALLIS_PORT" in
        ''|*[!0-9]*|0[0-9]*)
            echo "Error: invalid port — must be a positive number with no leading zeros." >&2
            return 1 ;;
    esac
    if [ "$CALLIS_PORT" -lt 1 ] || [ "$CALLIS_PORT" -gt 65535 ]; then
        echo "Error: invalid port — must be between 1 and 65535." >&2
        return 1
    fi
    printf "Your Callis username: "
    read -r CALLIS_USER
    if [ -z "$CALLIS_USER" ]; then
        echo "Error: username is required." >&2
        return 1
    fi
    printf "Path to your SSH key [$HOME/.ssh/id_ed25519]: "
    read -r CALLIS_KEY
    CALLIS_KEY="${CALLIS_KEY:-$HOME/.ssh/id_ed25519}"

    # Write values as plain key=value pairs (not sourced — parsed safely below).
    # Use a temp file + atomic mv so a failed write never leaves a partial config.
    TMP_CONFIG_FILE=$(mktemp "${CALLIS_CONFIG_FILE}.tmp.XXXXXX") || {
        echo "Error: could not create temporary config file." >&2
        return 1
    }
    if ! {
        printf 'CALLIS_HOST=%s\n' "$CALLIS_HOST"
        printf 'CALLIS_PORT=%s\n' "$CALLIS_PORT"
        printf 'CALLIS_USER=%s\n' "$CALLIS_USER"
        printf 'CALLIS_KEY=%s\n'  "$CALLIS_KEY"
    } > "$TMP_CONFIG_FILE"; then
        rm -f "$TMP_CONFIG_FILE"
        echo "Error: could not write configuration to temporary file." >&2
        return 1
    fi
    if ! chmod 600 "$TMP_CONFIG_FILE"; then
        rm -f "$TMP_CONFIG_FILE"
        echo "Error: could not set permissions on temporary config file." >&2
        return 1
    fi

    # Fetch the SSH host key, show its fingerprint, and require explicit user
    # confirmation before trusting it for future connections.
    # The config temp file is not committed until both files are ready so that
    # aborting or failing here never overwrites a previously working config.
    KNOWN_HOSTS_FILE="${CALLIS_CONFIG_DIR}/known_hosts"
    TMP_KNOWN_HOSTS_FILE=$(mktemp "${KNOWN_HOSTS_FILE}.tmp.XXXXXX") || {
        rm -f "$TMP_CONFIG_FILE"
        echo "Error: could not create temporary known_hosts file." >&2
        return 1
    }
    printf "Fetching SSH host key from %s:%s...\n" "$CALLIS_HOST" "$CALLIS_PORT"
    FETCHED=$(ssh-keyscan -T 10 -p "$CALLIS_PORT" -t ed25519 -- "$CALLIS_HOST" 2>/dev/null)
    if [ -n "$FETCHED" ]; then
        if ! printf '%s\n' "$FETCHED" > "$TMP_KNOWN_HOSTS_FILE"; then
            rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE"
            echo "Error: could not write SSH host key to temporary file." >&2
            return 1
        fi
        FINGERPRINT=$(ssh-keygen -lf "$TMP_KNOWN_HOSTS_FILE" 2>/dev/null)
        if [ -z "$FINGERPRINT" ]; then
            rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE"
            echo "Error: could not compute SSH host key fingerprint for ${CALLIS_HOST}:${CALLIS_PORT}." >&2
            return 1
        fi

        echo "Fetched SSH host key fingerprint:"
        printf '  %s\n' "$FINGERPRINT"
        echo "Verify this fingerprint with your administrator or another trusted out-of-band source before continuing."
        printf "Trust and save this host key? Type 'yes' to continue: "
        read -r TRUST_HOST_KEY
        if [ "$TRUST_HOST_KEY" != "yes" ]; then
            rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE"
            echo "Host key was not saved. Setup aborted." >&2
            return 1
        fi

        # Use -f (existence) not -s (non-empty) so empty or corrupt files also
        # trigger the overwrite confirmation and are not silently replaced.
        if [ -f "$KNOWN_HOSTS_FILE" ]; then
            echo "Warning: ${KNOWN_HOSTS_FILE} already exists and will be replaced."
            printf "Type 'yes' to overwrite the existing Callis host key: "
            read -r OVERWRITE_KNOWN_HOSTS
            if [ "$OVERWRITE_KNOWN_HOSTS" != "yes" ]; then
                rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE"
                echo "Existing host key was left unchanged. Setup aborted." >&2
                return 1
            fi
        fi

        # Back up the existing known_hosts so it can be restored if the final
        # config commit fails, ensuring no partial state is left on disk.
        BACKUP_KNOWN_HOSTS=""
        if [ -f "$KNOWN_HOSTS_FILE" ]; then
            BACKUP_KNOWN_HOSTS=$(mktemp "${KNOWN_HOSTS_FILE}.bak.XXXXXX") || {
                rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE"
                echo "Error: could not create backup of existing known_hosts." >&2
                return 1
            }
            if ! cp "$KNOWN_HOSTS_FILE" "$BACKUP_KNOWN_HOSTS"; then
                rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE" "$BACKUP_KNOWN_HOSTS"
                echo "Error: could not back up existing known_hosts." >&2
                return 1
            fi
        fi

        if ! mv "$TMP_KNOWN_HOSTS_FILE" "$KNOWN_HOSTS_FILE"; then
            if [ -n "$BACKUP_KNOWN_HOSTS" ]; then
                rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE" "$BACKUP_KNOWN_HOSTS"
            else
                rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE"
            fi
            echo "Error: could not save SSH host key to ${KNOWN_HOSTS_FILE}." >&2
            return 1
        fi
        if ! chmod 600 "$KNOWN_HOSTS_FILE"; then
            if [ -n "$BACKUP_KNOWN_HOSTS" ]; then
                mv "$BACKUP_KNOWN_HOSTS" "$KNOWN_HOSTS_FILE" || \
                    echo "Warning: could not restore previous known_hosts from ${BACKUP_KNOWN_HOSTS}." >&2
            else
                rm -f "$KNOWN_HOSTS_FILE"
            fi
            rm -f "$TMP_CONFIG_FILE"
            echo "Error: could not set permissions on ${KNOWN_HOSTS_FILE}." >&2
            return 1
        fi
        # Both files are ready — atomically commit the config last so that
        # any earlier abort leaves the previous config intact.
        if ! mv "$TMP_CONFIG_FILE" "$CALLIS_CONFIG_FILE"; then
            if [ -n "$BACKUP_KNOWN_HOSTS" ]; then
                mv "$BACKUP_KNOWN_HOSTS" "$KNOWN_HOSTS_FILE" || \
                    echo "Warning: could not restore previous known_hosts from ${BACKUP_KNOWN_HOSTS}." >&2
            else
                rm -f "$KNOWN_HOSTS_FILE"
            fi
            rm -f "$TMP_CONFIG_FILE"
            echo "Error: could not save configuration to ${CALLIS_CONFIG_FILE}." >&2
            return 1
        fi
        if [ -n "$BACKUP_KNOWN_HOSTS" ]; then
            rm -f "$BACKUP_KNOWN_HOSTS"
        fi
        echo "Setup complete. Configuration and host key saved."
    else
        rm -f "$TMP_KNOWN_HOSTS_FILE" "$TMP_CONFIG_FILE"
        echo "Error: could not fetch SSH host key from ${CALLIS_HOST}:${CALLIS_PORT}." >&2
        echo "Ensure the server is reachable and run 'callis setup' again." >&2
        return 1
    fi
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

_callis_has_known_hosts_entries() {
    known_hosts_file="$1"
    # Use -r (readable) instead of -s (non-empty) so unreadable files are
    # rejected cleanly; the grep handles empty files by returning non-zero.
    [ -r "$known_hosts_file" ] || return 1
    grep -Eq '^[[:space:]]*[^#[:space:]]' "$known_hosts_file" 2>/dev/null
}

# POSIX single-quote escaping: wraps the argument in single quotes and escapes
# any embedded single quotes so the result is safe for shell evaluation (e.g.,
# inside a ProxyCommand string that OpenSSH passes to a shell).
_callis_sq() {
    printf '%s' "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/"
}

_callis_list() {
    _callis_load_config || return 1
    if ! _callis_has_known_hosts_entries "${CALLIS_CONFIG_DIR}/known_hosts"; then
        echo "Error: SSH host key file is missing, empty, or invalid. Run 'callis setup' to fetch it again." >&2
        return 1
    fi
    ssh -i "$CALLIS_KEY" -p "$CALLIS_PORT" \
        -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o GlobalKnownHostsFile=/dev/null \
        -o UserKnownHostsFile="${CALLIS_CONFIG_DIR}/known_hosts" \
        "${CALLIS_USER}@${CALLIS_HOST}" list
}

_callis_connect() {
    _callis_load_config || return 1
    TAG="$1"
    shift

    case "$TAG" in
        ''|*[!a-z0-9-]*|-*|*-|*--*)
            echo "Error: invalid host tag — tags must use lowercase letters and digits separated by single hyphens, with no leading or trailing hyphen" >&2
            return 1 ;;
    esac

    if ! _callis_has_known_hosts_entries "${CALLIS_CONFIG_DIR}/known_hosts"; then
        echo "Error: SSH host key file is missing, empty, or invalid. Run 'callis setup' to fetch it again." >&2
        return 1
    fi

    STDERR_TMP_CREATED=0
    if STDERR_TMP=$(mktemp "${TMPDIR:-/tmp}/callis-err.XXXXXX"); then
        STDERR_TMP_CREATED=1
    else
        STDERR_TMP="/dev/null"
    fi

    DEST=$(ssh -i "$CALLIS_KEY" -p "$CALLIS_PORT" \
        -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o GlobalKnownHostsFile=/dev/null \
        -o UserKnownHostsFile="${CALLIS_CONFIG_DIR}/known_hosts" \
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

    # Validate bastion-supplied TARGET_HOST and TARGET_PORT to prevent shell
    # injection via OpenSSH's %h/%p substitution in ProxyCommand.
    case "$TARGET_HOST" in
        ''|*[!A-Za-z0-9._-]*)
            echo "Error: bastion returned an invalid target host" >&2
            return 1 ;;
    esac
    case "$TARGET_PORT" in
        ''|*[!0-9]*|0[0-9]*)
            echo "Error: bastion returned an invalid target port" >&2
            return 1 ;;
    esac
    if [ "$TARGET_PORT" -lt 1 ] || [ "$TARGET_PORT" -gt 65535 ]; then
        echo "Error: bastion returned an invalid target port" >&2
        return 1
    fi

    # Build ProxyCommand using POSIX single-quote escaping so user-controlled
    # values (key path, port, username, hostname) cannot inject shell metacharacters
    # when OpenSSH evaluates the command string. Quote %h:%p as a single shell
    # argument so OpenSSH substitution cannot introduce shell syntax.
    _escaped_key=$(_callis_sq "$CALLIS_KEY")
    _escaped_port=$(_callis_sq "$CALLIS_PORT")
    _escaped_user=$(_callis_sq "$CALLIS_USER")
    _escaped_host=$(_callis_sq "$CALLIS_HOST")
    _escaped_known=$(_callis_sq "${CALLIS_CONFIG_DIR}/known_hosts")
    PROXY_COMMAND="ssh -i ${_escaped_key} -p ${_escaped_port} -o BatchMode=yes -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=${_escaped_known} -W '%h:%p' ${_escaped_user}@${_escaped_host}"

    # Separate user-supplied SSH option flags from any trailing remote command.
    # Leading args that begin with '-' (including their next-arg values for
    # options that require them) are treated as SSH flags and placed after the
    # enforced security options below.  The first non-flag arg (or any args
    # after '--') form the remote command and are placed after the destination.
    # This means the enforced options always appear first and cannot be
    # overridden (OpenSSH uses first-occurrence semantics for -o options).
    #
    # SSH options that consume the next positional argument as their value:
    _nflags=0
    _skip_next=0
    for _ua in "$@"; do
        if [ "$_skip_next" -eq 1 ]; then
            _nflags=$((_nflags + 1)); _skip_next=0; continue
        fi
        case "$_ua" in
            --) break ;;
            # Options that take a next argument as a *separate* token.
            # When the value is concatenated in the same token (e.g.,
            # -L8080:host:port or -oStrictHostKeyChecking=yes), the token
            # length is > 2 and the value is already present, so do NOT
            # set _skip_next in that case.
            -b|-c|-D|-E|-e|-F|-I|-i|-J|-L|-l|-m|-o|-p|-Q|-R|-S|-w|-W)
                _nflags=$((_nflags + 1))
                if [ "${#_ua}" -eq 2 ]; then _skip_next=1; fi ;;
            -*) _nflags=$((_nflags + 1)) ;;
            *)  break ;;
        esac
    done

    # Build single-quoted strings for the flag and command portions so they
    # can be safely re-split by eval without shell-injection risk.
    _uf=''
    _uc=''
    _ui=0
    for _ua in "$@"; do
        _ui=$((_ui + 1))
        _q=$(_callis_sq "$_ua")
        if   [ "$_ui" -le "$_nflags" ]; then
            _uf="${_uf:+$_uf }$_q"
        elif [ "$_ua" = "--" ] && [ "$_ui" -eq "$((_nflags + 1))" ]; then
            :   # drop the '--' separator — not needed in the final ssh call
        else
            _uc="${_uc:+$_uc }$_q"
        fi
    done

    _sq_key=$(_callis_sq "$CALLIS_KEY")
    _sq_proxy=$(_callis_sq "$PROXY_COMMAND")
    _sq_dest=$(_callis_sq "${CALLIS_USER}@${TARGET_HOST}")
    _sq_known=$(_callis_sq "${HOME}/.ssh/known_hosts")

    # Enforced -o options come first so they take precedence (first-occurrence
    # wins in OpenSSH for -o flags).  User option flags follow.  -p comes after
    # user flags because OpenSSH uses last-occurrence semantics for -p, so
    # placing it last ensures the bastion-resolved target port cannot be
    # overridden by a user-supplied -p flag.  The fixed destination follows,
    # then any user-supplied remote command arguments.
    # shellcheck disable=SC2086
    eval ssh \
        -i "$_sq_key" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=yes \
        -o GlobalKnownHostsFile=/dev/null \
        -o "UserKnownHostsFile=$_sq_known" \
        -o "ProxyCommand=$_sq_proxy" \
        ${_uf} \
        -p "$TARGET_PORT" \
        "$_sq_dest" \
        ${_uc}
}
