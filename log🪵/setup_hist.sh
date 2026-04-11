#!/bin/bash

cat << 'EOF' > /etc/profile.d/01initsys.sh
# Only run for interactive bash shells
case $- in
    *i*) ;;
    *) return ;;
esac

# History settings
export HISTTIMEFORMAT="%m %d %H:%M:%S "
export HISTCONTROL=ignoredups:erasedups
export HISTSIZE=100000
export HISTFILESIZE=200000

# Ensure history appends
shopt -s histappend

# Logging function runs every prompt
__hsab() {
    local TTY_SAFE USER_DIR

    TTY_SAFE=$(tty 2>/dev/null | tr '/' '.')
    USER_DIR="/var/log/hsab/$USER"

    # Create per-user directory if it doesn't exist
    if [ ! -d "$USER_DIR" ]; then
        mkdir -p "$USER_DIR" 2>/dev/null
        chmod 700 "$USER_DIR" 2>/dev/null
    fi

    HISTFILE="$USER_DIR/${TTY_SAFE}"

    # Append and reload history
    history -a
    history -n
}

PROMPT_COMMAND="__hsab"

readonly PROMPT_COMMAND
EOF

# Permissions
chmod 644 /etc/profile.d/01initsys.sh
chown root:root /etc/profile.d/01initsys.sh

echo "Installed updated logging config to /etc/profile.d/01initsys.sh"
