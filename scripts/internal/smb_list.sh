#!/bin/bash
# List SMB shares on target

TARGET="$1"
USER="$2"
PASS="$3"
DOMAIN="${4:-WORKGROUP}"

if [ -z "$USER" ]; then
    # Anonymous access
    smbclient -L "//$TARGET" -N 2>&1
else
    smbclient -L "//$TARGET" -U "$DOMAIN\\$USER%$PASS" 2>&1
fi
