#!/bin/bash
# Download file from SMB share

TARGET="$1"
SHARE="$2"
REMOTE_PATH="$3"
USER="$4"
PASS="$5"
DOMAIN="${6:-WORKGROUP}"

OUTPUT_DIR="/home/ov3rr1d3/wifi_arsenal/captures/evidence/$TARGET"
mkdir -p "$OUTPUT_DIR"

LOCAL_FILE="$OUTPUT_DIR/$(basename "$REMOTE_PATH")"

if [ -z "$USER" ]; then
    smbclient "//$TARGET/$SHARE" -N -c "get \"$REMOTE_PATH\" \"$LOCAL_FILE\"" 2>&1
else
    smbclient "//$TARGET/$SHARE" -U "$DOMAIN\\$USER%$PASS" -c "get \"$REMOTE_PATH\" \"$LOCAL_FILE\"" 2>&1
fi

if [ -f "$LOCAL_FILE" ]; then
    echo "[+] Downloaded: $LOCAL_FILE"
else
    echo "[-] Download failed"
    exit 1
fi
