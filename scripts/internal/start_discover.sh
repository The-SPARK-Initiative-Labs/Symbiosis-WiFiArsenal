#!/bin/bash
# Start passive discovery

INTERFACE="${1:-alfa1}"
SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/scripts/internal"
PID_FILE="/tmp/discovery_pid.txt"
LOG_FILE="/home/ov3rr1d3/wifi_arsenal/captures/discovery.log"

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "[-] Discovery already running (PID: $OLD_PID)"
        exit 1
    fi
fi

echo "[*] Starting passive discovery on $INTERFACE"

# Start discovery in background
sudo python3 "$SCRIPT_DIR/discover.py" "$INTERFACE" > "$LOG_FILE" 2>&1 &
SUDO_PID=$!

sleep 2

# Find the actual python3 child of sudo (sudo PID != tool PID)
REAL_PID=$(pgrep -P $SUDO_PID -f "discover.py" 2>/dev/null || echo $SUDO_PID)
echo $REAL_PID > "$PID_FILE"

if ps -p $REAL_PID > /dev/null 2>&1; then
    echo "[+] Discovery started (PID: $REAL_PID)"
    echo "[+] Results: /home/ov3rr1d3/wifi_arsenal/captures/discovery_results.json"
else
    echo "[-] Discovery failed to start"
    cat "$LOG_FILE"
    exit 1
fi
