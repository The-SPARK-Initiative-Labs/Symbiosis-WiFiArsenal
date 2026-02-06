#!/bin/bash
# Stop passive discovery

PID_FILE="/tmp/discovery_pid.txt"
RUNNING_FLAG="/tmp/discovery_running"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "[*] Stopping discovery (PID: $PID)"
        sudo kill "$PID" 2>/dev/null
        sleep 1
        sudo kill -9 "$PID" 2>/dev/null
        rm -f "$PID_FILE"
        rm -f "$RUNNING_FLAG"
        echo "[+] Discovery stopped"
    else
        echo "[*] Discovery not running"
        rm -f "$PID_FILE"
    fi
else
    echo "[*] No PID file found"
    # Kill any orphaned processes
    sudo pkill -f "discover.py" 2>/dev/null
fi
