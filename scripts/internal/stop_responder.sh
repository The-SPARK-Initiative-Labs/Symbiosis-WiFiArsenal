#!/bin/bash
# Stop Responder

PID_FILE="/tmp/responder_pid.txt"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "[*] Stopping Responder (PID: $PID)"
        sudo kill "$PID" 2>/dev/null
        sleep 1
        sudo kill -9 "$PID" 2>/dev/null
        rm -f "$PID_FILE"
        echo "[+] Responder stopped"
    else
        echo "[*] Responder not running"
        rm -f "$PID_FILE"
    fi
else
    echo "[*] No PID file found"
fi

# Kill any orphaned responder processes
sudo pkill -f "responder" 2>/dev/null

# Stop hash monitor
pkill -f "monitor_hashes.sh" 2>/dev/null
