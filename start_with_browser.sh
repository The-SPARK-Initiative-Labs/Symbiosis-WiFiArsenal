#!/bin/bash
# WiFi Arsenal - Launch with Browser
# Starts Flask server, opens Firefox, cleans up when Firefox closes

ARSENAL_DIR="/home/ov3rr1d3/wifi_arsenal"
LOG_FILE="$ARSENAL_DIR/logs/flask_output.log"
PID_FILE="$ARSENAL_DIR/logs/server.pid"
MAX_LOG_SIZE=5242880  # 5MB

cleanup() {
    echo ""
    echo "Shutting down WiFi Arsenal..."

    # Kill the server by saved PID
    if [ -f "$PID_FILE" ]; then
        SERVER_PID=$(cat "$PID_FILE")
        sudo kill "$SERVER_PID" 2>/dev/null
        rm -f "$PID_FILE"
    fi

    # Kill any remaining server processes
    sudo pkill -f "python3 server.py" 2>/dev/null

    # Kill the tee logger if still running
    [ ! -z "$TEE_PID" ] && kill "$TEE_PID" 2>/dev/null

    # Wait briefly for processes to die
    sleep 1

    echo "WiFi Arsenal stopped."
    # Kill the entire process tree (closes the terminal window)
    kill -9 0 2>/dev/null
}

trap cleanup EXIT INT TERM

echo "==============================="
echo "  WiFi Arsenal - Sh4d0wFr4m3"
echo "==============================="
echo ""

# --- Check if already running on port 5000 ---
if ss -tlnp 2>/dev/null | grep -q ':5000 '; then
    echo "[!] Port 5000 is already in use."
    echo "    Killing existing server..."
    sudo pkill -f "python3 server.py" 2>/dev/null
    sleep 2
    if ss -tlnp 2>/dev/null | grep -q ':5000 '; then
        echo "[X] Could not free port 5000. Something else is using it."
        echo "    Run: sudo lsof -i :5000"
        read -p "Press Enter to exit..."
        exit 1
    fi
    echo "    Previous server killed."
fi

# --- Setup ---
mkdir -p "$ARSENAL_DIR/logs"

# Clean Python bytecode cache
rm -rf "$ARSENAL_DIR/__pycache__"
rm -f "$ARSENAL_DIR"/*.pyc

# --- Log rotation ---
if [ -f "$LOG_FILE" ] && [ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]; then
    echo "[*] Rotating log file (>5MB)..."
    mv "$LOG_FILE" "${LOG_FILE}.old"
fi

# --- Start server ---
cd "$ARSENAL_DIR"
export PYTHONDONTWRITEBYTECODE=1

echo "=== Flask Server Started: $(date) ===" | tee -a "$LOG_FILE"
echo "[*] Starting server..."

# Start server with a named pipe so we can capture the real PID
sudo -E systemd-inhibit --what=sleep:idle:handle-lid-switch --who="WiFi Arsenal" --why="Arsenal running - stay awake" --mode=block python3 server.py 2>&1 | tee -a "$LOG_FILE" &
TEE_PID=$!

# Wait for the actual python process to appear and save its PID
sleep 1
REAL_PID=$(pgrep -f "python3 server.py" | head -1)
if [ ! -z "$REAL_PID" ]; then
    echo "$REAL_PID" > "$PID_FILE"
fi

# --- Wait for server to be ready (up to 15 seconds) ---
echo "[*] Waiting for server..."
for i in $(seq 1 15); do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 2>/dev/null | grep -q "200"; then
        echo "[+] Server ready! (${i}s)"
        break
    fi
    if [ $i -eq 15 ]; then
        echo "[!] Server didn't respond after 15s. Opening browser anyway..."
    fi
    sleep 1
done

# --- Open browser (blocks until Firefox closes) ---
echo "[*] Opening Firefox..."
echo ""
firefox http://localhost:5000

# Firefox closed - cleanup runs via trap
echo ""
echo "Firefox closed - shutting down..."
