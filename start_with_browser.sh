#!/bin/bash
# WiFi Arsenal - Launch with Browser

# Trap exit signals and kill server
cleanup() {
    echo ""
    echo "Shutting down WiFi Arsenal..."
    if [ ! -z "$SERVER_PID" ]; then
        sudo kill $SERVER_PID 2>/dev/null
        sudo pkill -f "python3 server.py" 2>/dev/null
    fi
    exit 0
}

trap cleanup EXIT INT TERM

echo "🛡️  WiFi Arsenal - Starting..."

# Create logs directory if it doesn't exist
mkdir -p /home/ov3rr1d3/wifi_arsenal/logs

# Delete Python bytecode cache to prevent stale code issues
rm -rf /home/ov3rr1d3/wifi_arsenal/__pycache__
rm -f /home/ov3rr1d3/wifi_arsenal/*.pyc

# Start the server in background with logging
# All output goes to log file AND console
cd /home/ov3rr1d3/wifi_arsenal
export PYTHONDONTWRITEBYTECODE=1
LOG_FILE="/home/ov3rr1d3/wifi_arsenal/logs/flask_output.log"
echo "=== Flask Server Started: $(date) ===" | tee -a "$LOG_FILE"
sudo -E python3 server.py 2>&1 | tee -a "$LOG_FILE" &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Open browser and wait for it
echo "Opening browser..."
firefox http://localhost:5000

# Firefox closed - cleanup runs automatically via trap
echo ""
echo "Browser closed - shutting down..."
