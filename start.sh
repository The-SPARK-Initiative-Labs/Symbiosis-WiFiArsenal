#!/bin/bash
# WiFi Arsenal - Startup Script

echo "🛡️  WiFi Arsenal - Sh4d0wFr4m3"
echo "================================"
echo ""

# Delete Python bytecode cache to prevent stale code issues
echo "Cleaning Python cache..."
rm -rf /home/ov3rr1d3/wifi_arsenal/__pycache__
rm -f /home/ov3rr1d3/wifi_arsenal/*.pyc

echo "Starting web server..."
echo ""

cd /home/ov3rr1d3/wifi_arsenal

# Prevent Python from writing bytecode files
export PYTHONDONTWRITEBYTECODE=1

sudo -E python3 server.py
