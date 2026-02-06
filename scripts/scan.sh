#!/bin/bash
# WiFi Network Scanner with Auto Mode Management
# Usage: ./scan.sh [duration_in_seconds]

DURATION=${1:-30}
CAPTURE_DIR="/home/ov3rr1d3/wifi_arsenal/captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_PREFIX="$CAPTURE_DIR/scan_$TIMESTAMP"
SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/scripts"

# Kill any lingering processes that might block the interface
echo "[*] Cleaning up any lingering processes..."
sudo pkill -9 -f "airodump-ng" 2>/dev/null
sudo pkill -9 -f "aireplay-ng" 2>/dev/null
sleep 1

# Ensure alfa0 is in monitor mode
echo "[*] Checking alfa0 mode..."
$SCRIPT_DIR/mode_manager.sh ensure alfa0 monitor

if [ $? -ne 0 ]; then
    echo "[-] Failed to set monitor mode"
    exit 1
fi

echo "[*] Starting WiFi scan on alfa0 for $DURATION seconds..."
echo "[*] Results will be saved to: $OUTPUT_PREFIX"

# Run airodump-ng
sudo timeout $DURATION airodump-ng alfa0 \
    --band abg \
    --output-format csv \
    --write "$OUTPUT_PREFIX" \
    2>/dev/null

# Parse and display results
if [ -f "${OUTPUT_PREFIX}-01.csv" ]; then
    echo ""
    echo "=== Networks Found ==="
    echo ""
    
    # Extract and format AP data
    awk -F',' '/^[A-F0-9:]{17}/ && NF > 13 {
        bssid=$1
        channel=$4
        encryption=$6
        power=$9
        ssid=$14
        gsub(/^[ \t]+|[ \t]+$/, "", ssid)
        if (ssid == "") ssid="<hidden>"
        printf "%-17s  CH:%-3s  PWR:%-4s  %-10s  %s\n", bssid, channel, power, encryption, ssid
    }' "${OUTPUT_PREFIX}-01.csv"
    
    echo ""
    echo "[+] Scan complete. Full details in: ${OUTPUT_PREFIX}-01.csv"
else
    echo "[-] No networks found or scan failed"
fi
