#!/bin/bash
# RDP connect and screenshot

TARGET="$1"
USER="$2"
PASS="$3"
OUTPUT_DIR="/home/ov3rr1d3/wifi_arsenal/captures/evidence/$TARGET"

mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
SCREENSHOT="$OUTPUT_DIR/screenshot_${TIMESTAMP}.png"

echo "[*] Connecting to $TARGET as $USER"

# xfreerdp3 with screenshot
# /v: target
# /u: username
# /p: password
# /cert:ignore - ignore certificate warnings
# /auto-reconnect - try to reconnect
# +clipboard - enable clipboard
# /timeout:10000 - connection timeout

timeout 30 xfreerdp3 /v:"$TARGET" /u:"$USER" /p:"$PASS" \
    /cert:ignore \
    /timeout:10000 \
    /size:1920x1080 \
    +clipboard \
    /sec:any \
    2>&1 &

RDP_PID=$!
echo $RDP_PID > "/tmp/rdp_${TARGET}_pid.txt"

sleep 5

if ps -p $RDP_PID > /dev/null 2>&1; then
    echo "[+] RDP session started (PID: $RDP_PID)"
    echo "[+] Target: $TARGET"
    
    # Take screenshot after connection established
    sleep 3
    
    # Use scrot or import to capture the RDP window
    DISPLAY=:0 scrot -u "$SCREENSHOT" 2>/dev/null || \
    DISPLAY=:0 import -window root "$SCREENSHOT" 2>/dev/null
    
    if [ -f "$SCREENSHOT" ]; then
        echo "[+] Screenshot saved: $SCREENSHOT"
    fi
else
    echo "[-] RDP connection failed"
    exit 1
fi
