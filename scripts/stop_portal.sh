#!/bin/bash
# Evil Portal - Stop Script
# Cleanly shut down all portal services including Deauth Companion

INTERFACE="alfa0"
DEAUTH_INTERFACE="alfa1"
ORIGINAL_MAC_FILE="/tmp/portal_original_mac.txt"

echo "[*] Stopping Evil Portal..."

# Kill deauth first
if [ -f /tmp/deauth_pid.txt ]; then
    DEAUTH_PID=$(cat /tmp/deauth_pid.txt)
    echo "[*] Stopping Deauth Companion (PID: $DEAUTH_PID)..."
    sudo kill $DEAUTH_PID 2>/dev/null
    rm -f /tmp/deauth_pid.txt
fi
sudo pkill -9 -f "aireplay-ng.*deauth" 2>/dev/null

# Kill services
echo "[*] Killing hostapd..."
sudo pkill -9 -f hostapd

echo "[*] Killing dnsmasq..."
sudo pkill -9 -f dnsmasq

echo "[*] Killing portal server..."
sudo pkill -9 -f portal_server
sudo pkill -9 -f "flask.*portal"

sleep 2

# Restore original MAC if it was spoofed
if [ -f "$ORIGINAL_MAC_FILE" ]; then
    ORIGINAL_MAC=$(cat $ORIGINAL_MAC_FILE)
    CURRENT_MAC=$(cat /sys/class/net/$INTERFACE/address 2>/dev/null)
    if [ "$ORIGINAL_MAC" != "$CURRENT_MAC" ]; then
        echo "[*] Restoring original MAC: $ORIGINAL_MAC..."
        sudo ip link set $INTERFACE down
        sudo ip link set $INTERFACE address $ORIGINAL_MAC
        sudo ip link set $INTERFACE up
        echo "[+] MAC restored"
    fi
    rm -f $ORIGINAL_MAC_FILE
fi

# Reset portal interface
echo "[*] Resetting $INTERFACE..."
sudo ip addr flush dev $INTERFACE
sudo ip link set $INTERFACE down
sudo iw dev $INTERFACE set type managed 2>/dev/null
sleep 1
sudo ip link set $INTERFACE up

# Reset deauth interface to managed
echo "[*] Resetting $DEAUTH_INTERFACE..."
sudo ip link set $DEAUTH_INTERFACE down 2>/dev/null
sudo iw dev $DEAUTH_INTERFACE set type managed 2>/dev/null
sudo ip link set $DEAUTH_INTERFACE up 2>/dev/null

# Remove UFW rule
echo "[*] Removing UFW rule..."
sudo ufw delete allow in on $INTERFACE > /dev/null 2>&1

# Clean up iptables and IP forwarding (passthrough mode)
echo "[*] Flushing iptables and disabling IP forwarding..."
sudo iptables -t nat -F
sudo iptables -F FORWARD
sudo sysctl -w net.ipv4.ip_forward=0 > /dev/null

# Clean up config files
rm -f /tmp/hostapd_portal.conf
rm -f /tmp/dnsmasq_portal.conf
rm -f /tmp/hostapd.log
rm -f /tmp/deauth.log

# Restore default modes (matches udev design)
echo "[*] Restoring default interface modes..."
# alfa0 (Realtek) -> monitor mode (scanning/attacks)
sudo ip link set alfa0 down 2>/dev/null
sudo iw dev alfa0 set type monitor 2>/dev/null
sudo ip link set alfa0 up 2>/dev/null
# alfa1 (MediaTek) -> managed mode (ready for next portal)
sudo ip link set alfa1 down 2>/dev/null
sudo iw dev alfa1 set type managed 2>/dev/null
sudo ip link set alfa1 up 2>/dev/null

echo ""
echo "[+] Evil Portal stopped"
echo "[+] alfa0 -> monitor mode (ready for scanning)"
echo "[+] alfa1 -> managed mode (ready for portal)"
echo "[+] Original MAC restored (if changed)"
