#!/bin/bash
# Network scan — version detection, SMB scripts
# Two-phase: arp-scan to find alive hosts, then nmap detailed scan
# arp-scan is layer 2 — can't be blocked by software firewalls
# Runs async — UI polls for completion

TARGET="${1:-192.168.1.0/24}"
INTERFACE="${2:-}"
OUTPUT_DIR="/home/ov3rr1d3/wifi_arsenal/captures"
OUTPUT_FILE="$OUTPUT_DIR/nmap_results.json"
XML_FILE="$OUTPUT_DIR/nmap_results.xml"

IFACE_OPT=""
if [ -n "$INTERFACE" ]; then
    IFACE_OPT="-e $INTERFACE"
fi

echo "[*] Phase 1: Host discovery on $TARGET"

# Phase 1: arp-scan (layer 2 — unfirewallable)
# ICMP ping sweep missed firewalled hosts (Windows firewall blocks pings)
# arp-scan finds everything in ~2 seconds
ARP_IFACE_OPT=""
if [ -n "$INTERFACE" ]; then
    ARP_IFACE_OPT="-I $INTERFACE"
fi

ALIVE_IPS=$(sudo timeout 30 arp-scan $ARP_IFACE_OPT "$TARGET" 2>/dev/null | grep -oP '^\d+\.\d+\.\d+\.\d+')

if [ -z "$ALIVE_IPS" ]; then
    echo "[-] No hosts found via arp-scan"
    python3 -c "import json; json.dump({'hosts':[], 'scan_time':'', 'targets_scanned':'$TARGET'}, open('$OUTPUT_FILE','w'), indent=2)"
    exit 0
fi

echo "[+] Found alive hosts: $ALIVE_IPS"
echo "[*] Phase 2: Detailed scan on alive hosts"

# Phase 2: Port scan + version detection + SMB scripts on found hosts
# -sS = SYN scan (fast, stealthy)
# -sV = Version detection (identifies services)
# -O  = OS fingerprinting
# --top-ports 100 = catches SMB, RDP, telnet, SNMP, etc.
# -T4 = aggressive timing
# --open = only show open ports
# -Pn = skip host discovery (already done in phase 1)
sudo nmap -sS -sV -O --top-ports 100 -T4 --open -Pn \
    --script=smb-os-discovery,smb-security-mode \
    $IFACE_OPT -oX "$XML_FILE" $ALIVE_IPS 2>/dev/null

# Convert XML to JSON
TARGET_EXPORT="$TARGET" python3 << 'PYEOF'
import xml.etree.ElementTree as ET
import json
import re
import os

xml_file = "/home/ov3rr1d3/wifi_arsenal/captures/nmap_results.xml"
output_file = "/home/ov3rr1d3/wifi_arsenal/captures/nmap_results.json"
target = os.environ.get("TARGET_EXPORT", "192.168.1.0/24")

results = {"hosts": [], "scan_time": "", "targets_scanned": target}

try:
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for runstats in root.findall('.//finished'):
        results["scan_time"] = runstats.get('timestr', '')

    for host in root.findall('.//host'):
        host_info = {
            "ip": "", "mac": "", "hostname": "", "os": "",
            "os_accuracy": "", "device_type": "", "status": "",
            "ports": [], "smb_info": None
        }

        status = host.find('status')
        if status is not None:
            host_info["status"] = status.get('state', 'unknown')

        for addr in host.findall('address'):
            if addr.get('addrtype') == 'ipv4':
                host_info["ip"] = addr.get('addr', '')
            elif addr.get('addrtype') == 'mac':
                host_info["mac"] = addr.get('addr', '')
                vendor = addr.get('vendor', '')
                if vendor:
                    host_info["device_type"] = vendor

        for hostname in host.findall('.//hostname'):
            host_info["hostname"] = hostname.get('name', '')
            break

        # OS detection (from SMB scripts or nmap guess)
        for osmatch in host.findall('.//osmatch'):
            host_info["os"] = osmatch.get('name', '')
            host_info["os_accuracy"] = osmatch.get('accuracy', '') + '%'
            break

        # Ports with version info
        for port in host.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                port_info = {
                    "port": port.get('portid', ''),
                    "service": "",
                    "product": "",
                    "version": ""
                }
                service = port.find('service')
                if service is not None:
                    port_info["service"] = service.get('name', '')
                    port_info["product"] = service.get('product', '')
                    port_info["version"] = service.get('version', '')
                host_info["ports"].append(port_info)

        # SMB script output
        for hostscript in host.findall('.//hostscript/script'):
            script_id = hostscript.get('id', '')
            output = hostscript.get('output', '')

            if script_id == 'smb-os-discovery':
                if host_info["smb_info"] is None:
                    host_info["smb_info"] = {}
                for elem in hostscript.findall('elem'):
                    key = elem.get('key', '')
                    val = elem.text or ''
                    if key == 'os':
                        host_info["smb_info"]["os"] = val
                    elif key == 'lanmanager':
                        host_info["smb_info"]["lanmanager"] = val
                    elif key == 'domain':
                        host_info["smb_info"]["domain"] = val
                    elif key == 'fqdn':
                        host_info["smb_info"]["fqdn"] = val
                # Fallback: parse output text if elem parsing got nothing
                if not host_info["smb_info"].get("os") and output:
                    m = re.search(r'OS:\s*(.+)', output)
                    if m:
                        host_info["smb_info"]["os"] = m.group(1).strip()
                    m = re.search(r'Domain name:\s*(.+)', output)
                    if m:
                        host_info["smb_info"]["domain"] = m.group(1).strip()

            elif script_id == 'smb-security-mode':
                if host_info["smb_info"] is None:
                    host_info["smb_info"] = {}
                if 'message_signing: disabled' in output.lower():
                    host_info["smb_info"]["signing"] = "disabled"
                elif 'message_signing: required' in output.lower():
                    host_info["smb_info"]["signing"] = "required"
                else:
                    host_info["smb_info"]["signing"] = "enabled"
                m = re.search(r'authentication_level:\s*(\w+)', output)
                if m:
                    host_info["smb_info"]["auth_level"] = m.group(1)

        # Include all hosts that are up (even with no open ports)
        if host_info["status"] == "up" and host_info["ip"]:
            results["hosts"].append(host_info)

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"[+] Found {len(results['hosts'])} hosts")

except Exception as e:
    with open(output_file, 'w') as f:
        json.dump({"hosts": [], "error": str(e)}, f)
    print(f"[-] Error: {e}")
PYEOF
