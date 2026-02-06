#!/bin/bash
# Fast network scan - ping sweep + common ports only

TARGET="${1:-192.168.1.0/24}"
INTERFACE="${2:-}"
OUTPUT_DIR="/home/ov3rr1d3/wifi_arsenal/captures"
OUTPUT_FILE="$OUTPUT_DIR/nmap_results.json"
XML_FILE="$OUTPUT_DIR/nmap_results.xml"

IFACE_OPT=""
if [ -n "$INTERFACE" ]; then
    IFACE_OPT="-e $INTERFACE"
fi

echo "[*] Fast scan: $TARGET"

# Fast scan: Ping sweep + top 20 ports only, no service detection
# -sn = ping sweep
# -Pn = skip ping (some hosts block ICMP)  
# --top-ports 20 = only 20 most common
# -T4 = faster timing
sudo nmap -sS --top-ports 20 -T4 --open $IFACE_OPT -oX "$XML_FILE" "$TARGET" 2>/dev/null

# Convert to JSON
python3 << PYEOF
import xml.etree.ElementTree as ET
import json

xml_file = "$XML_FILE"
output_file = "$OUTPUT_FILE"

results = {"hosts": [], "scan_time": "", "targets_scanned": "$TARGET"}

try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    for runstats in root.findall('.//finished'):
        results["scan_time"] = runstats.get('timestr', '')
    
    for host in root.findall('.//host'):
        host_info = {"ip": "", "mac": "", "hostname": "", "os": "", "status": "", "ports": []}
        
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
                    host_info["os"] = vendor
        
        for hostname in host.findall('.//hostname'):
            host_info["hostname"] = hostname.get('name', '')
            break
        
        for port in host.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                port_info = {
                    "port": port.get('portid', ''),
                    "service": ""
                }
                service = port.find('service')
                if service is not None:
                    port_info["service"] = service.get('name', '')
                host_info["ports"].append(port_info)
        
        if host_info["status"] == "up" and host_info["ip"]:
            results["hosts"].append(host_info)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Found {len(results['hosts'])} hosts")

except Exception as e:
    print(f"[-] Error: {e}")
PYEOF
