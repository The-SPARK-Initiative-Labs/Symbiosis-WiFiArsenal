#!/bin/bash
# SNMP Enumeration — tries default community strings, walks system/interface OIDs
# Usage: enum_snmp.sh <output_json_path> <ip1> [ip2] [ip3] ...
# Finding a working community string is itself a vulnerability (default creds)

OUTPUT_FILE="${1:?Usage: enum_snmp.sh <output_json> <ip1> [ip2...]}"
shift
TARGETS="$@"

if [ -z "$TARGETS" ]; then
    echo '{"targets": {}, "scan_time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'", "error": "No targets specified"}' > "$OUTPUT_FILE"
    exit 0
fi

TMPDIR=$(mktemp -d /tmp/snmp_enum_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

# Community strings to try (these are default/common — finding one that works = vulnerability)
COMMUNITIES="public private community"

echo "[*] SNMP Enumeration starting — targets: $TARGETS"

for IP in $TARGETS; do
    echo "[*] Probing $IP for SNMP ..."
    HOSTDIR="$TMPDIR/$IP"
    mkdir -p "$HOSTDIR"

    FOUND_COMMUNITY=""

    # Try each community string — first one that works wins
    for COMM in $COMMUNITIES; do
        # Quick test: get sysDescr (1.3.6.1.2.1.1.1.0)
        RESULT=$(timeout 8 snmpget -v2c -c "$COMM" -t 3 -r 1 "$IP" 1.3.6.1.2.1.1.1.0 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$RESULT" ]; then
            FOUND_COMMUNITY="$COMM"
            echo "[+] $IP responds to community string: $COMM"
            echo "$COMM" > "$HOSTDIR/community.txt"
            break
        fi
    done

    if [ -z "$FOUND_COMMUNITY" ]; then
        echo "[-] $IP: No default community string worked"
        echo "none" > "$HOSTDIR/community.txt"
        continue
    fi

    # Full walks with the working community string
    # System info (sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation, sysServices)
    timeout 20 snmpwalk -v2c -c "$FOUND_COMMUNITY" -t 5 -r 1 "$IP" 1.3.6.1.2.1.1 > "$HOSTDIR/system.txt" 2>&1 &

    # Interfaces
    timeout 30 snmpwalk -v2c -c "$FOUND_COMMUNITY" -t 5 -r 1 "$IP" 1.3.6.1.2.1.2.2 > "$HOSTDIR/interfaces.txt" 2>&1 &

    # Running processes (hrSWRunName — may not be supported on all devices)
    timeout 20 snmpwalk -v2c -c "$FOUND_COMMUNITY" -t 5 -r 1 "$IP" 1.3.6.1.2.1.25.4.2.1.2 > "$HOSTDIR/processes.txt" 2>&1 &

    wait
    echo "[+] Done walking $IP"
done

echo "[*] Parsing results..."

# Parse all SNMP results into structured JSON
TMPDIR="$TMPDIR" OUTPUT_FILE="$OUTPUT_FILE" TARGETS_EXPORT="$TARGETS" python3 << 'PYEOF'
import json
import re
import os
from datetime import datetime, timezone

tmpdir = os.environ.get('TMPDIR', '/tmp')
targets = os.environ.get('TARGETS_EXPORT', '').split()
output_file = os.environ.get('OUTPUT_FILE', '/tmp/snmp_enum.json')

results = {"targets": {}, "scan_time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}

def parse_snmp_value(line):
    """Extract value from snmpwalk output line: OID = TYPE: value"""
    m = re.match(r'.*=\s*\S+:\s*(.*)', line)
    if m:
        val = m.group(1).strip().strip('"')
        return val
    # Sometimes format is just OID = value
    m = re.match(r'.*=\s*(.*)', line)
    if m:
        return m.group(1).strip().strip('"')
    return ''

def parse_timeticks(val):
    """Convert timeticks to human-readable uptime"""
    m = re.search(r'\((\d+)\)', val)
    if m:
        ticks = int(m.group(1))
        seconds = ticks // 100
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        if days > 0:
            return f"{days} days {hours}:{minutes:02d}:{secs:02d}"
        return f"{hours}:{minutes:02d}:{secs:02d}"
    # Fallback: return the raw value cleaned up
    return val.strip('"').strip()

for ip in targets:
    hostdir = os.path.join(tmpdir, ip)
    comm_file = os.path.join(hostdir, 'community.txt')

    if not os.path.exists(comm_file):
        continue

    with open(comm_file, 'r') as f:
        community = f.read().strip()

    if community == 'none':
        results["targets"][ip] = {
            "community_string": None,
            "status": "no_response",
            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        continue

    host_result = {
        "community_string": community,
        "system": {
            "description": "",
            "contact": "",
            "name": "",
            "location": "",
            "uptime": "",
            "object_id": ""
        },
        "interfaces": [],
        "processes": [],
        "status": "complete",
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    # Parse system info
    sys_file = os.path.join(hostdir, 'system.txt')
    if os.path.exists(sys_file):
        with open(sys_file, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('Timeout') or line.startswith('No '):
                    continue
                # sysDescr.0
                if '.1.3.6.1.2.1.1.1.0' in line or 'sysDescr' in line:
                    host_result["system"]["description"] = parse_snmp_value(line)
                # sysObjectID.0
                elif '.1.3.6.1.2.1.1.2.0' in line or 'sysObjectID' in line:
                    host_result["system"]["object_id"] = parse_snmp_value(line)
                # sysUpTime.0
                elif '.1.3.6.1.2.1.1.3.0' in line or 'sysUpTimeInst' in line or 'sysUpTime' in line:
                    host_result["system"]["uptime"] = parse_timeticks(parse_snmp_value(line))
                # sysContact.0
                elif '.1.3.6.1.2.1.1.4.0' in line or 'sysContact' in line:
                    host_result["system"]["contact"] = parse_snmp_value(line)
                # sysName.0
                elif '.1.3.6.1.2.1.1.5.0' in line or 'sysName' in line:
                    host_result["system"]["name"] = parse_snmp_value(line)
                # sysLocation.0
                elif '.1.3.6.1.2.1.1.6.0' in line or 'sysLocation' in line:
                    host_result["system"]["location"] = parse_snmp_value(line)

    # Parse interfaces
    iface_file = os.path.join(hostdir, 'interfaces.txt')
    if os.path.exists(iface_file):
        with open(iface_file, 'r', errors='replace') as f:
            iface_data = {}  # keyed by interface index
            for line in f:
                line = line.strip()
                if not line or line.startswith('Timeout') or line.startswith('No '):
                    continue
                # Extract interface index from OID
                # Format: .1.3.6.1.2.1.2.2.1.<field>.<index> = ...
                m = re.match(r'.*\.1\.3\.6\.1\.2\.1\.2\.2\.1\.(\d+)\.(\d+)\s*=', line)
                if not m:
                    continue
                field = int(m.group(1))
                idx = int(m.group(2))
                val = parse_snmp_value(line)

                if idx not in iface_data:
                    iface_data[idx] = {"index": idx, "description": "", "type": "", "mac": "", "speed": "", "status": ""}

                # Field meanings: 1=ifIndex, 2=ifDescr, 3=ifType, 5=ifSpeed, 6=ifPhysAddress, 8=ifOperStatus
                if field == 2:
                    iface_data[idx]["description"] = val
                elif field == 3:
                    # Map common ifType integers
                    type_map = {'6': 'ethernet', '24': 'loopback', '71': 'wifi', '131': 'tunnel', '1': 'other'}
                    iface_data[idx]["type"] = type_map.get(val, f"type-{val}")
                elif field == 5:
                    # Speed in bits/sec — convert to human readable
                    try:
                        speed_bps = int(val)
                        if speed_bps >= 1000000000:
                            iface_data[idx]["speed"] = f"{speed_bps // 1000000000} Gbps"
                        elif speed_bps >= 1000000:
                            iface_data[idx]["speed"] = f"{speed_bps // 1000000} Mbps"
                        elif speed_bps > 0:
                            iface_data[idx]["speed"] = f"{speed_bps // 1000} Kbps"
                    except ValueError:
                        pass
                elif field == 6:
                    # Physical address (MAC) — may come as hex string
                    mac = val.replace(' ', ':').upper()
                    if mac and mac != '""':
                        iface_data[idx]["mac"] = mac
                elif field == 8:
                    status_map = {'1': 'up', '2': 'down', '3': 'testing'}
                    iface_data[idx]["status"] = status_map.get(val, val)

            # Only include interfaces with a description (skip empty ones)
            host_result["interfaces"] = [
                iface for iface in sorted(iface_data.values(), key=lambda x: x['index'])
                if iface.get('description')
            ]

    # Parse running processes
    proc_file = os.path.join(hostdir, 'processes.txt')
    if os.path.exists(proc_file):
        with open(proc_file, 'r', errors='replace') as f:
            procs = []
            for line in f:
                line = line.strip()
                if not line or line.startswith('Timeout') or line.startswith('No '):
                    continue
                val = parse_snmp_value(line)
                if val and val != '""':
                    procs.append(val)
            # Deduplicate and sort
            host_result["processes"] = sorted(set(procs))

    results["targets"][ip] = host_result

with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

responding = sum(1 for h in results['targets'].values() if h.get('community_string'))
total = len(results['targets'])
print(f"[+] SNMP enum complete: {responding}/{total} hosts responded with default community strings")
PYEOF
