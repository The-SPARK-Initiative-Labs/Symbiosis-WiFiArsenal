#!/bin/bash
# Recon scan — primary scan tool for Internal Network page
# Phase 1: arp-scan (host discovery — layer 2, unfirewallable)
# Phase 2: nxc smb (SMB enumeration — OS, domain, signing, SMBv1)
# Phase 3: Attack surface discovery (shares, guest access, users, webdav, password policy)
# Phase 4: Legacy vuln check (EternalBlue — rare on modern systems but still worth checking)
# Runs async — UI polls for completion

TARGET="${1:-192.168.1.0/24}"
INTERFACE="${2:-}"
OUTPUT_DIR="/home/ov3rr1d3/wifi_arsenal/captures"
OUTPUT_FILE="$OUTPUT_DIR/recon_results.json"

# Phase 1: arp-scan (layer 2 — can't be blocked by software firewalls)
echo "[*] Phase 1: Host discovery on $TARGET"

ARP_IFACE_OPT=""
if [ -n "$INTERFACE" ]; then
    ARP_IFACE_OPT="-I $INTERFACE"
fi

# Capture both IP and MAC from arp-scan
# arp-scan output format: IP\tMAC\tVendor
ARP_OUTPUT=$(sudo timeout 30 arp-scan $ARP_IFACE_OPT "$TARGET" 2>/dev/null | grep -P '^\d+\.\d+\.\d+\.\d+')

if [ -z "$ARP_OUTPUT" ]; then
    echo "[-] No hosts found via arp-scan"
    python3 -c "import json, datetime; json.dump({'hosts':[], 'scan_time': datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y'), 'targets_scanned':'$TARGET', 'scan_type':'recon'}, open('$OUTPUT_FILE','w'), indent=2)"
    exit 0
fi

# Extract just IPs for nxc, keep full output for MAC parsing later
ALIVE_IPS=$(echo "$ARP_OUTPUT" | awk '{print $1}')
HOST_COUNT=$(echo "$ALIVE_IPS" | wc -l)

echo "[+] Found $HOST_COUNT hosts"

# Build IP array (safe from word splitting)
readarray -t IP_ARRAY <<< "$ALIVE_IPS"

if [ ${#IP_ARRAY[@]} -eq 0 ]; then
    echo "[-] No IPs to enumerate"
    ARP_DATA="$ARP_OUTPUT" TARGET_EXPORT="$TARGET" python3 << 'PYEOF'
import json, os, datetime
output_file = "/home/ov3rr1d3/wifi_arsenal/captures/recon_results.json"
target = os.environ.get("TARGET_EXPORT", "")
arp_raw = os.environ.get("ARP_DATA", "")
hosts = []
for line in arp_raw.strip().split('\n'):
    if not line.strip(): continue
    parts = line.split('\t')
    if len(parts) >= 2:
        hosts.append({"ip": parts[0].strip(), "mac": parts[1].strip(), "hostname": "", "os": "", "os_accuracy": "", "device_type": "", "status": "up", "ports": [], "smb_info": {}, "vulns": {}, "attack_surface": {}})
json.dump({"hosts": hosts, "scan_time": datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y'), "targets_scanned": target, "scan_type": "recon"}, open(output_file, 'w'), indent=2)
print(f"[+] Recon complete — {len(hosts)} hosts (no SMB enumeration)")
PYEOF
    exit 0
fi

# Phase 2: SMB enumeration via nxc
echo "[*] Phase 2: SMB enumeration..."
NXC_SMB_OUTPUT=$(nxc smb "${IP_ARRAY[@]}" 2>/dev/null)
echo "[+] SMB enumeration complete"

# Phase 3: Attack surface discovery — things that ACTUALLY matter on modern networks
echo "[*] Phase 3: Attack surface discovery..."

# 3a: Open shares (accessible without creds)
echo "[*]   Checking open shares..."
NXC_SHARES_OUTPUT=$(nxc smb "${IP_ARRAY[@]}" --shares -u '' -p '' 2>/dev/null)

# 3b: Guest account access
echo "[*]   Checking guest access..."
NXC_GUEST_OUTPUT=$(nxc smb "${IP_ARRAY[@]}" -u 'guest' -p '' 2>/dev/null)

# 3c: User enumeration (RID brute force — works without creds on many systems)
echo "[*]   Enumerating users..."
NXC_USERS_OUTPUT=$(nxc smb "${IP_ARRAY[@]}" --rid-brute 2>/dev/null)

# 3d: Password policy (lockout threshold — tells if spraying is safe)
echo "[*]   Checking password policy..."
NXC_PASSPOL_OUTPUT=$(nxc smb "${IP_ARRAY[@]}" --pass-pol -u '' -p '' 2>/dev/null)

# 3e: WebDAV check (NTLM relay works via WebDAV even when SMB signing is required)
echo "[*]   Checking WebDAV..."
NXC_WEBDAV_OUTPUT=$(nxc smb "${IP_ARRAY[@]}" -M webdav 2>/dev/null)

echo "[+] Attack surface discovery complete"

# Phase 4: Legacy vuln checks (still worth checking — old machines exist)
echo "[*] Phase 4: Legacy vulnerability checks..."
NXC_VULN_OUTPUT=$(nxc smb "${IP_ARRAY[@]}" -M ms17-010 2>/dev/null)
echo "[+] Vulnerability checks complete"

# Assemble JSON with Python
ARP_DATA="$ARP_OUTPUT" \
SMB_DATA="$NXC_SMB_OUTPUT" \
VULN_DATA="$NXC_VULN_OUTPUT" \
SHARES_DATA="$NXC_SHARES_OUTPUT" \
GUEST_DATA="$NXC_GUEST_OUTPUT" \
USERS_DATA="$NXC_USERS_OUTPUT" \
PASSPOL_DATA="$NXC_PASSPOL_OUTPUT" \
WEBDAV_DATA="$NXC_WEBDAV_OUTPUT" \
TARGET_EXPORT="$TARGET" python3 << 'PYEOF'
import json
import re
import os
import datetime

output_file = "/home/ov3rr1d3/wifi_arsenal/captures/recon_results.json"
target = os.environ.get("TARGET_EXPORT", "192.168.1.0/24")

arp_raw = os.environ.get("ARP_DATA", "")
smb_raw = os.environ.get("SMB_DATA", "")
vuln_raw = os.environ.get("VULN_DATA", "")
shares_raw = os.environ.get("SHARES_DATA", "")
guest_raw = os.environ.get("GUEST_DATA", "")
users_raw = os.environ.get("USERS_DATA", "")
passpol_raw = os.environ.get("PASSPOL_DATA", "")
webdav_raw = os.environ.get("WEBDAV_DATA", "")

# --- Parse arp-scan output ---
hosts_by_ip = {}
for line in arp_raw.strip().split('\n'):
    if not line.strip():
        continue
    parts = line.split('\t')
    if len(parts) >= 2:
        ip = parts[0].strip()
        mac = parts[1].strip()
        hosts_by_ip[ip] = {
            "ip": ip,
            "mac": mac,
            "hostname": "",
            "os": "",
            "os_accuracy": "",
            "device_type": "",
            "status": "up",
            "ports": [],
            "smb_info": {},
            "vulns": {
                "ms17_010": False,
                "relay_target": False,
                "spooler": False
            },
            "attack_surface": {
                "open_shares": [],
                "guest_access": False,
                "users": [],
                "password_policy": {},
                "webdav": False,
                "null_session": False
            }
        }

# --- Parse nxc smb output ---
smb_pattern = re.compile(
    r'SMB\s+'
    r'(\d+\.\d+\.\d+\.\d+)\s+'  # IP
    r'(\d+)\s+'                   # port
    r'(\S+)\s+'                   # hostname
    r'\[\*\]\s+'                  # [*] marker
    r'(.+?)'                      # OS string
    r'\s*\(name:([^)]*)\)'        # (name:...)
    r'\s*\(domain:([^)]*)\)'      # (domain:...)
    r'\s*\(signing:([^)]*)\)'     # (signing:...)
    r'\s*\(SMBv1:([^)]*)\)'       # (SMBv1:...)
)

for line in smb_raw.strip().split('\n'):
    if not line.strip():
        continue
    m = smb_pattern.search(line)
    if m:
        ip = m.group(1)
        hostname = m.group(3)
        os_str = m.group(4).strip()
        domain = m.group(6)
        signing = m.group(7)
        smbv1 = m.group(8)

        if ip in hosts_by_ip:
            h = hosts_by_ip[ip]
            h["hostname"] = hostname
            h["os"] = os_str
            h["smb_info"] = {
                "os": os_str,
                "domain": domain,
                "signing": "disabled" if signing.lower() == "false" else "required" if signing.lower() == "true" else signing,
                "smbv1": smbv1.lower() == "true"
            }
            if signing.lower() == "false":
                h["vulns"]["relay_target"] = True

# --- Parse open shares ---
# nxc --shares output: SMB  IP  445  HOST  [*] Share  Permissions  Remark
# Lines with [READ] or [WRITE] indicate accessible shares
share_pattern = re.compile(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(.+)')
for line in shares_raw.strip().split('\n'):
    if not line.strip():
        continue
    m = share_pattern.search(line)
    if m:
        ip = m.group(1)
        rest = m.group(2).strip()
        if ip in hosts_by_ip:
            # Look for share names with READ or WRITE access
            if 'READ' in rest or 'WRITE' in rest:
                # Extract share name — format varies, grab the meaningful part
                share_match = re.search(r'(\S+)\s+(READ|WRITE)', rest)
                if share_match:
                    share_name = share_match.group(1)
                    access = share_match.group(2)
                    hosts_by_ip[ip]["attack_surface"]["open_shares"].append({
                        "name": share_name,
                        "access": access
                    })
                    hosts_by_ip[ip]["attack_surface"]["null_session"] = True

# --- Parse guest access ---
# nxc with guest creds: [+] means auth succeeded
for line in guest_raw.strip().split('\n'):
    if not line.strip():
        continue
    # [+] IP:445 ... (Guest) means guest access works
    guest_match = re.search(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+\[\+\]', line)
    if guest_match:
        ip = guest_match.group(1)
        if ip in hosts_by_ip:
            hosts_by_ip[ip]["attack_surface"]["guest_access"] = True

# --- Parse user enumeration ---
# RID brute output: SMB  IP  445  HOST  500: DOMAIN\Administrator (SidTypeUser)
user_pattern = re.compile(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+\d+:\s+\S+\\(\S+)\s+\(SidTypeUser\)')
for line in users_raw.strip().split('\n'):
    if not line.strip():
        continue
    m = user_pattern.search(line)
    if m:
        ip = m.group(1)
        username = m.group(2)
        if ip in hosts_by_ip:
            if username not in hosts_by_ip[ip]["attack_surface"]["users"]:
                hosts_by_ip[ip]["attack_surface"]["users"].append(username)

# --- Parse password policy ---
# Pass-pol output: SMB  IP  445  HOST  Minimum password length: 0
passpol_ip = None
for line in passpol_raw.strip().split('\n'):
    if not line.strip():
        continue
    # Track which IP we're reading policy for
    ip_match = re.search(r'SMB\s+(\d+\.\d+\.\d+\.\d+)', line)
    if ip_match:
        passpol_ip = ip_match.group(1)
    if passpol_ip and passpol_ip in hosts_by_ip:
        pol = hosts_by_ip[passpol_ip]["attack_surface"]["password_policy"]
        if 'Minimum password length' in line:
            m = re.search(r'Minimum password length:\s*(\d+)', line)
            if m:
                pol["min_length"] = int(m.group(1))
        elif 'Account Lockout Threshold' in line:
            m = re.search(r'Account Lockout Threshold:\s*(\d+)', line)
            if m:
                pol["lockout_threshold"] = int(m.group(1))
        elif 'Password Complexity' in line:
            if 'Disabled' in line:
                pol["complexity"] = False
            elif 'Enabled' in line:
                pol["complexity"] = True

# --- Parse WebDAV ---
# WebDAV module: [+] WebClient Service enabled means relay via WebDAV is possible
for line in webdav_raw.strip().split('\n'):
    if not line.strip():
        continue
    if 'WebClient' in line and 'enabled' in line.lower():
        webdav_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if webdav_match:
            ip = webdav_match.group(1)
            if ip in hosts_by_ip:
                hosts_by_ip[ip]["attack_surface"]["webdav"] = True

# --- Parse EternalBlue (legacy) ---
vuln_pattern = re.compile(r'MS17-010\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+\[\+\]\s+.*VULNERABLE', re.IGNORECASE)
for line in vuln_raw.strip().split('\n'):
    if not line.strip():
        continue
    m = vuln_pattern.search(line)
    if m:
        ip = m.group(1)
        if ip in hosts_by_ip:
            hosts_by_ip[ip]["vulns"]["ms17_010"] = True

# --- Build final result ---
results = {
    "hosts": list(hosts_by_ip.values()),
    "scan_time": datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y'),
    "targets_scanned": target,
    "scan_type": "recon"
}

try:
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Summary
    total = len(results['hosts'])
    with_smb = sum(1 for h in results['hosts'] if h.get('smb_info', {}).get('os'))
    with_shares = sum(1 for h in results['hosts'] if h.get('attack_surface', {}).get('open_shares'))
    with_guest = sum(1 for h in results['hosts'] if h.get('attack_surface', {}).get('guest_access'))
    with_users = sum(1 for h in results['hosts'] if h.get('attack_surface', {}).get('users'))
    with_webdav = sum(1 for h in results['hosts'] if h.get('attack_surface', {}).get('webdav'))
    with_vulns = sum(1 for h in results['hosts'] if h.get('vulns', {}).get('ms17_010'))

    print(f"[+] Recon complete — {total} hosts")
    if with_smb: print(f"    SMB: {with_smb} hosts")
    if with_shares: print(f"    Open shares: {with_shares} hosts")
    if with_guest: print(f"    Guest access: {with_guest} hosts")
    if with_users: print(f"    Users found: {with_users} hosts")
    if with_webdav: print(f"    WebDAV: {with_webdav} hosts")
    if with_vulns: print(f"    EternalBlue: {with_vulns} hosts")

except Exception as e:
    with open(output_file, 'w') as f:
        json.dump({"hosts": [], "error": str(e), "scan_type": "recon"}, f)
    print(f"[-] Error writing results: {e}")

PYEOF
