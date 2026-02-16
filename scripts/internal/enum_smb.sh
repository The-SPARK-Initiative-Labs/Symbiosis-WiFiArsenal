#!/bin/bash
# SMB Enumeration — runs smbclient + enum4linux on target IPs
# Usage: enum_smb.sh <output_json_path> <ip1> [ip2] [ip3] ...
# Env vars: SMB_USER, SMB_PASS — optional credentials for authenticated enum (test/post-crack)
# Produces structured JSON with shares, users, password policy, OS info per host

OUTPUT_FILE="${1:?Usage: enum_smb.sh <output_json> <ip1> [ip2...]}"
shift
TARGETS="$@"

if [ -z "$TARGETS" ]; then
    echo '{"targets": {}, "scan_time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'", "error": "No targets specified"}' > "$OUTPUT_FILE"
    exit 0
fi

TMPDIR=$(mktemp -d /tmp/smb_enum_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

# Authenticated mode: credentials passed via env vars (never on command line)
AUTH_MODE="anonymous"
SMB_CLIENT_AUTH="-N"
E4L_AUTH=""
if [ -n "$SMB_USER" ]; then
    AUTH_MODE="authenticated"
    # smbclient uses -U user%pass, enum4linux uses -u user -p pass
    SMB_CLIENT_AUTH="-U ${SMB_USER}%${SMB_PASS:-}"
    E4L_AUTH="-u $SMB_USER -p ${SMB_PASS:-}"
fi

echo "[*] SMB Enumeration starting — mode: $AUTH_MODE, targets: $TARGETS"

for IP in $TARGETS; do
    echo "[*] Enumerating $IP ($AUTH_MODE) ..."
    HOSTDIR="$TMPDIR/$IP"
    mkdir -p "$HOSTDIR"

    # 1. Share listing via smbclient (10s timeout)
    timeout 15 smbclient -L "//$IP" $SMB_CLIENT_AUTH -t 10 > "$HOSTDIR/smbclient.txt" 2>&1 &

    # 2. Full enumeration via enum4linux
    timeout 120 enum4linux -a $E4L_AUTH "$IP" > "$HOSTDIR/enum4linux.txt" 2>&1 &

    wait
    echo "[+] Done enumerating $IP"
done

echo "[*] Parsing results..."

# Parse all results into structured JSON using Python
TMPDIR="$TMPDIR" OUTPUT_FILE="$OUTPUT_FILE" TARGETS_EXPORT="$TARGETS" AUTH_MODE="$AUTH_MODE" python3 << 'PYEOF'
import json
import re
import os
from datetime import datetime, timezone

tmpdir = os.environ.get('TMPDIR', '/tmp')
targets = os.environ.get('TARGETS_EXPORT', '').split()
output_file = os.environ.get('OUTPUT_FILE', '/tmp/smb_enum.json')
auth_mode = os.environ.get('AUTH_MODE', 'anonymous')

results = {"targets": {}, "mode": auth_mode, "scan_time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}

for ip in targets:
    hostdir = os.path.join(tmpdir, ip)
    host_result = {
        "shares": [],
        "users": [],
        "password_policy": {},
        "os_info": "",
        "domain": "",
        "signing": "",
        "status": "complete",
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    # Parse smbclient output for shares
    smbclient_file = os.path.join(hostdir, 'smbclient.txt')
    if os.path.exists(smbclient_file):
        with open(smbclient_file, 'r', errors='replace') as f:
            smbclient_out = f.read()

        # Check if connection failed entirely
        if 'NT_STATUS_' in smbclient_out and 'Sharename' not in smbclient_out:
            host_result["status"] = "error"
            # Extract the error
            m = re.search(r'(NT_STATUS_\w+)', smbclient_out)
            if m:
                host_result["error"] = m.group(1)

        # Parse share listing: "  ShareName  Type  Comment"
        in_shares = False
        for line in smbclient_out.splitlines():
            if 'Sharename' in line and 'Type' in line:
                in_shares = True
                continue
            if in_shares and line.strip().startswith('---'):
                continue
            if in_shares and line.strip() == '':
                in_shares = False
                continue
            if in_shares:
                # Format: "	ShareName       Disk      Some comment"
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1] if len(parts) > 1 else ''
                    comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                    host_result["shares"].append({
                        "name": share_name,
                        "type": share_type,
                        "comment": comment,
                        "anonymous_access": auth_mode == "anonymous"
                    })

    # Parse enum4linux output
    e4l_file = os.path.join(hostdir, 'enum4linux.txt')
    if os.path.exists(e4l_file):
        with open(e4l_file, 'r', errors='replace') as f:
            e4l_out = f.read()

        # OS info
        m = re.search(r'OS:\s*\[([^\]]*)\]', e4l_out)
        if m:
            host_result["os_info"] = m.group(1)

        # Domain / Workgroup
        m = re.search(r'Domain:\s*\[([^\]]*)\]', e4l_out)
        if m:
            host_result["domain"] = m.group(1)
        if not host_result["domain"]:
            m = re.search(r'Workgroup:\s*\[([^\]]*)\]', e4l_out)
            if m:
                host_result["domain"] = m.group(1)

        # Users from enum4linux (multiple patterns)
        users = set()
        # Pattern: "user:[Username] rid:[0x...]"
        for m in re.finditer(r'user:\[([^\]]+)\]', e4l_out):
            users.add(m.group(1))
        # Pattern from "Users on ..." section
        for m in re.finditer(r'^\s+(\S+)\s+\(.*\)\s*$', e4l_out, re.MULTILINE):
            name = m.group(1)
            if name and not name.startswith('---') and name not in ('Sharename', 'Type', 'Comment'):
                users.add(name)
        host_result["users"] = sorted(list(users))

        # Shares from enum4linux (supplement smbclient)
        existing_shares = {s['name'] for s in host_result['shares']}
        in_share_section = False
        for line in e4l_out.splitlines():
            if '=== Share Enumeration' in line or 'Sharename' in line:
                in_share_section = True
                continue
            if in_share_section and line.strip().startswith('---'):
                continue
            if in_share_section and ('=====' in line or line.strip() == ''):
                in_share_section = False
                continue
            if in_share_section:
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    stype = parts[1] if len(parts) > 1 else ''
                    comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                    if name not in existing_shares and name not in ('Sharename',):
                        host_result["shares"].append({
                            "name": name,
                            "type": stype,
                            "comment": comment,
                            "anonymous_access": True
                        })

        # Password policy
        pw = {}
        m = re.search(r'Minimum password length:\s*(\d+)', e4l_out)
        if m:
            pw["min_length"] = int(m.group(1))
        m = re.search(r'Account Lockout Threshold:\s*(\d+)', e4l_out)
        if m:
            pw["lockout_threshold"] = int(m.group(1))
        m = re.search(r'Password Complexity:\s*(\w+)', e4l_out)
        if m:
            pw["complexity"] = m.group(1).lower() not in ('disabled', '0', 'false', 'no')
        if pw:
            host_result["password_policy"] = pw

        # SMB signing
        if 'signing' in e4l_out.lower():
            if 'message_signing: disabled' in e4l_out.lower() or 'signing disabled' in e4l_out.lower():
                host_result["signing"] = "disabled"
            elif 'message_signing: required' in e4l_out.lower() or 'signing required' in e4l_out.lower():
                host_result["signing"] = "required"
            elif 'message_signing: enabled' in e4l_out.lower() or 'signing enabled' in e4l_out.lower():
                host_result["signing"] = "enabled"

    # If both tools failed, mark as error
    if host_result["status"] != "error" and not host_result["shares"] and not host_result["users"] and not host_result["os_info"]:
        host_result["status"] = "no_data"

    results["targets"][ip] = host_result

with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

host_count = len(results['targets'])
share_count = sum(len(h.get('shares', [])) for h in results['targets'].values())
user_count = sum(len(h.get('users', [])) for h in results['targets'].values())
print(f"[+] SMB enum complete: {host_count} hosts, {share_count} shares, {user_count} users found")
PYEOF
