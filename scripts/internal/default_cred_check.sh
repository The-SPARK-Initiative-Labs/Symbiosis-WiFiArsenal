#!/bin/bash
# Default Credential Check — tests factory/default credentials against discovered services using Hydra
# Usage: default_cred_check.sh <output_json_path> <IP:PORT:SERVICE> [IP:PORT:SERVICE] ...
# Produces structured JSON with credential test results per host/service

OUTPUT_FILE="${1:?Usage: default_cred_check.sh <output_json> <IP:PORT:SERVICE> [IP:PORT:SERVICE ...]}"
shift
TARGET_SPECS="$@"

if [ -z "$TARGET_SPECS" ]; then
    echo '{"targets": {}, "scan_time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'", "error": "No targets specified"}' > "$OUTPUT_FILE"
    exit 0
fi

TMPDIR=$(mktemp -d /tmp/default_cred_XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

# --- Credential lists per service type (embedded, never in server.py or config files) ---

cat > "$TMPDIR/creds_ssh.txt" << 'EOF'
admin:admin
admin:password
admin:1234
root:root
root:toor
root:password
pi:raspberry
ubnt:ubnt
user:user
EOF

cat > "$TMPDIR/creds_telnet.txt" << 'EOF'
admin:admin
admin:password
admin:1234
root:root
root:toor
user:user
EOF

cat > "$TMPDIR/creds_ftp.txt" << 'EOF'
admin:admin
admin:password
anonymous:
ftp:ftp
EOF

cat > "$TMPDIR/creds_http.txt" << 'EOF'
admin:admin
admin:password
admin:1234
admin:12345
root:root
root:password
EOF

cat > "$TMPDIR/creds_smb.txt" << 'EOF'
administrator:
guest:
admin:admin
admin:password
EOF

echo "[*] Default credential check starting — targets: $TARGET_SPECS"

for SPEC in $TARGET_SPECS; do
    IP=$(echo "$SPEC" | cut -d: -f1)
    PORT=$(echo "$SPEC" | cut -d: -f2)
    SERVICE=$(echo "$SPEC" | cut -d: -f3)

    # Validate IP format
    if ! echo "$IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "[-] Invalid IP: $IP — skipping"
        continue
    fi

    # Map service to Hydra module and credential file
    HYDRA_MODULE=""
    CRED_FILE=""
    EXTRA_FLAGS=""

    case "$SERVICE" in
        ssh)
            HYDRA_MODULE="ssh"
            CRED_FILE="$TMPDIR/creds_ssh.txt"
            ;;
        telnet)
            HYDRA_MODULE="telnet"
            CRED_FILE="$TMPDIR/creds_telnet.txt"
            ;;
        ftp)
            HYDRA_MODULE="ftp"
            CRED_FILE="$TMPDIR/creds_ftp.txt"
            ;;
        http)
            HYDRA_MODULE="http-get"
            CRED_FILE="$TMPDIR/creds_http.txt"
            EXTRA_FLAGS="/"
            ;;
        https)
            HYDRA_MODULE="https-get"
            CRED_FILE="$TMPDIR/creds_http.txt"
            EXTRA_FLAGS="/"
            ;;
        smb|microsoft-ds)
            HYDRA_MODULE="smb"
            CRED_FILE="$TMPDIR/creds_smb.txt"
            ;;
        *)
            echo "[-] Unsupported service: $SERVICE on $IP:$PORT — skipping"
            continue
            ;;
    esac

    # Build user and password lists from the combined file
    USER_FILE="$TMPDIR/users_${SERVICE}.txt"
    PASS_FILE="$TMPDIR/passes_${SERVICE}.txt"
    cut -d: -f1 "$CRED_FILE" | sort -u > "$USER_FILE"
    cut -d: -f2 "$CRED_FILE" | sort -u > "$PASS_FILE"

    OUTFILE="$TMPDIR/${IP}_${PORT}_${SERVICE}.txt"

    echo "[*] Testing $SERVICE on $IP:$PORT ..."

    # Hydra flags:
    #   -L userlist -P passlist — credential files
    #   -s port — target port
    #   -t 4 — max 4 parallel tasks (don't hammer the target)
    #   -f — stop on first valid login per host
    #   -I — don't wait 10s at start
    #   -o outfile — write results to file
    timeout 30 hydra -L "$USER_FILE" -P "$PASS_FILE" -s "$PORT" -t 4 -f -I -o "$OUTFILE" "$IP" "$HYDRA_MODULE" $EXTRA_FLAGS 2>&1 | while IFS= read -r line; do
        echo "[Hydra] $line"
    done

    echo "[+] Done testing $SERVICE on $IP:$PORT"
done

echo "[*] Parsing results..."

# Parse all Hydra output files into structured JSON
TMPDIR="$TMPDIR" OUTPUT_FILE="$OUTPUT_FILE" TARGET_SPECS_EXPORT="$TARGET_SPECS" python3 << 'PYEOF'
import json
import re
import os
from datetime import datetime, timezone

tmpdir = os.environ.get('TMPDIR', '/tmp')
target_specs = os.environ.get('TARGET_SPECS_EXPORT', '').split()
output_file = os.environ.get('OUTPUT_FILE', '/tmp/default_cred_results.json')

results = {
    "targets": {},
    "scan_time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    "total_found": 0
}

for spec in target_specs:
    parts = spec.split(':')
    if len(parts) < 3:
        continue
    ip, port, service = parts[0], parts[1], parts[2]

    if ip not in results["targets"]:
        results["targets"][ip] = {"services": []}

    service_result = {
        "port": int(port),
        "service": service,
        "credentials": [],
        "tested_at": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    # Parse Hydra output file
    outfile = os.path.join(tmpdir, f"{ip}_{port}_{service}.txt")
    if os.path.exists(outfile):
        with open(outfile, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                # Hydra output format: [PORT][SERVICE] host: IP   login: USER   password: PASS
                m = re.search(r'\[\d+\]\[[\w-]+\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s*(.*)', line)
                if m:
                    found_user = m.group(2)
                    found_pass = m.group(3).strip()
                    service_result["credentials"].append({
                        "user": found_user,
                        "pass": found_pass,
                        "status": "valid"
                    })
                    results["total_found"] += 1

    if not service_result["credentials"]:
        service_result["credentials"].append({"user": "", "pass": "", "status": "none_found"})

    results["targets"][ip]["services"].append(service_result)

with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

found = results["total_found"]
hosts = len(results["targets"])
services = sum(len(h["services"]) for h in results["targets"].values())
print(f"[+] Default credential check complete: {hosts} hosts, {services} services tested, {found} valid credentials found")
PYEOF
