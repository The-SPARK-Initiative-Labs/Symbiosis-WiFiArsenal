#!/bin/bash
# Monitor Responder logs for new hashes and consolidate them

RESPONDER_LOG_DIR="/usr/share/responder/logs"
if [ ! -d "$RESPONDER_LOG_DIR" ]; then
    RESPONDER_LOG_DIR="/var/lib/responder/logs"
fi

OUTPUT_FILE="/home/ov3rr1d3/wifi_arsenal/captures/hashes/responder_hashes.txt"
HASH_JSON="/home/ov3rr1d3/wifi_arsenal/captures/hashes/hashes.json"
SEEN_FILE="/tmp/seen_hashes.txt"

touch "$OUTPUT_FILE"
touch "$SEEN_FILE"
echo "[]" > "$HASH_JSON"

echo "[*] Monitoring for new hashes in $RESPONDER_LOG_DIR"

while true; do
    # Find NTLMv2 hash files
    for hashfile in "$RESPONDER_LOG_DIR"/*NTLM*.txt 2>/dev/null; do
        if [ -f "$hashfile" ]; then
            while IFS= read -r line; do
                # Hash format: user::domain:challenge:response:response
                if [[ "$line" == *"::"* ]] && [[ "$line" != "" ]]; then
                    HASH_ID=$(echo "$line" | md5sum | cut -d' ' -f1)
                    
                    if ! grep -q "$HASH_ID" "$SEEN_FILE" 2>/dev/null; then
                        echo "$HASH_ID" >> "$SEEN_FILE"
                        echo "$line" >> "$OUTPUT_FILE"
                        
                        # Parse hash components
                        USER=$(echo "$line" | cut -d: -f1)
                        DOMAIN=$(echo "$line" | cut -d: -f3)
                        
                        echo "[+] NEW HASH: $DOMAIN\\$USER"
                        
                        # Update JSON
                        python3 << PYEOF
import json
import os
from datetime import datetime

hash_file = "$HASH_JSON"
new_hash = {
    "user": "$USER",
    "domain": "$DOMAIN",
    "hash": """$line""",
    "type": "NTLMv2",
    "status": "captured",
    "cracked_password": None,
    "timestamp": datetime.now().isoformat()
}

try:
    with open(hash_file, 'r') as f:
        hashes = json.load(f)
except:
    hashes = []

# Check for duplicate
is_dupe = False
for h in hashes:
    if h.get("user") == new_hash["user"] and h.get("domain") == new_hash["domain"]:
        is_dupe = True
        break

if not is_dupe:
    hashes.append(new_hash)
    with open(hash_file, 'w') as f:
        json.dump(hashes, f, indent=2)
    print(f"[+] Added to {hash_file}")
PYEOF
                    fi
                fi
            done < "$hashfile"
        fi
    done
    
    sleep 5
done
