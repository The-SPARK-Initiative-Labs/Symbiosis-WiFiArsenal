#!/bin/bash
# GUI wrapper for Flipper sync - triggered by udev when Flipper is plugged in

SCRIPT_DIR="/home/ov3rr1d3/wifi_arsenal/wardrive_system"
PYTHON_SCRIPT="$SCRIPT_DIR/flipper_sync.py"
LOG_FILE="$SCRIPT_DIR/flipper_sync.log"

# Wait a moment for device to stabilize
sleep 2

# Check if Flipper is actually connected
if [ ! -e "/dev/ttyACM0" ]; then
    exit 0
fi

# Show GUI prompt using zenity
if zenity --question \
    --title="Flipper Zero Detected" \
    --text="Br34ch3r connected!\n\nImport wardrive files from Flipper?" \
    --width=300 \
    --ok-label="Import" \
    --cancel-label="Skip"; then
    
    # User clicked Import
    # Run sync in a terminal so user can see progress
    gnome-terminal -- bash -c "
        echo '🔄 Starting Flipper Sync...'
        echo ''
        cd '$SCRIPT_DIR'
        python3 '$PYTHON_SCRIPT' 2>&1 | tee '$LOG_FILE'
        echo ''
        echo 'Press Enter to close...'
        read
    "
else
    # User clicked Skip
    notify-send "Flipper Zero" "Skipped wardrive import" --icon=dialog-information
fi
