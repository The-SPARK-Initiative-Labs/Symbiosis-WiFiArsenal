#!/bin/bash

# RUN_WARDRIVE.sh - Linux version for Sh4d0wFr4m3 (Kali Linux)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGES_DIR="$(dirname "$SCRIPT_DIR")/python_packages"
PYTHON_SCRIPT="$SCRIPT_DIR/wardrive_mapper.py"

echo "============================================"
echo "    WARDRIVE MAPPER - Linux Edition"
echo "============================================"
echo ""

if [ ! -d "$PACKAGES_DIR" ]; then
    echo "ERROR: Python packages not found"
    exit 1
fi

export PYTHONPATH="$PACKAGES_DIR:$PYTHONPATH"

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "ERROR: wardrive_mapper.py not found"
    exit 1
fi

WARDRIVE_COUNT=$(ls "$SCRIPT_DIR"/wardrive*.txt 2>/dev/null | wc -l)

if [ $WARDRIVE_COUNT -eq 0 ]; then
    echo "No wardrive*.txt files found"
    echo ""
    read -p "Press Enter to exit..."
    exit 1
fi

echo "Found $WARDRIVE_COUNT wardrive file(s) to process"
echo ""

read -p "Download offline map tiles? (Y/N, default=N): " DOWNLOAD_CHOICE
DOWNLOAD_CHOICE=${DOWNLOAD_CHOICE:-N}

echo ""
echo "Processing wardrive data..."
echo ""

for WARDRIVE_FILE in "$SCRIPT_DIR"/wardrive*.txt; do
    if [ -f "$WARDRIVE_FILE" ]; then
        echo "Processing: $(basename "$WARDRIVE_FILE")"
        python3 "$PYTHON_SCRIPT" "$WARDRIVE_FILE"
    fi
done

echo ""
echo "Map generation complete!"
echo ""

if [[ "$DOWNLOAD_CHOICE" =~ ^[Yy]$ ]]; then
    echo "Downloading map tiles..."
    python3 "$SCRIPT_DIR/download_tiles.py"
    echo ""
fi

HTML_FILE="$(dirname "$SCRIPT_DIR")/wardrive_master_map.html"
if [ -f "$HTML_FILE" ]; then
    echo "Opening map in browser..."
    xdg-open "$HTML_FILE" 2>/dev/null || firefox "$HTML_FILE" 2>/dev/null || chromium "$HTML_FILE" 2>/dev/null
fi

echo ""
echo "Press Enter to exit..."
read
