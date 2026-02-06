#!/bin/bash
# Check if capture file contains a valid handshake/PMKID
# Usage: ./check_handshake.sh <capture_file> [output_hash_file]
# Returns: 0 if valid hash found, 1 if not
#
# If output_hash_file provided, writes hash there on success

CAPTURE_FILE="$1"
OUTPUT_FILE="$2"

if [ -z "$CAPTURE_FILE" ]; then
    exit 1
fi

if [ ! -f "$CAPTURE_FILE" ]; then
    exit 1
fi

# Create temp file for hash output
TEMP_HASH="/tmp/check_hash_$$.hc22000"

# Try to extract hash
hcxpcapngtool -o "$TEMP_HASH" "$CAPTURE_FILE" 2>/dev/null

# Check if hash file exists and has content
if [ -f "$TEMP_HASH" ] && [ -s "$TEMP_HASH" ]; then
    # Success - we have a hash
    if [ -n "$OUTPUT_FILE" ]; then
        mv "$TEMP_HASH" "$OUTPUT_FILE"
    else
        rm -f "$TEMP_HASH"
    fi
    exit 0
else
    # No valid hash
    rm -f "$TEMP_HASH" 2>/dev/null
    exit 1
fi
