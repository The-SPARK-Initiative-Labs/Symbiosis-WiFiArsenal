#!/usr/bin/env python3
"""
Flipper Wardrive Sync
Automatically syncs wardrive .txt files from Flipper's Marauder dumps folder
to local system, then deletes them from Flipper
"""

import serial
import time
import os
import sys

FLIPPER_BAUD = 115200
DUMPS_PATH = '/ext/apps_data/marauder/dumps'  # NO TRAILING SLASH!
LOCAL_WARDRIVE_DIR = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/'


def find_flipper_port():
    """Scan /dev/ttyACM* devices and identify which one is a Flipper Zero.

    Opens each at 115200 baud (Flipper's rate) and sends 'storage list /ext'.
    If response contains 'apps_data' → confirmed Flipper.
    If response contains NMEA data ($G) → that's the GPS, skip it.
    Returns (port_string, None) or (None, None).
    """
    import glob as g
    ports = sorted(g.glob('/dev/ttyACM*'))
    if not ports:
        return None

    for port in ports:
        try:
            ser = serial.Serial(port, FLIPPER_BAUD, timeout=2)
            time.sleep(0.5)

            # Flush any pending data
            ser.reset_input_buffer()
            ser.reset_output_buffer()

            # Check if it's spitting out NMEA (GPS device)
            initial = ser.read(ser.in_waiting or 1).decode('ascii', errors='ignore')
            if '$G' in initial:
                ser.close()
                continue  # That's GPS, not Flipper

            # Try Flipper CLI command
            ser.write(b'storage list /ext\r\n')
            time.sleep(1.5)

            response = b''
            while ser.in_waiting:
                response += ser.read(ser.in_waiting)
                time.sleep(0.1)

            text = response.decode('utf-8', errors='ignore')
            ser.close()

            if 'apps_data' in text or '[D]' in text or '[F]' in text:
                return port

            # If we got NMEA back, it's GPS
            if '$G' in text:
                continue

        except Exception:
            try:
                ser.close()
            except Exception:
                pass
            continue

    return None

def send_command(ser, cmd, wait_time=1.5):
    """Send command to Flipper and read response"""
    # Flush buffers
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    
    # Send command
    ser.write(f"{cmd}\r\n".encode())
    time.sleep(wait_time)
    
    # Read response
    response = b''
    while ser.in_waiting:
        response += ser.read(ser.in_waiting)
        time.sleep(0.1)
    
    return response.decode('utf-8', errors='ignore')

def list_wardrive_files(ser):
    """List all wardrive .txt files in dumps folder"""
    print(f"📂 Listing files in {DUMPS_PATH}...")
    
    response = send_command(ser, f'storage list {DUMPS_PATH}')
    
    # Parse file list - look for lines with .txt files
    files = []
    for line in response.split('\n'):
        line = line.strip()
        if '.txt' in line and 'wardrive' in line.lower():
            # Extract filename from "[F] filename size" format
            parts = line.split()
            if len(parts) >= 2:
                filename = parts[1]
                files.append(filename)
    
    return files

def read_file_from_flipper(ser, filepath):
    """Read file contents from Flipper"""
    print(f"📖 Reading {filepath}...")
    
    # Use storage read command with longer wait time
    response = send_command(ser, f'storage read {filepath}', wait_time=3.0)
    
    # Extract file contents - everything after the command echo
    lines = response.split('\n')
    content_lines = []
    skip_lines = True
    
    for line in lines:
        # Skip until we see the WigleWifi header
        if 'WigleWifi' in line:
            skip_lines = False
        
        if not skip_lines:
            content_lines.append(line)
    
    return '\n'.join(content_lines).strip()

def delete_file_from_flipper(ser, filepath):
    """Delete file from Flipper after successful sync"""
    print(f"🗑️  Deleting {filepath} from Flipper...")
    
    response = send_command(ser, f'storage remove {filepath}')
    
    if 'error' in response.lower() or 'failed' in response.lower():
        print(f"❌ Failed to delete: {response}")
        return False
    
    print(f"✅ Deleted from Flipper")
    return True

def main():
    """Main sync process"""
    print("=" * 60)
    print("🔄 FLIPPER WARDRIVE SYNC")
    print("=" * 60)
    
    # Find Flipper port (smart detection — skips GPS devices)
    print("\n🔍 Scanning for Flipper Zero...")
    flipper_port = find_flipper_port()
    if not flipper_port:
        print("❌ Error: Flipper not found on any /dev/ttyACM* port")
        print("   Make sure Br34ch3r is plugged in and not in USB mass storage mode")
        sys.exit(1)

    # Open serial connection
    print(f"\n🔌 Connecting to Flipper at {flipper_port}...")
    try:
        ser = serial.Serial(flipper_port, FLIPPER_BAUD, timeout=2)
        time.sleep(1.5)  # Wait for connection to stabilize
        print("✅ Connected")
    except Exception as e:
        print(f"❌ Failed to connect: {e}")
        sys.exit(1)
    
    try:
        # List wardrive files
        files = list_wardrive_files(ser)
        
        if not files:
            print("\n📭 No wardrive files found on Flipper")
            print("   Run a wardrive on the Flipper first!")
            ser.close()
            sys.exit(0)
        
        print(f"\n✅ Found {len(files)} wardrive file(s):")
        for f in files:
            print(f"   • {f}")
        
        # Sync each file
        synced_count = 0
        for filename in files:
            print(f"\n{'=' * 60}")
            print(f"Processing: {filename}")
            print('=' * 60)
            
            filepath = f'{DUMPS_PATH}/{filename}'  # Build path with slash
            
            # Read file contents
            content = read_file_from_flipper(ser, filepath)
            
            if not content or len(content) < 50:
                print(f"❌ Failed to read file or file is too small")
                print(f"Content length: {len(content)} bytes")
                continue
            
            # Save locally
            local_path = os.path.join(LOCAL_WARDRIVE_DIR, filename)
            with open(local_path, 'w') as f:
                f.write(content)
            
            print(f"💾 Saved to: {local_path}")
            
            # Verify file was saved
            if os.path.exists(local_path):
                file_size = os.path.getsize(local_path)
                print(f"✅ File saved successfully ({file_size} bytes)")
                
                # Delete from Flipper
                if delete_file_from_flipper(ser, filepath):
                    synced_count += 1
            else:
                print(f"❌ Failed to save file locally")
        
        print(f"\n{'=' * 60}")
        print(f"✅ SYNC COMPLETE")
        print(f"   Synced {synced_count} of {len(files)} files")
        print('=' * 60)
        
        if synced_count > 0:
            print(f"\n💡 Next steps:")
            print(f"   cd /home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/")
            print(f"   python3 wardrive_mapper.py {files[0]}")
        
    except Exception as e:
        print(f"\n❌ Error during sync: {e}")
        import traceback
        traceback.print_exc()
    finally:
        ser.close()
        print("\n🔌 Disconnected from Flipper")

if __name__ == "__main__":
    main()
