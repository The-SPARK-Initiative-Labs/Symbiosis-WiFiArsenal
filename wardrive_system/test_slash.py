#!/usr/bin/env python3
"""Test with and without trailing slash"""

import serial
import time

ser = serial.Serial('/dev/ttyACM0', 115200, timeout=2)
time.sleep(1.5)

def test_path(path):
    print(f"\nTesting: {repr(path)}")
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    ser.write(f'storage list {path}\r\n'.encode())
    time.sleep(1.5)
    
    response = b''
    while ser.in_waiting:
        response += ser.read(ser.in_waiting)
        time.sleep(0.1)
    
    result = response.decode('utf-8', errors='ignore')
    if 'error' in result.lower():
        print("  ❌ ERROR")
    else:
        print("  ✅ SUCCESS")
    print(result)

test_path('/ext/apps_data/marauder/dumps/')  # With slash
test_path('/ext/apps_data/marauder/dumps')   # Without slash

ser.close()
