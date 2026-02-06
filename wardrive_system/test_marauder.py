#!/usr/bin/env python3
"""Test script to find marauder dumps"""

import serial
import time

ser = serial.Serial('/dev/ttyACM0', 115200, timeout=2)
time.sleep(1)

def send_cmd(cmd):
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    ser.write(f"{cmd}\r\n".encode())
    time.sleep(1.5)
    response = b''
    while ser.in_waiting:
        response += ser.read(ser.in_waiting)
        time.sleep(0.1)
    return response.decode('utf-8', errors='ignore')

print("Looking for marauder:")
print("=" * 60)

print("\nChecking: /ext/apps_data")
result = send_cmd('storage list /ext/apps_data')
print(result)

if 'marauder' in result.lower():
    print("\n✅ Found marauder folder!")
    print("\nChecking: /ext/apps_data/marauder")
    result = send_cmd('storage list /ext/apps_data/marauder')
    print(result)
    
    if 'dumps' in result.lower():
        print("\n✅ Found dumps folder!")
        print("\nChecking: /ext/apps_data/marauder/dumps")
        result = send_cmd('storage list /ext/apps_data/marauder/dumps')
        print(result)

ser.close()
