#!/usr/bin/env python3
"""Test script to explore Flipper filesystem"""

import serial
import time

ser = serial.Serial('/dev/ttyACM0', 115200, timeout=2)
time.sleep(1)

def send_cmd(cmd):
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    ser.write(f"{cmd}\r\n".encode())
    time.sleep(1)
    response = b''
    while ser.in_waiting:
        response += ser.read(ser.in_waiting)
        time.sleep(0.1)
    return response.decode('utf-8', errors='ignore')

print("Testing root paths:")
print("=" * 60)

for path in ['/', '/ext', '/int', '/any']:
    print(f"\nTrying: storage list {path}")
    result = send_cmd(f'storage list {path}')
    print(result)
    print("-" * 60)

ser.close()
