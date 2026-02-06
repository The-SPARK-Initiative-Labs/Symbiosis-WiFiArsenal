#!/usr/bin/env python3
"""Quick test to see actual response format"""

import serial
import time

ser = serial.Serial('/dev/ttyACM0', 115200, timeout=2)
time.sleep(1.5)

ser.reset_input_buffer()
ser.reset_output_buffer()
ser.write(b'storage list /ext/apps_data/marauder/dumps/\r\n')
time.sleep(1.5)

response = b''
while ser.in_waiting:
    response += ser.read(ser.in_waiting)
    time.sleep(0.1)

result = response.decode('utf-8', errors='ignore')
print("RAW RESPONSE:")
print(repr(result))
print("\n" + "=" * 60)
print("ACTUAL OUTPUT:")
print(result)
print("=" * 60)

print("\nPARSING:")
for i, line in enumerate(result.split('\n')):
    print(f"Line {i}: {repr(line)}")
    if '.txt' in line and 'wardrive' in line.lower():
        print(f"  -> MATCHES! Parts: {line.split()}")

ser.close()
