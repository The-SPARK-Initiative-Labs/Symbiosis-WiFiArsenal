#!/usr/bin/env python3
"""Test script: validate vehicle_filter.py syntax and pattern matching."""
import sys
sys.path.insert(0, '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive')

# Step 1: Import validates syntax
try:
    from vehicle_filter import is_vehicle_ssid, VEHICLE_SSID_PATTERNS
    print(f"[OK] Import succeeded. {len(VEHICLE_SSID_PATTERNS)} patterns loaded.\n")
except Exception as e:
    print(f"[FATAL] Import failed: {e}")
    sys.exit(1)

# Step 2: Test all SSIDs from the 182-gap list that must return True
test_ssids = [
    "myChevrolet D07A",
    "myGMC F69B",
    "myBuick",
    "CHEVROLET_6277",
    "uconnectadpt",
    "Uconnect-33623536",
    "Porsche_WLAN_8995",
    "MY ROGUE1663",
    "BMW 83700",
    "BMW 09520",
    "BMW 09647 CarPlay",
    "BUICK1773",
    "BUICK9980",
    "GMC8589",
    "GMC7288",
    "GMC Wifi",
    "GMC Dialys",
    "My GMC",
    "Cadillac 58",
    "DIRECT-i6-myChevrolet",
    "DIRECT-FH-myCadillac",
    "SYNC_XR4744JS",
    "TOYOTA Camry",
    "TOYOTA RAV4",
    "LEXUS NX",
    "LEXUS NX-2.4g_abc123",
    "Lexus",
    "Tahoe",
    "Tahoe WiFi",
    "Acadia",
    "Tesla",
    "Tesla Model 3",
    "Traverse",
    "2021Escalade",
    "2021 Escalade",
    "2022Silverado",
    "2022 Silverado",
    "2023Chevy",
    "2023 chevy",
    "CHEVROLET",
    "myChevrolet",
    "myCadillac",
]

passed = 0
failed = 0
failures = []

for ssid in test_ssids:
    result = is_vehicle_ssid(ssid)
    if result:
        print(f"  PASS: {ssid!r}")
        passed += 1
    else:
        print(f"  FAIL: {ssid!r} -- expected True, got False")
        failed += 1
        failures.append(ssid)

print(f"\n{'='*60}")
print(f"Total patterns: {len(VEHICLE_SSID_PATTERNS)}")
print(f"Tests: {passed + failed} | Passed: {passed} | Failed: {failed}")
if failed:
    print(f"\nFailed SSIDs:")
    for f in failures:
        print(f"  - {f!r}")
    print(f"\nOVERALL: FAIL")
    sys.exit(1)
else:
    print(f"\nOVERALL: PASS -- All {passed} test SSIDs matched correctly.")
