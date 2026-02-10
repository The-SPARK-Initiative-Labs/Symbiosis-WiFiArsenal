#!/usr/bin/env python3
"""
Vehicle WiFi SSID Filter — Regex-based pattern matching
Source: ~/Desktop/vehicle-wifi-ssid-patterns.md (128 patterns, 10 categories)

Replaces naive substring matching that caused false positives:
  - 'ram' matched Ramona, Ramsey, Program
  - 'audi' matched Audit, Auditorium
  - 'ford' matched LGFordLincoln, Bedford, Stanford
  - 'car' matched Oscar, McCarthy
  - 'sync' matched Syncthing

Each pattern uses the minimum match type needed (PREFIX, EXACT, REGEX)
to filter vehicles without killing legitimate business networks.
"""

import re

# Compiled vehicle WiFi SSID patterns — organized by category and tier
VEHICLE_SSID_PATTERNS = [
    # ===================================================================
    # TIER 1: High-frequency, high-confidence
    # ===================================================================

    # GM Brands (OnStar) — millions of vehicles, always broadcasting
    re.compile(r'^WiFi Hotspot [A-Za-z0-9]{4}$', re.IGNORECASE),
    re.compile(r'^myChevrolet', re.IGNORECASE),       # bare, hex suffix, digits — all vehicle
    re.compile(r'^myGMC', re.IGNORECASE),              # bare, hex suffix, digits — all vehicle
    re.compile(r'^myBuick', re.IGNORECASE),            # bare, hex suffix, digits — all vehicle
    re.compile(r'^myCadillac', re.IGNORECASE),         # bare, hex suffix, digits — all vehicle
    re.compile(r'^CHEVROLET', re.IGNORECASE),          # bare, CHEVROLET_6277, etc.

    # BMW
    re.compile(r'^My BMW Hotspot \w{4}$', re.IGNORECASE),
    re.compile(r'^DIRECT-BMW\s?\d{5}$', re.IGNORECASE),

    # Mercedes-Benz — do NOT match bare "MB"
    re.compile(r'^MB Hotspot', re.IGNORECASE),
    re.compile(r'^DIRECT-MBUX\s\d{5}$', re.IGNORECASE),

    # Audi — do NOT match bare "audi" (hits Audit, Auditorium)
    re.compile(r'^Audi_MMI_', re.IGNORECASE),
    re.compile(r'^Audi\d{4,6}$', re.IGNORECASE),

    # Stellantis / Uconnect — Ram/Jeep/Dodge/Chrysler all use Uconnect branding
    re.compile(r'^[Uu]connect', re.IGNORECASE),        # uconnectadpt, Uconnect-33623536, etc.

    # OBD-II Dongles
    re.compile(r'^WiFi[_-]OBD(II|2)$', re.IGNORECASE),
    re.compile(r'^CLK\s?Devices$', re.IGNORECASE),
    re.compile(r'^V-?LINK$', re.IGNORECASE),
    re.compile(r'^OBDLink', re.IGNORECASE),
    re.compile(r'^OBDII$', re.IGNORECASE),
    re.compile(r'^OBD2$', re.IGNORECASE),
    re.compile(r'^ELM327$', re.IGNORECASE),

    # Dash Cams (highest volume in wardriving data)
    re.compile(r'^(5G_)?VIOFO[-_]', re.IGNORECASE),
    re.compile(r'^DR\d{3,4}[A-Z]?[-_]', re.IGNORECASE),   # BlackVue
    re.compile(r'_VANTRUE_', re.IGNORECASE),                 # Vantrue (substring — user cannot rename)
    re.compile(r'^70mai_', re.IGNORECASE),
    re.compile(r'^Thinkware_', re.IGNORECASE),
    re.compile(r'^DDPAI_', re.IGNORECASE),
    re.compile(r'^(NVT_)?CARDV', re.IGNORECASE),
    re.compile(r'^GP\d{6,10}$'),                             # GoPro Hero 5+

    # ===================================================================
    # TIER 2: Medium-frequency, confirmed
    # ===================================================================

    # Toyota/Lexus — do NOT match bare "Toyota" (dealerships)
    re.compile(r'^Toyota .+-\d+[gG]_[a-f0-9]+'),
    re.compile(r'^Lexus .+-\d+[gG]_[a-f0-9]+'),

    # Nissan/Infiniti — MY + model name + random suffix
    re.compile(r'^MY\s?(PATHFINDER|ROGUE|ARMADA|ALTIMA|SENTRA|FRONTIER|MURANO|KICKS|ARIYA|LEAF|MAXIMA|VERSA|TITAN)[A-Z0-9]+$'),
    re.compile(r'^MY\s?(QX60|QX80|QX50|Q50|Q60)[A-Z0-9]+$'),

    # Subaru — require model name after brand
    re.compile(r'^Subaru (Crosstrek|Outback|Forester|Ascent|Legacy|Impreza|WRX|Solterra|BRZ)', re.IGNORECASE),

    # Porsche
    re.compile(r'^Porsche[_ ]WLAN', re.IGNORECASE),     # drop $ — catches Porsche_WLAN_8995 etc.

    # Land Rover — do NOT match bare "LR" (too generic)
    re.compile(r'^LR\d{6}$'),

    # Ford SYNC 4 projection
    re.compile(r'^PROJ[A-Za-z0-9]+$'),

    # Ford/Lincoln
    re.compile(r'^FordPass[_ ]', re.IGNORECASE),
    re.compile(r'^LincolnWay[_ ]', re.IGNORECASE),

    # CarPlay/WiFi Direct head units
    re.compile(r'^WiFi-AP-[0-9a-fA-F]{6}$', re.IGNORECASE),
    re.compile(r'^CarPlay_', re.IGNORECASE),

    # Dash Cams (continued)
    re.compile(r'^[Nn]ext[Bb]ase[-_ ]'),
    re.compile(r'^Roav[_ ]', re.IGNORECASE),
    re.compile(r'^B50_[A-Fa-f0-9]{4}'),
    re.compile(r'^Miofive_', re.IGNORECASE),
    re.compile(r'^Papago-', re.IGNORECASE),
    re.compile(r'^TYPE_S_', re.IGNORECASE),
    re.compile(r'^M5[56]0_'),
    re.compile(r'^IROAD_', re.IGNORECASE),
    re.compile(r'^KENWOOD\s+DRV', re.IGNORECASE),
    re.compile(r'^(G840[HS]|G930|G900|i07)'),              # Wolfbox

    # Backup Cameras — require separator after "car" (not bare substring)
    re.compile(r'^[Ss][Ww][Dd]_\w+'),
    re.compile(r'^[Cc]ar[_-]\w+'),
    re.compile(r'^WIFICAMERA$', re.IGNORECASE),
    re.compile(r'^WIFIAV', re.IGNORECASE),

    # Carrier vehicle devices
    re.compile(r'^T-Mobile[_ ]Broadband\d{2}$', re.IGNORECASE),

    # Fleet/Transit/Law Enforcement
    re.compile(r'^[Pp]ep[Ww]ave_'),
    re.compile(r'^Pvt\.WFR_'),
    re.compile(r'^AXON-[A-Z0-9]+$', re.IGNORECASE),
    re.compile(r'^IBR\d{3,4}-'),
    re.compile(r'^Digi-TX54-'),
    re.compile(r'^Digi Hotspot$', re.IGNORECASE),
    re.compile(r'^Digi-WR54-'),
    re.compile(r'^MofiNetwork', re.IGNORECASE),
    re.compile(r'^RUT[A-Z0-9]{1,4}_'),
    re.compile(r'^Teltonika_Router$', re.IGNORECASE),
    re.compile(r'^Kajeet', re.IGNORECASE),
    re.compile(r'^BusWiFi$', re.IGNORECASE),
    re.compile(r'^Greyhound WiFi$', re.IGNORECASE),
    re.compile(r'^Megabus RIDE$', re.IGNORECASE),
    re.compile(r'^FlixBus', re.IGNORECASE),
    re.compile(r'^AmtrakConnect$', re.IGNORECASE),

    # RV / Motorhome
    re.compile(r'^KING (5G|2\.4G)', re.IGNORECASE),
    re.compile(r'^MV2458-'),
    re.compile(r'^Furrion', re.IGNORECASE),

    # ===================================================================
    # TIER 3: Lower-frequency or less-confirmed
    # ===================================================================

    # Stellantis alternate patterns
    re.compile(r'^Wi-Fi Hotspot \d{5}$'),
    re.compile(r'^Wi-Fi-Hotspot .{2}$'),

    # BMW / MINI alternate
    re.compile(r'^BMW_\w{4,8}$'),
    re.compile(r'^MINI[_\s]\d{4,5}$', re.IGNORECASE),  # MINI Cooper (digit suffix avoids "Ministry")

    # Toyota WiFi Direct
    re.compile(r'^DIRECT-.{2}-AUDIO_PLUS'),
    re.compile(r'^DIRECT-.{2}-PREMIUM_AUDIO'),
    re.compile(r'^DIRECT-.{2}-Car_\w{4}$'),

    # Chinese EVs
    re.compile(r'^小鹏'),
    re.compile(r'^XPENG'),

    # Android head units (may catch some old phones — low risk)
    re.compile(r'^AndroidAP$'),
    re.compile(r'^AndroidAP_'),

    # Vehicle adapters / tuners
    re.compile(r'^AAWirelessDongle$', re.IGNORECASE),
    re.compile(r'^weedle$'),
    re.compile(r'^Wifi327$', re.IGNORECASE),
    re.compile(r'^bootmod3', re.IGNORECASE),
    re.compile(r'^EZLYNK[_-]', re.IGNORECASE),

    # Dash cams (lower frequency)
    re.compile(r'^OSMO_(ACTION|POCKET)', re.IGNORECASE),
    re.compile(r'^YI[-_]', re.IGNORECASE),
    re.compile(r'^DJI_', re.IGNORECASE),
    re.compile(r'^(M300S|PG17|M63|GS63H)[-_]'),
    re.compile(r'^(ONE X|One RS|X[2-5]|GO [23]|Ace)'),

    # Intercity bus
    re.compile(r'^BoltBus$', re.IGNORECASE),

    # ===================================================================
    # TIER 2/3 additions: Patterns from DEVICE_DATABASE (anchored ^)
    # ===================================================================

    # Generic dashcam / fleet cameras
    re.compile(r'^Dash-', re.IGNORECASE),            # Generic dashcam
    re.compile(r'^Driveri', re.IGNORECASE),           # Netradyne fleet camera
    re.compile(r'^Blackvue', re.IGNORECASE),          # BlackVue dashcam (bare name)
    re.compile(r'^ROVE_R2', re.IGNORECASE),           # Rove dashcam

    # Fleet ELD / tracking
    re.compile(r'^KeepTruckin', re.IGNORECASE),       # Fleet ELD
    re.compile(r'^Samsara', re.IGNORECASE),           # Fleet tracking
    re.compile(r'^IOSiX', re.IGNORECASE),             # ELD device
    re.compile(r'^jomupi-eld', re.IGNORECASE),        # ELD device

    # Backup camera
    re.compile(r'^YADA_BEON', re.IGNORECASE),         # Backup camera

    # OEM diagnostic tools
    re.compile(r'^witech', re.IGNORECASE),            # OEM diagnostic tool
    re.compile(r'^wva-', re.IGNORECASE),              # Vehicle diagnostic adapter

    # GM vehicle models / infotainment
    re.compile(r'^Silverado[_\s]?\d', re.IGNORECASE),  # Chevy Silverado (require digit suffix, avoid "Silverado Ranch")
    re.compile(r'^Escalade[_\s]?\d', re.IGNORECASE),  # Cadillac Escalade (require digit suffix)
    re.compile(r'^Traverse[_\s]?\d', re.IGNORECASE),  # Chevy Traverse (require digit suffix, avoid "Traverse City")
    re.compile(r'^MyLink[_\s]?\d', re.IGNORECASE),    # Chevy MyLink infotainment (require digit suffix)
    re.compile(r'^OnStar[_\s]?\d', re.IGNORECASE),    # GM OnStar (require digit suffix)

    # European / other OEM
    re.compile(r'^My VW', re.IGNORECASE),             # Volkswagen Car-Net
    re.compile(r'^Mazda_', re.IGNORECASE),            # Mazda Connect
    re.compile(r'^Cayenne_', re.IGNORECASE),          # Porsche Cayenne
    re.compile(r'^MBUX', re.IGNORECASE),              # Mercedes MBUX
    re.compile(r'^MB WLAN', re.IGNORECASE),           # Mercedes WLAN
    re.compile(r'^landrover', re.IGNORECASE),         # Land Rover InControl
    re.compile(r'^Nissan RSE', re.IGNORECASE),        # Nissan rear seat entertainment

    # ===================================================================
    # GAP CLOSURE: Patterns from DB gap analysis (182 missed vehicles)
    # ===================================================================

    # BMW with space+digits (BMW 83700, BMW 09520, BMW 09647 CarPlay)
    re.compile(r'^BMW\s\d{4,5}', re.IGNORECASE),

    # BUICK standalone digits (BUICK1773, BUICK9980)
    re.compile(r'^BUICK\d', re.IGNORECASE),

    # GMC standalone digits (GMC8589, GMC7288)
    re.compile(r'^GMC\d{4}', re.IGNORECASE),

    # GMC with space (GMC Wifi, GMC Dialys, My GMC)
    re.compile(r'^(My\s)?GMC(\s|$)', re.IGNORECASE),

    # Cadillac with space+digit (Cadillac 58)
    re.compile(r'^Cadillac\s\d', re.IGNORECASE),

    # WiFi Direct GM variants (DIRECT-i6-myChevrolet, DIRECT-FH-myCadillac)
    re.compile(r'^DIRECT-.{2}-my(Chevrolet|GMC|Buick|Cadillac)', re.IGNORECASE),

    # Ford SYNC with underscore suffix (SYNC_XR4744JS — safe: requires underscore+alphanum)
    re.compile(r'^SYNC_[A-Z0-9]+$', re.IGNORECASE),

    # TOYOTA uppercase + space + model (always vehicle, dealerships don't use this format)
    re.compile(r'^TOYOTA\s', re.IGNORECASE),

    # LEXUS uppercase + space/bare (LEXUS NX-2.4g_..., bare "Lexus")
    re.compile(r'^LEXUS[\s_]', re.IGNORECASE),
    re.compile(r'^Lexus$', re.IGNORECASE),

    # Chevy Tahoe — all in DB are personal vehicle hotspots
    re.compile(r'^Tahoe', re.IGNORECASE),

    # GMC Acadia — bare exact
    re.compile(r'^Acadia$', re.IGNORECASE),

    # Tesla — Powerwalls caught too, acceptable tradeoff
    re.compile(r'^Tesla', re.IGNORECASE),

    # Motive fleet ELD (Motive AABL36XX######)
    re.compile(r'^Motive\s', re.IGNORECASE),

    # GMC with alpha model code (GMCSLT9168255532)
    re.compile(r'^GMC[A-Z]{2,}', re.IGNORECASE),

    # Bare model names (exact match or year-prefixed)
    re.compile(r'^Traverse$', re.IGNORECASE),
    re.compile(r'^\d{4}\s?Escalade', re.IGNORECASE),
    re.compile(r'^\d{4}\s?[Ss]ilverado', re.IGNORECASE),
    re.compile(r'^\d{4}\s?[Cc]hevy', re.IGNORECASE),
]


def is_vehicle_ssid(ssid):
    """Check if SSID matches any known vehicle WiFi pattern.

    Returns True if the SSID belongs to a vehicle (should be filtered from map).
    Returns False for None, empty, or non-matching SSIDs.
    """
    if not ssid:
        return False
    return any(p.search(ssid) for p in VEHICLE_SSID_PATTERNS)
