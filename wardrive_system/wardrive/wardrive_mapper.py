#!/usr/bin/env python3
"""
Wardrive Mapper - Cumulative Edition
Converts Flipper Zero wardrive logs to interactive HTML maps
Supports cumulative data collection across multiple wardrive sessions
"""

import sys
import sqlite3
import folium
from folium import plugins
import pandas as pd
from datetime import datetime
import os
import math
import requests
import html  # For XSS protection - escape user-controlled SSID content

# Get script directory for relative paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ========== GPS TRACK HELPER FUNCTIONS ==========

def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two GPS points in miles using Haversine formula"""
    R = 3959  # Earth's radius in miles

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)

    a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    return R * c

def simplify_track(points, tolerance=0.0001):
    """
    Simplify GPS track using Douglas-Peucker algorithm.
    Reduces 9000+ points to ~300 while preserving route shape.
    Tolerance is in degrees (~11 meters at 0.0001)
    """
    if len(points) < 3:
        return points

    def perpendicular_distance(point, line_start, line_end):
        """Calculate perpendicular distance from point to line"""
        if line_start == line_end:
            return haversine_distance(point[0], point[1], line_start[0], line_start[1])

        # Use simplified distance calculation for performance
        x0, y0 = point[1], point[0]  # lon, lat
        x1, y1 = line_start[1], line_start[0]
        x2, y2 = line_end[1], line_end[0]

        num = abs((y2-y1)*x0 - (x2-x1)*y0 + x2*y1 - y2*x1)
        den = math.sqrt((y2-y1)**2 + (x2-x1)**2)

        if den == 0:
            return 0
        return num / den

    def douglas_peucker(points, epsilon):
        """Recursive Douglas-Peucker implementation"""
        if len(points) < 3:
            return points

        # Find point with maximum distance
        max_dist = 0
        max_idx = 0

        for i in range(1, len(points) - 1):
            dist = perpendicular_distance(points[i], points[0], points[-1])
            if dist > max_dist:
                max_dist = dist
                max_idx = i

        # If max distance > tolerance, recursively simplify
        if max_dist > epsilon:
            left = douglas_peucker(points[:max_idx+1], epsilon)
            right = douglas_peucker(points[max_idx:], epsilon)
            return left[:-1] + right
        else:
            return [points[0], points[-1]]

    return douglas_peucker(points, tolerance)

def calculate_track_stats(points, timestamps=None):
    """
    Calculate statistics for a GPS track.
    Returns: distance_miles, duration_seconds, avg_speed_mph
    """
    if len(points) < 2:
        return 0, 0, 0

    # Calculate total distance
    total_distance = 0
    for i in range(len(points) - 1):
        total_distance += haversine_distance(
            points[i][0], points[i][1],
            points[i+1][0], points[i+1][1]
        )

    # Calculate duration from timestamps
    duration_seconds = 0
    if timestamps and len(timestamps) >= 2:
        try:
            first_time = datetime.strptime(timestamps[0], '%Y-%m-%d %H:%M:%S')
            last_time = datetime.strptime(timestamps[-1], '%Y-%m-%d %H:%M:%S')
            duration_seconds = (last_time - first_time).total_seconds()

            # Sanity check: if duration > 24 hours, it's probably bad data
            if duration_seconds > 86400:  # 24 hours
                # Estimate based on points and typical wardrive speed
                duration_seconds = len(points) * 3  # ~3 seconds per point average
        except:
            duration_seconds = len(points) * 3  # Fallback estimate

    # Calculate average speed
    avg_speed = 0
    if duration_seconds > 0:
        avg_speed = (total_distance / duration_seconds) * 3600  # mph

    return round(total_distance, 2), int(duration_seconds), round(avg_speed, 1)

def format_duration(seconds):
    """Format seconds as human-readable duration"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        mins = seconds // 60
        secs = seconds % 60
        return f"{mins}m {secs}s"
    else:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"

# GPS track colors per session (professional, high contrast)
GPS_TRACK_COLORS = [
    '#00D4FF',  # Cyan
    '#FF6B00',  # Orange
    '#00FF85',  # Green
    '#FF00D4',  # Magenta
    '#FFE600',  # Yellow
    '#00FF00',  # Lime
    '#FF3366',  # Pink
    '#6699FF',  # Light blue
]

# Color coding based on signal strength (RSSI) - radar gradient style
# Thresholds adjusted for typical wardrive distribution where most signals are -70 to -90 dBm
def get_marker_color(rssi):
    """Return color based on signal strength - radar gradient (green to red)"""
    try:
        rssi = int(rssi)
        if rssi >= -65:
            return 'green'        # Top ~18% - Strong signals (drove close)
        elif rssi >= -72:
            return 'lightgreen'   # Next ~15% - Good signals
        elif rssi >= -78:
            return 'beige'        # Middle ~20% - Fair signals (yellow-ish)
        elif rssi >= -84:
            return 'orange'       # Next ~25% - Moderate signals
        elif rssi >= -92:
            return 'lightred'     # Next ~15% - Weak signals
        else:
            return 'red'          # Bottom ~7% - Very weak (barely detected)
    except:
        return 'gray'

def get_signal_strength_text(rssi):
    """Return human-readable signal strength"""
    try:
        rssi = int(rssi)
        if rssi >= -50:
            return 'Strong'
        elif rssi >= -70:
            return 'Medium'
        else:
            return 'Weak'
    except:
        return 'Unknown'

# Device identification database with exploit info
DEVICE_DATABASE = {
    # Printers - HP (OPEN ones have no password, DIRECT- have predictable passwords)
    'HP-Print-': {
        'type': 'Printer',
        'icon': 'print',
        'brand': 'HP',
        'desc': 'HP WiFi Direct Printer',
        'exploit': 'OPEN = no password needed. Connect directly. Access web panel at 192.168.223.1',
        'setup_url': 'http://192.168.223.1 or HP Smart app',
        'vuln_level': 'high' if '[OPEN]' else 'medium'
    },
    'HP-Setup': {
        'type': 'Printer (Setup Mode)',
        'icon': 'print',
        'brand': 'HP',
        'desc': 'HP Printer in setup mode - not yet configured',
        'exploit': 'UNCONFIGURED! Connect and access setup at 192.168.223.1. Can hijack printer ownership.',
        'setup_url': 'http://192.168.223.1',
        'vuln_level': 'critical'
    },
    'DIRECT-': {
        'type': 'WiFi Direct Device',
        'icon': 'print',
        'brand': 'Various',
        'desc': 'WiFi Direct (usually printer). Password often on device label or predictable.',
        'exploit': 'Default password usually printed on device. Try: 12345678, password, or check device sticker.',
        'setup_url': 'Connect then browse to 192.168.223.1',
        'vuln_level': 'medium'
    },
    # Printers - Other brands
    'Canon': {
        'type': 'Printer',
        'icon': 'print',
        'brand': 'Canon',
        'desc': 'Canon WiFi Printer',
        'exploit': 'Web panel at printer IP. Default login often admin/admin or no password.',
        'setup_url': 'Canon PRINT app or http://<printer-ip>',
        'vuln_level': 'medium'
    },
    'EPSON': {
        'type': 'Printer',
        'icon': 'print',
        'brand': 'Epson',
        'desc': 'Epson WiFi Printer',
        'exploit': 'Web panel at printer IP. Check for default credentials.',
        'setup_url': 'Epson Smart Panel app or http://<printer-ip>',
        'vuln_level': 'medium'
    },
    'Brother': {
        'type': 'Printer',
        'icon': 'print',
        'brand': 'Brother',
        'desc': 'Brother WiFi Printer',
        'exploit': 'Web panel usually no auth required. Access at printer IP.',
        'setup_url': 'Brother iPrint&Scan app',
        'vuln_level': 'medium'
    },

    # Ring Doorbells/Cameras
    'Ring-': {
        'type': 'Smart Doorbell/Camera',
        'icon': 'bell',
        'brand': 'Ring (Amazon)',
        'desc': 'Ring device broadcasting for setup or pairing',
        'exploit': 'Setup mode = unclaimed device. Can be registered to your Ring account!',
        'setup_url': 'Ring app (iOS/Android)',
        'vuln_level': 'critical'
    },
    'Ring Setup': {
        'type': 'Smart Doorbell (Setup Mode)',
        'icon': 'bell',
        'brand': 'Ring (Amazon)',
        'desc': 'Ring in SETUP MODE - someone reset it or never finished setup',
        'exploit': 'UNCLAIMED! Open Ring app, add new device, claim this doorbell as yours.',
        'setup_url': 'Ring app → Set Up Device → Doorbells',
        'vuln_level': 'critical'
    },

    # Blink Cameras
    'BLINK-': {
        'type': 'Security Camera (Setup)',
        'icon': 'video',
        'brand': 'Blink (Amazon)',
        'desc': 'Blink camera in setup mode',
        'exploit': 'Setup mode = unclaimed. Register with Blink app to own the camera.',
        'setup_url': 'Blink Home Monitor app',
        'vuln_level': 'critical'
    },

    # Google/Nest
    'GoogleHome': {
        'type': 'Smart Speaker',
        'icon': 'microphone',
        'brand': 'Google',
        'desc': 'Google Home/Nest speaker in setup mode',
        'exploit': 'Setup mode. Google Home app can claim and configure.',
        'setup_url': 'Google Home app',
        'vuln_level': 'high'
    },
    'Nest': {
        'type': 'Smart Home Device',
        'icon': 'home',
        'brand': 'Nest (Google)',
        'desc': 'Nest thermostat/camera/device',
        'exploit': 'If in setup mode, can be claimed via Google Home app.',
        'setup_url': 'Google Home app',
        'vuln_level': 'high'
    },

    # Chromecast
    'Chromecast': {
        'type': 'Streaming Device',
        'icon': 'tv',
        'brand': 'Google',
        'desc': 'Chromecast in setup mode',
        'exploit': 'Claim with Google Home app. Once on same network, can cast to it.',
        'setup_url': 'Google Home app',
        'vuln_level': 'high'
    },

    # Roku
    'Roku': {
        'type': 'Streaming Device',
        'icon': 'tv',
        'brand': 'Roku',
        'desc': 'Roku streaming device',
        'exploit': 'WiFi Direct mode. API at port 8060 often unauthenticated. Can control remotely.',
        'setup_url': 'Roku app or http://<roku-ip>:8060',
        'vuln_level': 'medium'
    },
    'DIRECT-roku': {
        'type': 'Streaming Device',
        'icon': 'tv',
        'brand': 'Roku',
        'desc': 'Roku in WiFi Direct mode for screen mirroring',
        'exploit': 'Connect for screen mirroring. REST API at port 8060.',
        'setup_url': 'Roku app',
        'vuln_level': 'medium'
    },

    # Sonos
    'SONOS-': {
        'type': 'Smart Speaker',
        'icon': 'music',
        'brand': 'Sonos',
        'desc': 'Sonos speaker in setup mode',
        'exploit': 'Setup mode = unconfigured. Sonos app can claim speaker.',
        'setup_url': 'Sonos app',
        'vuln_level': 'high'
    },

    # Sony Speakers/Audio
    'SRS-': {
        'type': 'Wireless Speaker',
        'icon': 'music',
        'brand': 'Sony',
        'desc': 'Sony SRS wireless speaker (360° sound, Chromecast, AirPlay)',
        'exploit': 'OPEN setup mode! Connect via Sony Music Center app to claim speaker. Control playback, volume.',
        'setup_url': 'Sony Music Center app',
        'vuln_level': 'high'
    },
    'WH-': {
        'type': 'Wireless Headphones',
        'icon': 'headphones',
        'brand': 'Sony',
        'desc': 'Sony WH-series headphones (WH-1000XM series, etc.)',
        'exploit': 'Bluetooth pairing mode. Sony Headphones Connect app.',
        'setup_url': 'Sony Headphones Connect app',
        'vuln_level': 'low'
    },
    'WF-': {
        'type': 'Wireless Earbuds',
        'icon': 'headphones',
        'brand': 'Sony',
        'desc': 'Sony WF-series earbuds',
        'exploit': 'Bluetooth pairing mode.',
        'setup_url': 'Sony Headphones Connect app',
        'vuln_level': 'low'
    },
    'HT-': {
        'type': 'Soundbar',
        'icon': 'music',
        'brand': 'Sony',
        'desc': 'Sony HT-series soundbar with WiFi',
        'exploit': 'Setup mode. Sony Music Center to configure. May expose web interface.',
        'setup_url': 'Sony Music Center app',
        'vuln_level': 'medium'
    },

    # JBL/Harman Speakers
    'JBL': {
        'type': 'Wireless Speaker',
        'icon': 'music',
        'brand': 'JBL (Harman)',
        'desc': 'JBL Bluetooth/WiFi speaker',
        'exploit': 'JBL Portable or JBL One app to configure. PartyBoost to link speakers.',
        'setup_url': 'JBL Portable / JBL One app',
        'vuln_level': 'medium'
    },

    # Bose Speakers
    'Bose': {
        'type': 'Wireless Speaker/Headphones',
        'icon': 'music',
        'brand': 'Bose',
        'desc': 'Bose WiFi speaker or headphones',
        'exploit': 'Bose Music or Bose Connect app. SoundTouch speakers have web interface.',
        'setup_url': 'Bose Music / Bose Connect app',
        'vuln_level': 'medium'
    },
    'SoundTouch': {
        'type': 'Wireless Speaker',
        'icon': 'music',
        'brand': 'Bose',
        'desc': 'Bose SoundTouch speaker system',
        'exploit': 'Web interface at device IP. Bose SoundTouch app. Can control playback.',
        'setup_url': 'Bose SoundTouch app or http://<device-ip>',
        'vuln_level': 'medium'
    },

    # Marshall Speakers
    'Marshall': {
        'type': 'Wireless Speaker',
        'icon': 'music',
        'brand': 'Marshall',
        'desc': 'Marshall Bluetooth/WiFi speaker',
        'exploit': 'Marshall Bluetooth app. Newer models have Chromecast/AirPlay.',
        'setup_url': 'Marshall Bluetooth app',
        'vuln_level': 'medium'
    },

    # Bang & Olufsen
    'Beoplay': {
        'type': 'Wireless Speaker/Headphones',
        'icon': 'music',
        'brand': 'Bang & Olufsen',
        'desc': 'B&O Beoplay speaker or headphones',
        'exploit': 'Bang & Olufsen app to configure.',
        'setup_url': 'Bang & Olufsen app',
        'vuln_level': 'medium'
    },

    # Ultimate Ears
    'UE-': {
        'type': 'Wireless Speaker',
        'icon': 'music',
        'brand': 'Ultimate Ears',
        'desc': 'UE Boom/Megaboom/Wonderboom speaker',
        'exploit': 'BOOM app. PartyUp feature to link speakers.',
        'setup_url': 'BOOM app (UE)',
        'vuln_level': 'low'
    },

    # Amazon Echo
    'Amazon-': {
        'type': 'Smart Speaker',
        'icon': 'microphone',
        'brand': 'Amazon',
        'desc': 'Amazon Echo device in setup mode',
        'exploit': 'Setup mode! Amazon Alexa app to claim. Has always-on mic.',
        'setup_url': 'Amazon Alexa app',
        'vuln_level': 'high'
    },
    'Echo-': {
        'type': 'Smart Speaker',
        'icon': 'microphone',
        'brand': 'Amazon',
        'desc': 'Amazon Echo in setup mode',
        'exploit': 'Unconfigured Echo! Alexa app to claim ownership.',
        'setup_url': 'Amazon Alexa app',
        'vuln_level': 'high'
    },

    # Denon/Marantz AV
    'Denon': {
        'type': 'AV Receiver',
        'icon': 'music',
        'brand': 'Denon',
        'desc': 'Denon AV receiver with HEOS',
        'exploit': 'Web interface at device IP. HEOS app. Can control volume, inputs, stream audio.',
        'setup_url': 'HEOS app or http://<device-ip>',
        'vuln_level': 'high'
    },
    'Marantz': {
        'type': 'AV Receiver',
        'icon': 'music',
        'brand': 'Marantz',
        'desc': 'Marantz AV receiver with HEOS',
        'exploit': 'Web interface at device IP. HEOS app for control.',
        'setup_url': 'HEOS app or http://<device-ip>',
        'vuln_level': 'high'
    },
    'HEOS': {
        'type': 'Wireless Speaker',
        'icon': 'music',
        'brand': 'Denon/Marantz',
        'desc': 'HEOS wireless speaker system',
        'exploit': 'HEOS app to configure and control. Web interface available.',
        'setup_url': 'HEOS app',
        'vuln_level': 'medium'
    },

    # Yamaha AV
    'Yamaha': {
        'type': 'AV Receiver/Speaker',
        'icon': 'music',
        'brand': 'Yamaha',
        'desc': 'Yamaha AV receiver or MusicCast speaker',
        'exploit': 'MusicCast app. Web interface at device IP for AV receivers.',
        'setup_url': 'Yamaha MusicCast app or http://<device-ip>',
        'vuln_level': 'high'
    },
    'MusicCast': {
        'type': 'Wireless Speaker',
        'icon': 'music',
        'brand': 'Yamaha',
        'desc': 'Yamaha MusicCast wireless audio',
        'exploit': 'MusicCast app to control. Multi-room audio system.',
        'setup_url': 'Yamaha MusicCast app',
        'vuln_level': 'medium'
    },

    # Pioneer/AV Receivers
    'Pioneer': {
        'type': 'AV Receiver',
        'icon': 'music',
        'brand': 'Pioneer',
        'desc': 'Pioneer AV receiver with WiFi streaming',
        'exploit': 'Often OPEN. Web interface at device IP. Can control volume, inputs, play audio.',
        'setup_url': 'Pioneer Remote App or http://<device-ip>',
        'vuln_level': 'high'
    },

    # Robot Vacuums
    'ECOVACS': {
        'type': 'Robot Vacuum',
        'icon': 'robot',
        'brand': 'Ecovacs',
        'desc': 'Ecovacs Deebot robot vacuum in setup mode',
        'exploit': 'Unconfigured! ECOVACS app can claim and control. Has camera/mic on some models.',
        'setup_url': 'ECOVACS HOME app',
        'vuln_level': 'critical'
    },
    'Roomba': {
        'type': 'Robot Vacuum',
        'icon': 'robot',
        'brand': 'iRobot',
        'desc': 'iRobot Roomba vacuum',
        'exploit': 'Setup mode = claim with iRobot app. Newer models have cameras.',
        'setup_url': 'iRobot Home app',
        'vuln_level': 'high'
    },
    'iRobot': {
        'type': 'Robot Vacuum',
        'icon': 'robot',
        'brand': 'iRobot',
        'desc': 'iRobot device (Roomba/Braava)',
        'exploit': 'Setup mode. iRobot app to claim.',
        'setup_url': 'iRobot Home app',
        'vuln_level': 'high'
    },

    # Hot Tubs/Spas
    'BWGSpa': {
        'type': 'Hot Tub/Spa Controller',
        'icon': 'tint',
        'brand': 'Balboa Water Group',
        'desc': 'Balboa hot tub WiFi module - controls spa',
        'exploit': 'OPEN network! Connect and access spa controls. Can adjust temp, jets, lights.',
        'setup_url': 'BWA app or http://192.168.0.1',
        'vuln_level': 'critical'
    },
    'Balboa': {
        'type': 'Hot Tub Controller',
        'icon': 'tint',
        'brand': 'Balboa',
        'desc': 'Balboa spa controller',
        'exploit': 'Connect to control hot tub settings remotely.',
        'setup_url': 'BWA app',
        'vuln_level': 'high'
    },

    # Scent Diffusers
    'AeraMini': {
        'type': 'Smart Scent Diffuser',
        'icon': 'leaf',
        'brand': 'Aera',
        'desc': 'Aera smart home fragrance diffuser in setup mode',
        'exploit': 'OPEN setup network. Aera app to claim and control scent schedules.',
        'setup_url': 'Aera Smart Home Fragrance app',
        'vuln_level': 'medium'
    },
    'AROMA': {
        'type': 'Scent Diffuser',
        'icon': 'leaf',
        'brand': 'Various',
        'desc': 'Commercial scent diffuser',
        'exploit': 'Usually OPEN. Web panel for scheduling.',
        'setup_url': 'Device web panel',
        'vuln_level': 'medium'
    },

    # Vehicle Tuners
    'EZLYNK': {
        'type': 'Vehicle Tuner',
        'icon': 'car',
        'brand': 'EZ LYNK',
        'desc': 'EZ LYNK diesel truck tuner - modifies engine parameters',
        'exploit': 'OPEN WiFi! Connect to access tune files, engine data, DTC codes.',
        'setup_url': 'EZ LYNK app',
        'vuln_level': 'critical'
    },

    # ESP/IoT Microcontrollers
    'ESP_': {
        'type': 'IoT Microcontroller',
        'icon': 'microchip',
        'brand': 'Espressif',
        'desc': 'ESP8266/ESP32 dev board or DIY IoT device',
        'exploit': 'DIY device in AP mode. Often has web config at 192.168.4.1 with no auth.',
        'setup_url': 'http://192.168.4.1',
        'vuln_level': 'high'
    },

    # ISP Routers in Setup Mode
    'SpectrumSetup': {
        'type': 'ISP Router (Setup)',
        'icon': 'wifi',
        'brand': 'Spectrum/Charter',
        'desc': 'Spectrum router in setup mode - not yet configured',
        'exploit': 'Factory reset or new install. Default creds on device sticker.',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'medium'
    },
    'ATTSetup': {
        'type': 'ISP Router (Setup)',
        'icon': 'wifi',
        'brand': 'AT&T',
        'desc': 'AT&T gateway in setup mode',
        'exploit': 'Setup mode. Check device sticker for default password.',
        'setup_url': 'http://192.168.1.254',
        'vuln_level': 'medium'
    },
    'xfinitywifi': {
        'type': 'ISP Hotspot',
        'icon': 'wifi',
        'brand': 'Xfinity/Comcast',
        'desc': 'Xfinity public hotspot from customer router',
        'exploit': 'Public network. Requires Xfinity login or can try default xfinity/xfinity.',
        'setup_url': 'Auto-redirects to login portal',
        'vuln_level': 'low'
    },

    # Video Doorbells (non-Ring)
    'ADC-VDB': {
        'type': 'Video Doorbell',
        'icon': 'bell',
        'brand': 'Alarm.com',
        'desc': 'Alarm.com video doorbell',
        'exploit': 'Setup mode. Can be claimed via Alarm.com app.',
        'setup_url': 'Alarm.com app',
        'vuln_level': 'high'
    },

    # Smart TVs
    'VIZIOTV': {
        'type': 'Smart TV',
        'icon': 'tv',
        'brand': 'Vizio',
        'desc': 'Vizio SmartCast TV',
        'exploit': 'API often open. Can control TV, see what\'s playing.',
        'setup_url': 'Vizio SmartCast app',
        'vuln_level': 'medium'
    },

    # Dashcams
    '70mai': {
        'type': 'Dashcam',
        'icon': 'video',
        'brand': '70mai',
        'desc': '70mai dashcam WiFi for video download',
        'exploit': 'Connect to download footage. Usually password on device sticker.',
        'setup_url': '70mai app',
        'vuln_level': 'medium'
    },

    # WEP Networks (super vulnerable)
    '[WEP]': {
        'type': 'WEP Encrypted',
        'icon': 'unlock-alt',
        'brand': 'Legacy',
        'desc': 'OBSOLETE WEP encryption - trivially crackable',
        'exploit': 'WEP crackable in minutes with aircrack-ng. Capture ~50k IVs then crack.',
        'setup_url': 'N/A - just crack it',
        'vuln_level': 'critical'
    },

    # Generic suffixes for unconfigured devices
    '.o_': {
        'type': 'Google/Nest Device',
        'icon': 'microphone',
        'brand': 'Google',
        'desc': 'Google device suffix - speaker/display in setup mode',
        'exploit': 'Setup mode. Google Home app to claim.',
        'setup_url': 'Google Home app',
        'vuln_level': 'high'
    },
    '_setup': {
        'type': 'Device (Setup Mode)',
        'icon': 'cog',
        'brand': 'Various',
        'desc': 'Device in setup/pairing mode - unconfigured',
        'exploit': 'Unconfigured! Find the matching app to claim ownership.',
        'setup_url': 'Check device brand for app',
        'vuln_level': 'high'
    },
    '_config': {
        'type': 'Device (Config Mode)',
        'icon': 'cog',
        'brand': 'Various',
        'desc': 'Device in configuration mode',
        'exploit': 'Config mode. Web panel usually at 192.168.4.1 or 192.168.0.1',
        'setup_url': 'http://192.168.4.1',
        'vuln_level': 'high'
    },

    # ========== ROUTERS & MODEMS ==========

    # Arris Cable Modems/Gateways
    'ARRIS-': {
        'type': 'Cable Modem/Router',
        'icon': 'wifi',
        'brand': 'Arris',
        'desc': 'Arris cable modem/gateway (Spectrum, Xfinity, Cox)',
        'exploit': 'Default admin panel at 192.168.0.1 or 192.168.100.1. Try admin/password or check sticker.',
        'setup_url': 'http://192.168.0.1',
        'vuln_level': 'low'
    },
    'APM': {
        'type': 'Cable Modem/Router',
        'icon': 'wifi',
        'brand': 'Arris',
        'desc': 'Arris APM series cable modem',
        'exploit': 'Admin panel at 192.168.0.1. Default creds on device sticker.',
        'setup_url': 'http://192.168.0.1',
        'vuln_level': 'low'
    },
    'TG1682': {
        'type': 'Cable Gateway',
        'icon': 'wifi',
        'brand': 'Arris',
        'desc': 'Arris Touchstone TG1682 gateway',
        'exploit': 'Admin at 10.0.0.1. Default: admin/password',
        'setup_url': 'http://10.0.0.1',
        'vuln_level': 'low'
    },
    'DG1670': {
        'type': 'Cable Gateway',
        'icon': 'wifi',
        'brand': 'Arris',
        'desc': 'Arris DG1670 DOCSIS gateway',
        'exploit': 'Admin at 192.168.0.1. Check sticker for password.',
        'setup_url': 'http://192.168.0.1',
        'vuln_level': 'low'
    },
    'SBG': {
        'type': 'Cable Modem/Router',
        'icon': 'wifi',
        'brand': 'Arris/Motorola',
        'desc': 'Arris SURFboard gateway',
        'exploit': 'Admin at 192.168.0.1. Default: admin/motorola or admin/password',
        'setup_url': 'http://192.168.0.1',
        'vuln_level': 'low'
    },
    'NVG': {
        'type': 'Fiber Gateway',
        'icon': 'wifi',
        'brand': 'Arris/AT&T',
        'desc': 'AT&T Fiber NVG gateway',
        'exploit': 'Admin at 192.168.1.254. Device access code on sticker.',
        'setup_url': 'http://192.168.1.254',
        'vuln_level': 'low'
    },
    'BGW': {
        'type': 'Fiber Gateway',
        'icon': 'wifi',
        'brand': 'Arris/AT&T',
        'desc': 'AT&T BGW fiber gateway',
        'exploit': 'Admin at 192.168.1.254. Access code on sticker.',
        'setup_url': 'http://192.168.1.254',
        'vuln_level': 'low'
    },

    # AT&T
    'ATT': {
        'type': 'ISP Router/Gateway',
        'icon': 'wifi',
        'brand': 'AT&T',
        'desc': 'AT&T residential gateway',
        'exploit': 'Admin at 192.168.1.254. Access code printed on device.',
        'setup_url': 'http://192.168.1.254',
        'vuln_level': 'low'
    },
    'ATT-WIFI': {
        'type': 'ISP Router',
        'icon': 'wifi',
        'brand': 'AT&T',
        'desc': 'AT&T WiFi gateway',
        'exploit': 'Admin at 192.168.1.254. WPA key on sticker.',
        'setup_url': 'http://192.168.1.254',
        'vuln_level': 'low'
    },
    'ATT-HOMEBASE': {
        'type': 'LTE Home Router',
        'icon': 'wifi',
        'brand': 'AT&T',
        'desc': 'AT&T Wireless Home Base (LTE router)',
        'exploit': 'Admin at 192.168.1.1. Great for location - LTE = address registered.',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },

    # Spectrum/Charter
    'Spectrum': {
        'type': 'ISP Router',
        'icon': 'wifi',
        'brand': 'Spectrum/Charter',
        'desc': 'Spectrum cable router/gateway',
        'exploit': 'Admin at 192.168.1.1. Password on device sticker.',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },
    'MySpectrum': {
        'type': 'ISP Router',
        'icon': 'wifi',
        'brand': 'Spectrum/Charter',
        'desc': 'Spectrum WiFi network',
        'exploit': 'Admin at 192.168.1.1',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },

    # Xfinity/Comcast
    'XFINITY': {
        'type': 'ISP Router',
        'icon': 'wifi',
        'brand': 'Xfinity/Comcast',
        'desc': 'Xfinity gateway',
        'exploit': 'Admin at 10.0.0.1. Default: admin/password',
        'setup_url': 'http://10.0.0.1',
        'vuln_level': 'low'
    },

    # NETGEAR
    'NETGEAR': {
        'type': 'Consumer Router',
        'icon': 'wifi',
        'brand': 'NETGEAR',
        'desc': 'NETGEAR wireless router',
        'exploit': 'Admin at 192.168.1.1 or routerlogin.net. Default: admin/password',
        'setup_url': 'http://routerlogin.net',
        'vuln_level': 'low'
    },
    'ORBI': {
        'type': 'Mesh Router',
        'icon': 'wifi',
        'brand': 'NETGEAR',
        'desc': 'NETGEAR Orbi mesh WiFi system',
        'exploit': 'Admin at orbilogin.net. Default: admin/password',
        'setup_url': 'http://orbilogin.net',
        'vuln_level': 'low'
    },

    # ASUS
    'ASUS': {
        'type': 'Consumer Router',
        'icon': 'wifi',
        'brand': 'ASUS',
        'desc': 'ASUS wireless router',
        'exploit': 'Admin at router.asus.com or 192.168.1.1. Default: admin/admin',
        'setup_url': 'http://router.asus.com',
        'vuln_level': 'low'
    },
    'RT-': {
        'type': 'Consumer Router',
        'icon': 'wifi',
        'brand': 'ASUS',
        'desc': 'ASUS RT-series router',
        'exploit': 'Admin at 192.168.1.1. Default: admin/admin',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },

    # TP-Link
    'TP-Link': {
        'type': 'Consumer Router',
        'icon': 'wifi',
        'brand': 'TP-Link',
        'desc': 'TP-Link wireless router',
        'exploit': 'Admin at 192.168.0.1 or tplinkwifi.net. Default: admin/admin',
        'setup_url': 'http://tplinkwifi.net',
        'vuln_level': 'low'
    },
    'Archer': {
        'type': 'Consumer Router',
        'icon': 'wifi',
        'brand': 'TP-Link',
        'desc': 'TP-Link Archer series router',
        'exploit': 'Admin at tplinkwifi.net. Default: admin/admin',
        'setup_url': 'http://tplinkwifi.net',
        'vuln_level': 'low'
    },
    'Deco': {
        'type': 'Mesh Router',
        'icon': 'wifi',
        'brand': 'TP-Link',
        'desc': 'TP-Link Deco mesh WiFi system',
        'exploit': 'Managed via Deco app. Admin at 192.168.0.1',
        'setup_url': 'Deco app',
        'vuln_level': 'low'
    },

    # Linksys
    'Linksys': {
        'type': 'Consumer Router',
        'icon': 'wifi',
        'brand': 'Linksys',
        'desc': 'Linksys wireless router',
        'exploit': 'Admin at 192.168.1.1 or linksyssmartwifi.com. Default: admin/admin',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },

    # eero
    'eero': {
        'type': 'Mesh Router',
        'icon': 'wifi',
        'brand': 'Amazon/eero',
        'desc': 'eero mesh WiFi system',
        'exploit': 'Managed only via eero app. No web admin.',
        'setup_url': 'eero app',
        'vuln_level': 'low'
    },

    # Google/Nest WiFi
    'GoogleWifi': {
        'type': 'Mesh Router',
        'icon': 'wifi',
        'brand': 'Google',
        'desc': 'Google WiFi mesh system',
        'exploit': 'Managed via Google Home app. No web admin.',
        'setup_url': 'Google Home app',
        'vuln_level': 'low'
    },

    # Ubiquiti
    'UniFi': {
        'type': 'Enterprise AP',
        'icon': 'wifi',
        'brand': 'Ubiquiti',
        'desc': 'Ubiquiti UniFi access point',
        'exploit': 'Managed via UniFi controller. Enterprise grade.',
        'setup_url': 'UniFi Controller',
        'vuln_level': 'low'
    },
    'Ubiquiti': {
        'type': 'Enterprise AP',
        'icon': 'wifi',
        'brand': 'Ubiquiti',
        'desc': 'Ubiquiti wireless access point',
        'exploit': 'Enterprise equipment. Managed centrally.',
        'setup_url': 'UniFi/UISP Controller',
        'vuln_level': 'low'
    },

    # ========== VEHICLES ==========

    'Audi_MMI': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Audi',
        'desc': 'Audi MMI Connect in-car WiFi hotspot',
        'exploit': 'Vehicle hotspot. Password in vehicle settings.',
        'setup_url': 'Audi MMI system',
        'vuln_level': 'low'
    },
    'BMW': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'BMW',
        'desc': 'BMW ConnectedDrive WiFi hotspot',
        'exploit': 'Vehicle hotspot. Check iDrive for password.',
        'setup_url': 'BMW iDrive',
        'vuln_level': 'low'
    },
    'GMC': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'GMC',
        'desc': 'GMC vehicle WiFi hotspot (OnStar)',
        'exploit': 'OnStar WiFi. Password in vehicle settings or myGMC app.',
        'setup_url': 'myGMC app',
        'vuln_level': 'low'
    },
    'Chevy': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Chevrolet',
        'desc': 'Chevrolet vehicle WiFi hotspot (OnStar)',
        'exploit': 'OnStar WiFi. Password in vehicle settings.',
        'setup_url': 'myChevrolet app',
        'vuln_level': 'low'
    },
    'Silverado': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Chevrolet',
        'desc': 'Chevy Silverado truck WiFi',
        'exploit': 'OnStar hotspot.',
        'setup_url': 'myChevrolet app',
        'vuln_level': 'low'
    },
    'Tahoe': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Chevrolet',
        'desc': 'Chevy Tahoe SUV WiFi',
        'exploit': 'OnStar hotspot.',
        'setup_url': 'myChevrolet app',
        'vuln_level': 'low'
    },
    'Escalade': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Cadillac',
        'desc': 'Cadillac Escalade WiFi hotspot',
        'exploit': 'OnStar WiFi.',
        'setup_url': 'myCadillac app',
        'vuln_level': 'low'
    },
    'MyLink': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Chevrolet',
        'desc': 'Chevrolet MyLink infotainment WiFi',
        'exploit': 'OnStar hotspot.',
        'setup_url': 'myChevrolet app',
        'vuln_level': 'low'
    },
    'OnStar': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'GM',
        'desc': 'General Motors OnStar WiFi hotspot',
        'exploit': 'GM vehicle WiFi. Password in vehicle.',
        'setup_url': 'OnStar app',
        'vuln_level': 'low'
    },
    'Ford': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Ford',
        'desc': 'Ford vehicle WiFi hotspot',
        'exploit': 'FordPass WiFi hotspot.',
        'setup_url': 'FordPass app',
        'vuln_level': 'low'
    },
    'SYNC': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Ford',
        'desc': 'Ford SYNC infotainment WiFi',
        'exploit': 'Ford vehicle WiFi.',
        'setup_url': 'FordPass app',
        'vuln_level': 'low'
    },
    'Jeep': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Jeep',
        'desc': 'Jeep Uconnect WiFi hotspot',
        'exploit': 'Uconnect WiFi.',
        'setup_url': 'Uconnect app',
        'vuln_level': 'low'
    },
    'Uconnect': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Stellantis',
        'desc': 'Chrysler/Dodge/Jeep/Ram Uconnect WiFi',
        'exploit': 'Vehicle WiFi hotspot.',
        'setup_url': 'Uconnect app',
        'vuln_level': 'low'
    },
    'Toyota': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Toyota',
        'desc': 'Toyota vehicle WiFi hotspot',
        'exploit': 'Toyota Connected Services WiFi.',
        'setup_url': 'Toyota app',
        'vuln_level': 'low'
    },
    'Honda': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Honda',
        'desc': 'Honda vehicle WiFi hotspot',
        'exploit': 'HondaLink WiFi.',
        'setup_url': 'HondaLink app',
        'vuln_level': 'low'
    },
    'Tesla': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Tesla',
        'desc': 'Tesla vehicle WiFi (rare - usually uses cellular)',
        'exploit': 'Tesla hotspot mode.',
        'setup_url': 'Tesla app',
        'vuln_level': 'low'
    },
    'CHEVROLET': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Chevrolet',
        'desc': 'Chevrolet OnStar WiFi hotspot',
        'exploit': 'OnStar hotspot. Password in vehicle settings.',
        'setup_url': 'myChevrolet app',
        'vuln_level': 'low'
    },
    'BUICK': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Buick',
        'desc': 'Buick OnStar WiFi hotspot',
        'exploit': 'OnStar WiFi.',
        'setup_url': 'myBuick app',
        'vuln_level': 'low'
    },
    'Cadillac': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Cadillac',
        'desc': 'Cadillac OnStar WiFi hotspot',
        'exploit': 'OnStar WiFi.',
        'setup_url': 'myCadillac app',
        'vuln_level': 'low'
    },
    'My VW': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Volkswagen',
        'desc': 'Volkswagen Car-Net WiFi hotspot',
        'exploit': 'VW Car-Net hotspot.',
        'setup_url': 'VW Car-Net app',
        'vuln_level': 'low'
    },
    'Mazda_': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Mazda',
        'desc': 'Mazda Connect WiFi',
        'exploit': 'Vehicle WiFi hotspot.',
        'setup_url': 'MyMazda app',
        'vuln_level': 'low'
    },
    'Cayenne_': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Porsche',
        'desc': 'Porsche Cayenne WiFi hotspot',
        'exploit': 'Porsche Connect WiFi.',
        'setup_url': 'Porsche Connect app',
        'vuln_level': 'low'
    },
    'MBUX': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Mercedes-Benz',
        'desc': 'Mercedes-Benz MBUX infotainment WiFi',
        'exploit': 'Mercedes me connect WiFi.',
        'setup_url': 'Mercedes me app',
        'vuln_level': 'low'
    },
    'MB Hotspot': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Mercedes-Benz',
        'desc': 'Mercedes-Benz WiFi hotspot',
        'exploit': 'Mercedes vehicle WiFi.',
        'setup_url': 'Mercedes me app',
        'vuln_level': 'low'
    },
    'MB WLAN': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Mercedes-Benz',
        'desc': 'Mercedes-Benz WLAN hotspot',
        'exploit': 'Mercedes vehicle WiFi.',
        'setup_url': 'Mercedes me app',
        'vuln_level': 'low'
    },
    'CarPlay_': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Apple CarPlay',
        'desc': 'Apple CarPlay wireless connection',
        'exploit': 'CarPlay pairing network.',
        'setup_url': 'Vehicle infotainment',
        'vuln_level': 'low'
    },
    'Lexus': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Lexus',
        'desc': 'Lexus Enform WiFi hotspot',
        'exploit': 'Lexus Enform WiFi.',
        'setup_url': 'Lexus app',
        'vuln_level': 'low'
    },
    'Acadia': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'GMC',
        'desc': 'GMC Acadia OnStar WiFi',
        'exploit': 'OnStar hotspot.',
        'setup_url': 'myGMC app',
        'vuln_level': 'low'
    },

    # ========== MORE ISP ROUTERS ==========

    'CVCTX_': {
        'type': 'Fiber/DSL Gateway',
        'icon': 'wifi',
        'brand': 'Calix',
        'desc': 'Calix residential gateway (fiber/DSL ISP equipment)',
        'exploit': 'ISP-provided router. Admin usually at 192.168.1.1',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },
    'ExpressNet': {
        'type': 'ISP Router',
        'icon': 'wifi',
        'brand': 'Various ISP',
        'desc': 'ISP-provided residential router',
        'exploit': 'ISP router. Admin at 192.168.1.1 or 192.168.0.1',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },
    'CODA-': {
        'type': 'Cable Modem',
        'icon': 'wifi',
        'brand': 'Hitron',
        'desc': 'Hitron CODA cable modem/gateway',
        'exploit': 'Admin at 192.168.0.1. Default: cusadmin/password',
        'setup_url': 'http://192.168.0.1',
        'vuln_level': 'low'
    },
    'CGNM-': {
        'type': 'Cable Modem',
        'icon': 'wifi',
        'brand': 'Compal/Xfinity',
        'desc': 'Compal cable modem (Xfinity)',
        'exploit': 'Admin at 10.0.0.1. Default: admin/password',
        'setup_url': 'http://10.0.0.1',
        'vuln_level': 'low'
    },
    'Frontier': {
        'type': 'ISP Router',
        'icon': 'wifi',
        'brand': 'Frontier',
        'desc': 'Frontier Communications ISP router',
        'exploit': 'Admin at 192.168.1.1. Password on sticker.',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },
    'EarthLink': {
        'type': 'ISP Router',
        'icon': 'wifi',
        'brand': 'EarthLink',
        'desc': 'EarthLink ISP router',
        'exploit': 'Admin at 192.168.1.1',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },

    # ========== MOBILE HOTSPOTS ==========

    'Hotspot': {
        'type': 'Mobile Hotspot',
        'icon': 'mobile',
        'brand': 'Various',
        'desc': 'Mobile hotspot device or phone tethering',
        'exploit': 'Mobile hotspot. Likely a phone or MiFi device.',
        'setup_url': 'Device settings',
        'vuln_level': 'low'
    },
    'Galaxy': {
        'type': 'Phone Hotspot',
        'icon': 'mobile',
        'brand': 'Samsung',
        'desc': 'Samsung Galaxy phone WiFi hotspot',
        'exploit': 'Phone tethering. Password set by owner.',
        'setup_url': 'Phone settings',
        'vuln_level': 'low'
    },
    'Moto': {
        'type': 'Phone Hotspot',
        'icon': 'mobile',
        'brand': 'Motorola',
        'desc': 'Motorola phone WiFi hotspot',
        'exploit': 'Phone tethering.',
        'setup_url': 'Phone settings',
        'vuln_level': 'low'
    },
    'Alcatel_linkzone': {
        'type': 'Mobile Hotspot',
        'icon': 'mobile',
        'brand': 'Alcatel',
        'desc': 'Alcatel Linkzone mobile hotspot',
        'exploit': 'MiFi device. Admin at 192.168.1.1',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },
    'Franklin': {
        'type': 'Mobile Hotspot',
        'icon': 'mobile',
        'brand': 'Franklin Wireless',
        'desc': 'Franklin mobile hotspot (T-Mobile/Sprint)',
        'exploit': 'MiFi device.',
        'setup_url': 'http://192.168.1.1',
        'vuln_level': 'low'
    },
    'Moxee': {
        'type': 'Mobile Hotspot',
        'icon': 'mobile',
        'brand': 'Moxee',
        'desc': 'Moxee mobile hotspot',
        'exploit': 'MiFi device.',
        'setup_url': 'Device settings',
        'vuln_level': 'low'
    },

    # ========== DASHCAMS ==========

    'Blackvue': {
        'type': 'Dashcam',
        'icon': 'video',
        'brand': 'BlackVue',
        'desc': 'BlackVue dashcam WiFi',
        'exploit': 'Connect to view/download footage. BlackVue app.',
        'setup_url': 'BlackVue app',
        'vuln_level': 'medium'
    },
    '70mai': {
        'type': 'Dashcam',
        'icon': 'video',
        'brand': '70mai',
        'desc': '70mai dashcam WiFi',
        'exploit': 'Connect to view/download footage. 70mai app.',
        'setup_url': '70mai app',
        'vuln_level': 'medium'
    },
    'Dash-': {
        'type': 'Dashcam',
        'icon': 'video',
        'brand': 'Various',
        'desc': 'Vehicle dashcam WiFi',
        'exploit': 'Connect to view/download footage.',
        'setup_url': 'Dashcam app',
        'vuln_level': 'medium'
    },
    'Driveri': {
        'type': 'Fleet Camera',
        'icon': 'video',
        'brand': 'Driveri/Netradyne',
        'desc': 'Driveri fleet tracking camera',
        'exploit': 'Commercial fleet camera system.',
        'setup_url': 'Fleet management portal',
        'vuln_level': 'low'
    },

    # ========== FLEET/TRUCKING ==========

    'Motive': {
        'type': 'Fleet ELD',
        'icon': 'truck',
        'brand': 'Motive (KeepTruckin)',
        'desc': 'Motive ELD fleet tracking device',
        'exploit': 'Electronic logging device for trucks.',
        'setup_url': 'Motive fleet portal',
        'vuln_level': 'low'
    },
    'KeepTruckin': {
        'type': 'Fleet ELD',
        'icon': 'truck',
        'brand': 'KeepTruckin/Motive',
        'desc': 'KeepTruckin ELD fleet tracking device',
        'exploit': 'Electronic logging device for trucks.',
        'setup_url': 'KeepTruckin portal',
        'vuln_level': 'low'
    },

    # ========== RV/CAMPING ==========

    'Winegard': {
        'type': 'RV WiFi',
        'icon': 'wifi',
        'brand': 'Winegard',
        'desc': 'Winegard RV WiFi antenna/booster',
        'exploit': 'RV WiFi extender. Admin at 192.168.0.1',
        'setup_url': 'http://192.168.0.1',
        'vuln_level': 'low'
    },
    'MyRV_': {
        'type': 'RV WiFi',
        'icon': 'wifi',
        'brand': 'Various',
        'desc': 'RV built-in WiFi system',
        'exploit': 'RV WiFi hotspot.',
        'setup_url': 'RV settings',
        'vuln_level': 'low'
    },
    'KING_': {
        'type': 'RV Satellite/WiFi',
        'icon': 'wifi',
        'brand': 'King',
        'desc': 'King RV satellite or WiFi system',
        'exploit': 'RV entertainment/WiFi system.',
        'setup_url': 'King Connect app',
        'vuln_level': 'low'
    },
    'ColoradoLandingRV': {
        'type': 'RV Park WiFi',
        'icon': 'wifi',
        'brand': 'RV Park',
        'desc': 'RV park guest WiFi',
        'exploit': 'Public RV park WiFi.',
        'setup_url': 'N/A',
        'vuln_level': 'low'
    },

    # ========== SECURITY SYSTEMS ==========

    'Alula': {
        'type': 'Security System',
        'icon': 'shield',
        'brand': 'Alula',
        'desc': 'Alula security/alarm panel',
        'exploit': 'Security system WiFi. Managed by alarm company.',
        'setup_url': 'Alula app',
        'vuln_level': 'low'
    },
    'ADC-': {
        'type': 'Security Camera',
        'icon': 'video',
        'brand': 'Alarm.com',
        'desc': 'Alarm.com video doorbell or camera',
        'exploit': 'Security camera in setup mode.',
        'setup_url': 'Alarm.com app',
        'vuln_level': 'medium'
    },

    # ========== SMART HOME ==========

    'ECOVACS': {
        'type': 'Robot Vacuum',
        'icon': 'home',
        'brand': 'Ecovacs',
        'desc': 'Ecovacs robot vacuum',
        'exploit': 'Robot vacuum WiFi setup.',
        'setup_url': 'Ecovacs Home app',
        'vuln_level': 'medium'
    },
    'AeraMini': {
        'type': 'Smart Diffuser',
        'icon': 'home',
        'brand': 'Aera',
        'desc': 'Aera smart fragrance diffuser',
        'exploit': 'Smart home device.',
        'setup_url': 'Aera app',
        'vuln_level': 'medium'
    },
    'JellyFish': {
        'type': 'Smart Lights',
        'icon': 'lightbulb',
        'brand': 'JellyFish',
        'desc': 'JellyFish permanent outdoor lights',
        'exploit': 'Smart lighting system.',
        'setup_url': 'JellyFish app',
        'vuln_level': 'medium'
    },

    # ========== BUSINESS/POS ==========

    'AlohaPOS': {
        'type': 'POS System',
        'icon': 'credit-card',
        'brand': 'NCR Aloha',
        'desc': 'NCR Aloha point-of-sale system',
        'exploit': 'Restaurant POS system.',
        'setup_url': 'NCR management',
        'vuln_level': 'low'
    },
    'CricketPOS': {
        'type': 'POS System',
        'icon': 'credit-card',
        'brand': 'Cricket',
        'desc': 'Cricket Wireless store POS',
        'exploit': 'Retail POS.',
        'setup_url': 'Store management',
        'vuln_level': 'low'
    },

    # ========== MISC DEVICES ==========

    'AVerM15W': {
        'type': 'Document Camera',
        'icon': 'camera',
        'brand': 'AVer',
        'desc': 'AVer document camera/visualizer',
        'exploit': 'Classroom/office document camera.',
        'setup_url': 'AVer software',
        'vuln_level': 'low'
    },
    'ClickShare': {
        'type': 'Presentation System',
        'icon': 'tv',
        'brand': 'Barco',
        'desc': 'Barco ClickShare wireless presentation',
        'exploit': 'Conference room presentation system.',
        'setup_url': 'ClickShare app',
        'vuln_level': 'low'
    },
    'EnGenius': {
        'type': 'Business AP',
        'icon': 'wifi',
        'brand': 'EnGenius',
        'desc': 'EnGenius wireless access point',
        'exploit': 'SMB wireless AP.',
        'setup_url': 'EnGenius Cloud',
        'vuln_level': 'low'
    },
    'JBL Bar': {
        'type': 'Soundbar',
        'icon': 'music',
        'brand': 'JBL',
        'desc': 'JBL soundbar WiFi',
        'exploit': 'Smart soundbar.',
        'setup_url': 'JBL One app',
        'vuln_level': 'low'
    },
    # === T-Mobile Home Internet ===
    'TMOBILE-': {
        'type': 'Home Internet Gateway',
        'icon': 'wifi',
        'brand': 'T-Mobile',
        'desc': 'T-Mobile 5G Home Internet Gateway',
        'exploit': 'T-Mobile 5G/LTE home internet. Default login often admin/admin.',
        'setup_url': '192.168.12.1',
        'vuln_level': 'medium'
    },
    'TMOBILE_': {
        'type': 'Home Internet Gateway',
        'icon': 'wifi',
        'brand': 'T-Mobile',
        'desc': 'T-Mobile 5G Home Internet Gateway',
        'exploit': 'T-Mobile 5G/LTE home internet.',
        'setup_url': '192.168.12.1',
        'vuln_level': 'medium'
    },
    'TMobile': {
        'type': 'Home Internet Gateway',
        'icon': 'wifi',
        'brand': 'T-Mobile',
        'desc': 'T-Mobile Home Internet',
        'exploit': 'T-Mobile home internet gateway.',
        'setup_url': '192.168.12.1',
        'vuln_level': 'medium'
    },
    'tmobile': {
        'type': 'Home Internet Gateway',
        'icon': 'wifi',
        'brand': 'T-Mobile',
        'desc': 'T-Mobile Home Internet',
        'exploit': 'T-Mobile home internet gateway.',
        'setup_url': '192.168.12.1',
        'vuln_level': 'medium'
    },
    # === Verizon ===
    'Verizon-': {
        'type': 'Router/Hotspot',
        'icon': 'wifi',
        'brand': 'Verizon',
        'desc': 'Verizon router or MiFi hotspot',
        'exploit': 'Verizon MiFi or phone hotspot.',
        'setup_url': 'my.verizon.com',
        'vuln_level': 'medium'
    },
    'Verizon_': {
        'type': 'FiOS Router',
        'icon': 'wifi',
        'brand': 'Verizon',
        'desc': 'Verizon FiOS router',
        'exploit': 'Verizon FiOS gateway. Default login on sticker.',
        'setup_url': '192.168.1.1',
        'vuln_level': 'medium'
    },
    # === Other ISPs ===
    'suddenlink': {
        'type': 'Cable Router',
        'icon': 'wifi',
        'brand': 'Suddenlink/Optimum',
        'desc': 'Suddenlink (now Optimum) cable router',
        'exploit': 'Altice/Optimum provided router.',
        'setup_url': '192.168.0.1',
        'vuln_level': 'medium'
    },
    'Sparklight': {
        'type': 'Cable Router',
        'icon': 'wifi',
        'brand': 'Sparklight',
        'desc': 'Sparklight (Cable One) provided router',
        'exploit': 'ISP-provided cable router.',
        'setup_url': '192.168.0.1',
        'vuln_level': 'medium'
    },
    'Viasat': {
        'type': 'Satellite Router',
        'icon': 'satellite',
        'brand': 'Viasat',
        'desc': 'Viasat satellite internet router',
        'exploit': 'Satellite internet - high latency.',
        'setup_url': '192.168.100.1',
        'vuln_level': 'medium'
    },
    'STARLINK': {
        'type': 'Satellite Router',
        'icon': 'satellite',
        'brand': 'SpaceX',
        'desc': 'SpaceX Starlink satellite internet',
        'exploit': 'Starlink LEO satellite internet. Modern security.',
        'setup_url': '192.168.1.1 or app',
        'vuln_level': 'low'
    },
    'Starlink': {
        'type': 'Satellite Router',
        'icon': 'satellite',
        'brand': 'SpaceX',
        'desc': 'SpaceX Starlink satellite internet',
        'exploit': 'Starlink LEO satellite internet.',
        'setup_url': '192.168.1.1 or app',
        'vuln_level': 'low'
    },
    'starlink': {
        'type': 'Satellite Router',
        'icon': 'satellite',
        'brand': 'SpaceX',
        'desc': 'SpaceX Starlink satellite internet',
        'exploit': 'Starlink LEO satellite internet.',
        'setup_url': '192.168.1.1 or app',
        'vuln_level': 'low'
    },
    # === More Routers ===
    'belkin.': {
        'type': 'Router',
        'icon': 'wifi',
        'brand': 'Belkin',
        'desc': 'Belkin consumer router',
        'exploit': 'Consumer router. Check for outdated firmware.',
        'setup_url': '192.168.2.1',
        'vuln_level': 'medium'
    },
    'dlink': {
        'type': 'Router',
        'icon': 'wifi',
        'brand': 'D-Link',
        'desc': 'D-Link router',
        'exploit': 'D-Link routers have history of vulnerabilities.',
        'setup_url': '192.168.0.1',
        'vuln_level': 'high'
    },
    'WAVLINK': {
        'type': 'Router/Extender',
        'icon': 'wifi',
        'brand': 'Wavlink',
        'desc': 'Wavlink router or WiFi extender',
        'exploit': 'Budget router brand. Often has vulnerabilities.',
        'setup_url': '192.168.10.1',
        'vuln_level': 'high'
    },
    'GL-SFT': {
        'type': 'Travel Router',
        'icon': 'wifi',
        'brand': 'GL.iNet',
        'desc': 'GL.iNet travel router',
        'exploit': 'OpenWRT-based travel router. Security-focused.',
        'setup_url': '192.168.8.1',
        'vuln_level': 'low'
    },
    'GL-': {
        'type': 'Travel Router',
        'icon': 'wifi',
        'brand': 'GL.iNet',
        'desc': 'GL.iNet router',
        'exploit': 'OpenWRT-based router.',
        'setup_url': '192.168.8.1',
        'vuln_level': 'low'
    },
    'FX4100': {
        'type': 'Router',
        'icon': 'wifi',
        'brand': 'ZTE/Various',
        'desc': 'ZTE or similar ISP router',
        'exploit': 'ISP-provided router.',
        'setup_url': '192.168.1.1',
        'vuln_level': 'medium'
    },
    'ngHub': {
        'type': 'Gateway',
        'icon': 'wifi',
        'brand': 'AT&T',
        'desc': 'AT&T NextGen Hub gateway',
        'exploit': 'AT&T fiber gateway. Similar to BGW series.',
        'setup_url': '192.168.1.254',
        'vuln_level': 'medium'
    },
    'TC8717': {
        'type': 'Cable Modem/Router',
        'icon': 'wifi',
        'brand': 'Technicolor',
        'desc': 'Technicolor cable modem router',
        'exploit': 'ISP-provided Technicolor gateway.',
        'setup_url': '192.168.0.1',
        'vuln_level': 'medium'
    },
    # === NVR/Security Cameras ===
    'NVR': {
        'type': 'Network Video Recorder',
        'icon': 'video',
        'brand': 'Various',
        'desc': 'NVR security camera system',
        'exploit': 'IP camera NVR. Often has default passwords. Check for RTSP streams.',
        'setup_url': 'Check device label',
        'vuln_level': 'high'
    },
    'WIFIBRG': {
        'type': 'WiFi Camera Bridge',
        'icon': 'video',
        'brand': 'Various',
        'desc': 'WiFi bridge for IP cameras',
        'exploit': 'WiFi camera bridge. May expose RTSP streams.',
        'setup_url': 'Check device',
        'vuln_level': 'high'
    },
    'WIFINVR': {
        'type': 'WiFi NVR',
        'icon': 'video',
        'brand': 'Various',
        'desc': 'WiFi NVR camera system',
        'exploit': 'Wireless NVR. Check for default credentials.',
        'setup_url': 'Check device',
        'vuln_level': 'high'
    },
    'SS-CCTV': {
        'type': 'CCTV System',
        'icon': 'video',
        'brand': 'Various',
        'desc': 'CCTV security system',
        'exploit': 'Security camera system.',
        'setup_url': 'Check device',
        'vuln_level': 'medium'
    },
    # === Smart Home ===
    'SmartLife': {
        'type': 'Smart Home Device',
        'icon': 'lightbulb',
        'brand': 'Tuya',
        'desc': 'Tuya Smart Life device',
        'exploit': 'Tuya-based smart device. Common IoT platform.',
        'setup_url': 'Smart Life app',
        'vuln_level': 'medium'
    },
    'WeMo': {
        'type': 'Smart Switch',
        'icon': 'lightbulb',
        'brand': 'Belkin',
        'desc': 'Belkin WeMo smart switch/plug',
        'exploit': 'Smart home switch. Check for outdated firmware.',
        'setup_url': 'Wemo app',
        'vuln_level': 'medium'
    },
    'NewThermostat': {
        'type': 'Smart Thermostat',
        'icon': 'home',
        'brand': 'Various',
        'desc': 'Smart thermostat in setup mode',
        'exploit': 'WiFi thermostat setup AP.',
        'setup_url': 'Manufacturer app',
        'vuln_level': 'low'
    },
    'Thermostat': {
        'type': 'Smart Thermostat',
        'icon': 'home',
        'brand': 'Various',
        'desc': 'Smart thermostat',
        'exploit': 'WiFi-enabled thermostat.',
        'setup_url': 'Check device',
        'vuln_level': 'low'
    },
    'iAqualink': {
        'type': 'Pool Controller',
        'icon': 'swimming-pool',
        'brand': 'Jandy',
        'desc': 'Jandy iAqualink pool/spa controller',
        'exploit': 'Pool automation controller.',
        'setup_url': 'iAqualink app',
        'vuln_level': 'low'
    },
    'RAINBIRD': {
        'type': 'Irrigation Controller',
        'icon': 'tint',
        'brand': 'Rain Bird',
        'desc': 'Rain Bird smart irrigation controller',
        'exploit': 'Sprinkler/irrigation system.',
        'setup_url': 'Rain Bird app',
        'vuln_level': 'low'
    },
    'Traeger': {
        'type': 'Smart Grill',
        'icon': 'fire',
        'brand': 'Traeger',
        'desc': 'Traeger WiFi-enabled pellet grill',
        'exploit': 'Smart grill for remote monitoring.',
        'setup_url': 'Traeger app',
        'vuln_level': 'low'
    },
    'Tineco': {
        'type': 'Smart Vacuum',
        'icon': 'vacuum',
        'brand': 'Tineco',
        'desc': 'Tineco vacuum or floor washer',
        'exploit': 'Smart cleaning device.',
        'setup_url': 'Tineco app',
        'vuln_level': 'low'
    },
    'iFLO': {
        'type': 'Smart Irrigation',
        'icon': 'tint',
        'brand': 'iFLO',
        'desc': 'iFLO smart irrigation device',
        'exploit': 'Smart watering system.',
        'setup_url': 'iFLO app',
        'vuln_level': 'low'
    },
    # === Smart Appliances - LG ===
    '[LG_': {
        'type': 'Smart Appliance',
        'icon': 'home',
        'brand': 'LG',
        'desc': 'LG ThinQ smart appliance (washer, dryer, AC, oven)',
        'exploit': 'LG smart home appliance. ThinQ app control.',
        'setup_url': 'LG ThinQ app',
        'vuln_level': 'low'
    },
    # === Smart Appliances - Samsung ===
    'Samsung Dryer': {
        'type': 'Smart Dryer',
        'icon': 'home',
        'brand': 'Samsung',
        'desc': 'Samsung smart dryer',
        'exploit': 'Samsung SmartThings appliance.',
        'setup_url': 'SmartThings app',
        'vuln_level': 'low'
    },
    'Samsung Fridge': {
        'type': 'Smart Fridge',
        'icon': 'snowflake',
        'brand': 'Samsung',
        'desc': 'Samsung smart refrigerator',
        'exploit': 'Samsung Family Hub fridge.',
        'setup_url': 'SmartThings app',
        'vuln_level': 'low'
    },
    '[cooktop]': {
        'type': 'Smart Cooktop',
        'icon': 'fire',
        'brand': 'Samsung',
        'desc': 'Samsung smart cooktop',
        'exploit': 'Samsung smart cooking appliance.',
        'setup_url': 'SmartThings app',
        'vuln_level': 'low'
    },
    '[fridge]': {
        'type': 'Smart Fridge',
        'icon': 'snowflake',
        'brand': 'Samsung',
        'desc': 'Samsung smart refrigerator',
        'exploit': 'Samsung smart fridge.',
        'setup_url': 'SmartThings app',
        'vuln_level': 'low'
    },
    '[oven]': {
        'type': 'Smart Oven',
        'icon': 'fire',
        'brand': 'Samsung',
        'desc': 'Samsung smart oven',
        'exploit': 'Samsung smart cooking appliance.',
        'setup_url': 'SmartThings app',
        'vuln_level': 'low'
    },
    '[range]': {
        'type': 'Smart Range',
        'icon': 'fire',
        'brand': 'Samsung',
        'desc': 'Samsung smart range/stove',
        'exploit': 'Samsung smart cooking appliance.',
        'setup_url': 'SmartThings app',
        'vuln_level': 'low'
    },
    '[washer]': {
        'type': 'Smart Washer',
        'icon': 'home',
        'brand': 'Samsung',
        'desc': 'Samsung smart washing machine',
        'exploit': 'Samsung SmartThings appliance.',
        'setup_url': 'SmartThings app',
        'vuln_level': 'low'
    },
    # === Smart Appliances - Other ===
    'midea_fa': {
        'type': 'Smart Appliance',
        'icon': 'home',
        'brand': 'Midea',
        'desc': 'Midea smart appliance',
        'exploit': 'Midea/GE smart home device.',
        'setup_url': 'Midea app',
        'vuln_level': 'low'
    },
    'Kenmore_': {
        'type': 'Smart Appliance',
        'icon': 'home',
        'brand': 'Kenmore',
        'desc': 'Kenmore smart appliance',
        'exploit': 'Kenmore Connect appliance.',
        'setup_url': 'Kenmore app',
        'vuln_level': 'low'
    },
    # === Robot Vacuums ===
    'eufy': {
        'type': 'Robot Vacuum',
        'icon': 'robot',
        'brand': 'Eufy',
        'desc': 'Eufy (Anker) robot vacuum',
        'exploit': 'Robot vacuum. Maps home layout.',
        'setup_url': 'EufyHome app',
        'vuln_level': 'low'
    },
    'Shark_RV': {
        'type': 'Robot Vacuum',
        'icon': 'robot',
        'brand': 'Shark',
        'desc': 'Shark robot vacuum',
        'exploit': 'Shark IQ robot vacuum.',
        'setup_url': 'SharkClean app',
        'vuln_level': 'low'
    },
    # === Audio ===
    'Polk': {
        'type': 'Soundbar',
        'icon': 'music',
        'brand': 'Polk Audio',
        'desc': 'Polk Audio soundbar',
        'exploit': 'Smart soundbar.',
        'setup_url': 'Polk app',
        'vuln_level': 'low'
    },
    # === Mobile Hotspots ===
    'iPhone': {
        'type': 'Phone Hotspot',
        'icon': 'mobile',
        'brand': 'Apple',
        'desc': 'Apple iPhone personal hotspot',
        'exploit': 'iPhone personal hotspot. WPA2 protected.',
        'setup_url': 'N/A',
        'vuln_level': 'low'
    },
    'OnePlus': {
        'type': 'Phone Hotspot',
        'icon': 'mobile',
        'brand': 'OnePlus',
        'desc': 'OnePlus phone hotspot',
        'exploit': 'Android phone hotspot.',
        'setup_url': 'N/A',
        'vuln_level': 'low'
    },
    'PEPLINK': {
        'type': 'Mobile Router',
        'icon': 'wifi',
        'brand': 'Peplink',
        'desc': 'Peplink mobile/cellular router',
        'exploit': 'Enterprise mobile router. Multi-WAN capable.',
        'setup_url': '192.168.50.1',
        'vuln_level': 'low'
    },
    # === Vehicles ===
    'Porsche_WLAN': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Porsche',
        'desc': 'Porsche in-vehicle WiFi',
        'exploit': 'Porsche PCM WiFi hotspot.',
        'setup_url': 'PCM system',
        'vuln_level': 'low'
    },
    'Nissan RSE': {
        'type': 'Vehicle Entertainment',
        'icon': 'car',
        'brand': 'Nissan',
        'desc': 'Nissan Rear Seat Entertainment',
        'exploit': 'In-vehicle entertainment system.',
        'setup_url': 'Vehicle infotainment',
        'vuln_level': 'low'
    },
    'MINI': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'MINI',
        'desc': 'MINI Cooper in-vehicle WiFi',
        'exploit': 'BMW/MINI connected drive hotspot.',
        'setup_url': 'MINI Connected app',
        'vuln_level': 'low'
    },
    'Traverse': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Chevrolet',
        'desc': 'Chevrolet Traverse WiFi hotspot',
        'exploit': 'GM OnStar WiFi hotspot.',
        'setup_url': 'myChevrolet app',
        'vuln_level': 'low'
    },
    'MY ROGUE': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Nissan',
        'desc': 'Nissan Rogue WiFi hotspot',
        'exploit': 'Nissan NissanConnect WiFi.',
        'setup_url': 'NissanConnect app',
        'vuln_level': 'low'
    },
    'landrover': {
        'type': 'Vehicle WiFi',
        'icon': 'car',
        'brand': 'Land Rover',
        'desc': 'Land Rover in-vehicle WiFi',
        'exploit': 'JLR InControl WiFi hotspot.',
        'setup_url': 'InControl app',
        'vuln_level': 'low'
    },
    # === Dashcams ===
    'Roav_DashCam': {
        'type': 'Dashcam',
        'icon': 'camera',
        'brand': 'Anker',
        'desc': 'Anker Roav dashcam',
        'exploit': 'Roav dashcam WiFi for video transfer.',
        'setup_url': 'Roav app',
        'vuln_level': 'low'
    },
    'ROVE_R2': {
        'type': 'Dashcam',
        'icon': 'camera',
        'brand': 'Rove',
        'desc': 'Rove R2 4K dashcam',
        'exploit': 'Dashcam WiFi for footage download.',
        'setup_url': 'Rove app',
        'vuln_level': 'low'
    },
    # === Fleet/Trucking ===
    'Samsara': {
        'type': 'Fleet Tracking',
        'icon': 'truck',
        'brand': 'Samsara',
        'desc': 'Samsara fleet management device',
        'exploit': 'Fleet tracking/ELD device. GPS enabled.',
        'setup_url': 'Samsara dashboard',
        'vuln_level': 'low'
    },
    'IOSiX ELD': {
        'type': 'ELD Device',
        'icon': 'truck',
        'brand': 'IOSiX',
        'desc': 'IOSiX electronic logging device',
        'exploit': 'ELD for commercial trucks.',
        'setup_url': 'IOSiX app',
        'vuln_level': 'low'
    },
    'jomupi-eld': {
        'type': 'ELD Device',
        'icon': 'truck',
        'brand': 'Jomupi',
        'desc': 'Jomupi electronic logging device',
        'exploit': 'Commercial truck ELD.',
        'setup_url': 'ELD app',
        'vuln_level': 'low'
    },
    # === Business Equipment ===
    'iCOMM': {
        'type': 'Commercial WiFi',
        'icon': 'wifi',
        'brand': 'iCOMM',
        'desc': 'iCOMM commercial WiFi system',
        'exploit': 'Business WiFi infrastructure.',
        'setup_url': 'Check device',
        'vuln_level': 'medium'
    },
    'POS': {
        'type': 'Point of Sale',
        'icon': 'credit-card',
        'brand': 'Various',
        'desc': 'Point of Sale system WiFi',
        'exploit': 'POS terminal. Handles payment data.',
        'setup_url': 'N/A',
        'vuln_level': 'high'
    },
    'SHARP': {
        'type': 'Commercial Device',
        'icon': 'print',
        'brand': 'Sharp',
        'desc': 'Sharp commercial device (copier/display)',
        'exploit': 'Sharp business equipment.',
        'setup_url': 'Device panel',
        'vuln_level': 'medium'
    },
    # === Hotel/Hospitality ===
    'hhonors': {
        'type': 'Hotel WiFi',
        'icon': 'building',
        'brand': 'Hilton',
        'desc': 'Hilton Honors hotel WiFi',
        'exploit': 'Hotel guest network.',
        'setup_url': 'Hotel portal',
        'vuln_level': 'medium'
    },
    'HolidayInnExpress': {
        'type': 'Hotel WiFi',
        'icon': 'building',
        'brand': 'IHG',
        'desc': 'Holiday Inn Express hotel WiFi',
        'exploit': 'Hotel guest network.',
        'setup_url': 'Hotel portal',
        'vuln_level': 'medium'
    },
    'LaQuinta': {
        'type': 'Hotel WiFi',
        'icon': 'building',
        'brand': 'La Quinta',
        'desc': 'La Quinta hotel WiFi',
        'exploit': 'Hotel guest network.',
        'setup_url': 'Hotel portal',
        'vuln_level': 'medium'
    },
    'AMERICAS BEST VALUE': {
        'type': 'Hotel WiFi',
        'icon': 'building',
        'brand': 'Americas Best Value Inn',
        'desc': 'Americas Best Value Inn hotel WiFi',
        'exploit': 'Budget hotel network.',
        'setup_url': 'Hotel portal',
        'vuln_level': 'medium'
    },
    'Executive Inn': {
        'type': 'Hotel WiFi',
        'icon': 'building',
        'brand': 'Executive Inn',
        'desc': 'Executive Inn hotel WiFi',
        'exploit': 'Hotel guest network.',
        'setup_url': 'Hotel portal',
        'vuln_level': 'medium'
    },
    # === Fast Food/Restaurant ===
    'McDonalds': {
        'type': 'Restaurant WiFi',
        'icon': 'utensils',
        'brand': 'McDonalds',
        'desc': 'McDonalds free WiFi',
        'exploit': 'Public restaurant WiFi.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'Dairy Queen': {
        'type': 'Restaurant WiFi',
        'icon': 'utensils',
        'brand': 'Dairy Queen',
        'desc': 'Dairy Queen WiFi',
        'exploit': 'Fast food restaurant WiFi.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'Pizza Hut': {
        'type': 'Restaurant WiFi',
        'icon': 'utensils',
        'brand': 'Pizza Hut',
        'desc': 'Pizza Hut guest WiFi',
        'exploit': 'Restaurant guest network.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'Popeyes': {
        'type': 'Restaurant WiFi',
        'icon': 'utensils',
        'brand': 'Popeyes',
        'desc': 'Popeyes restaurant WiFi',
        'exploit': 'Fast food WiFi.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'Golden Chick': {
        'type': 'Restaurant WiFi',
        'icon': 'utensils',
        'brand': 'Golden Chick',
        'desc': 'Golden Chick restaurant WiFi',
        'exploit': 'Restaurant guest network.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'Dominos': {
        'type': 'Restaurant WiFi',
        'icon': 'utensils',
        'brand': 'Dominos',
        'desc': 'Dominos Pizza WiFi',
        'exploit': 'Pizza restaurant network.',
        'setup_url': 'N/A',
        'vuln_level': 'medium'
    },
    'Shipleys': {
        'type': 'Restaurant WiFi',
        'icon': 'utensils',
        'brand': 'Shipleys',
        'desc': 'Shipleys Donuts WiFi',
        'exploit': 'Donut shop WiFi.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'Whopper': {
        'type': 'Restaurant WiFi',
        'icon': 'utensils',
        'brand': 'Burger King',
        'desc': 'Burger King WiFi',
        'exploit': 'Fast food restaurant WiFi.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'Walmartwifi': {
        'type': 'Retail WiFi',
        'icon': 'shopping-cart',
        'brand': 'Walmart',
        'desc': 'Walmart store WiFi',
        'exploit': 'Retail store public network.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'TSC_Customer': {
        'type': 'Retail WiFi',
        'icon': 'shopping-cart',
        'brand': 'Tractor Supply',
        'desc': 'Tractor Supply Company WiFi',
        'exploit': 'Retail store network.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'HEB': {
        'type': 'Retail WiFi',
        'icon': 'shopping-cart',
        'brand': 'HEB',
        'desc': 'HEB grocery store WiFi',
        'exploit': 'Grocery store network.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    # === Retail ===
    'JOANNS': {
        'type': 'Retail WiFi',
        'icon': 'shopping-cart',
        'brand': 'Joann Fabrics',
        'desc': 'Joann Fabrics store WiFi',
        'exploit': 'Retail store network.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
    'TheUPSStore': {
        'type': 'Retail WiFi',
        'icon': 'box',
        'brand': 'UPS',
        'desc': 'UPS Store WiFi',
        'exploit': 'UPS Store business network.',
        'setup_url': 'N/A',
        'vuln_level': 'medium'
    },
    # === Baby Monitors ===
    'VTECH_': {
        'type': 'Baby Monitor',
        'icon': 'baby',
        'brand': 'VTech',
        'desc': 'VTech baby monitor or cordless phone',
        'exploit': 'VTech has had security breaches. Check firmware.',
        'setup_url': 'VTech app',
        'vuln_level': 'high'
    },
    # === Scanners ===
    'iX1500': {
        'type': 'Document Scanner',
        'icon': 'file',
        'brand': 'Fujitsu',
        'desc': 'Fujitsu ScanSnap document scanner',
        'exploit': 'Network document scanner.',
        'setup_url': 'ScanSnap app',
        'vuln_level': 'low'
    },
    # === Medical ===
    'NxStageRouter': {
        'type': 'Medical Device',
        'icon': 'medkit',
        'brand': 'NxStage',
        'desc': 'NxStage home dialysis router',
        'exploit': 'Medical device for home dialysis.',
        'setup_url': 'N/A',
        'vuln_level': 'low'
    },
    'MedCart': {
        'type': 'Medical Device',
        'icon': 'medkit',
        'brand': 'Various',
        'desc': 'Medical cart WiFi',
        'exploit': 'Healthcare equipment.',
        'setup_url': 'N/A',
        'vuln_level': 'medium'
    },
    # === Educational ===
    'eduroam': {
        'type': 'Educational WiFi',
        'icon': 'graduation-cap',
        'brand': 'Eduroam',
        'desc': 'Eduroam educational roaming network',
        'exploit': 'Federated academic WiFi. 802.1X authentication.',
        'setup_url': 'Institution portal',
        'vuln_level': 'low'
    },
    # === Streaming ===
    'SlingTV': {
        'type': 'Streaming Device',
        'icon': 'tv',
        'brand': 'Sling',
        'desc': 'Sling TV streaming device',
        'exploit': 'Streaming service device.',
        'setup_url': 'Sling app',
        'vuln_level': 'low'
    },
    # === Automotive Accessories ===
    'YADA_BEON': {
        'type': 'Backup Camera',
        'icon': 'camera',
        'brand': 'YADA',
        'desc': 'YADA wireless backup camera',
        'exploit': 'Aftermarket backup camera.',
        'setup_url': 'N/A',
        'vuln_level': 'low'
    },
    'witech': {
        'type': 'Diagnostic Tool',
        'icon': 'wrench',
        'brand': 'Witech',
        'desc': 'Witech automotive diagnostic tool',
        'exploit': 'OEM diagnostic equipment for Chrysler/Jeep/Dodge.',
        'setup_url': 'N/A',
        'vuln_level': 'low'
    },
    'wva-': {
        'type': 'Diagnostic Tool',
        'icon': 'wrench',
        'brand': 'Various',
        'desc': 'Vehicle diagnostic WiFi adapter',
        'exploit': 'OBD/diagnostic WiFi adapter.',
        'setup_url': 'N/A',
        'vuln_level': 'low'
    },
    # === Industrial ===
    'Silca-Futura': {
        'type': 'Key Machine',
        'icon': 'key',
        'brand': 'Silca',
        'desc': 'Silca Futura key cutting machine',
        'exploit': 'Professional locksmith equipment.',
        'setup_url': 'N/A',
        'vuln_level': 'low'
    },
    'SENA': {
        'type': 'Bluetooth Intercom',
        'icon': 'headphones',
        'brand': 'SENA',
        'desc': 'SENA motorcycle Bluetooth intercom',
        'exploit': 'Motorcycle communication device.',
        'setup_url': 'SENA app',
        'vuln_level': 'low'
    },
    # === Presentation ===
    'SEC_LinkShare': {
        'type': 'Presentation System',
        'icon': 'tv',
        'brand': 'Samsung',
        'desc': 'Samsung LinkShare wireless display',
        'exploit': 'Wireless presentation system.',
        'setup_url': 'Samsung Smart View',
        'vuln_level': 'low'
    },
    # === RV/Camping ===
    'RangeXTD': {
        'type': 'WiFi Extender',
        'icon': 'wifi',
        'brand': 'RangeXTD',
        'desc': 'RangeXTD WiFi range extender',
        'exploit': 'WiFi range extender for RV/camping.',
        'setup_url': '192.168.10.1',
        'vuln_level': 'medium'
    },
    'Pvt.WiFiRanger': {
        'type': 'RV Router',
        'icon': 'wifi',
        'brand': 'WiFiRanger',
        'desc': 'WiFiRanger RV mobile router',
        'exploit': 'Long-range WiFi for RVs.',
        'setup_url': '192.168.50.1',
        'vuln_level': 'low'
    },
    'TengoInternet': {
        'type': 'RV WiFi',
        'icon': 'wifi',
        'brand': 'Tengo Internet',
        'desc': 'Tengo Internet RV park WiFi',
        'exploit': 'RV park/campground WiFi service.',
        'setup_url': 'Captive portal',
        'vuln_level': 'medium'
    },
}

def identify_device(ssid, auth_mode):
    """
    Identify device type from SSID and return exploit info.
    Returns dict with type, desc, exploit, setup_url, vuln_level, icon
    """
    if not ssid:
        return None

    ssid_lower = ssid.lower()

    # Check for WEP first (always critical)
    if '[WEP]' in auth_mode:
        info = DEVICE_DATABASE['[WEP]'].copy()
        info['match'] = 'WEP Encryption'
        return info

    # Check each pattern in database
    for pattern, info in DEVICE_DATABASE.items():
        if pattern == '[WEP]':
            continue
        # Case-insensitive matching
        if pattern.lower() in ssid_lower or ssid_lower.startswith(pattern.lower()):
            result = info.copy()
            result['match'] = pattern
            # Adjust vuln level if OPEN
            if '[OPEN]' in auth_mode:
                result['vuln_level'] = 'critical'
                result['exploit'] = 'OPEN NETWORK! ' + result['exploit']
            return result

    # Default: Residential/Custom network name
    result = {
        'type': 'Residential Network',
        'icon': 'home',
        'brand': 'Unknown',
        'desc': 'Custom or residential network name',
        'exploit': 'Standard home/business WiFi network with custom SSID.',
        'setup_url': 'Check router label',
        'vuln_level': 'low',
        'match': 'Custom SSID'
    }
    # Adjust vuln level if OPEN
    if '[OPEN]' in auth_mode:
        result['vuln_level'] = 'critical'
        result['exploit'] = 'OPEN NETWORK! ' + result['exploit']
    return result

# Threat category patterns for auto-classification
RESIDENTIAL_PATTERNS = [
    'netgear', 'asus', 'tp-link', 'tplink', 'linksys', 'dlink', 'd-link',
    'xfinity', 'xfinitywifi', 'att', 'att-wifi', 'spectrum', 'verizon',
    'centurylink', 'frontier', 'cox', 'comcast', 'optimum', 'charter',
    'eero', 'google wifi', 'googlewifi', 'orbi', 'velop', 'deco', 'mesh',
    'arris', 'motorola', 'ubee', 'technicolor', 'actiontec', 'zyxel',
    '-2.4g', '-5g', '-guest', 'home', 'house', 'family', 'kids',
    'mynetwork', 'wireless', 'mywifi', 'router', 'network'
]

CORPORATE_PATTERNS = [
    'corp', 'corporate', 'office', 'business', 'enterprise', 'company',
    'employee', 'staff', 'internal', 'secure', 'private', 'confidential',
    'unifi', 'ubiquiti', 'cisco', 'meraki', 'aruba', 'ruckus', 'fortinet',
    'sonicwall', 'watchguard', 'paloalto', 'juniper', 'mikrotik',
    'conference', 'meeting', 'boardroom', 'training', 'warehouse',
    'factory', 'plant', 'hq', 'headquarters', 'branch'
]

GUEST_PATTERNS = [
    'guest', 'visitor', 'public', 'free', 'open', 'hotspot', 'wifi',
    'hhonors', 'marriott', 'hilton', 'hyatt', 'sheraton', 'westin',
    'holiday inn', 'hampton', 'courtyard', 'fairfield', 'residence inn',
    'starbucks', 'mcdonalds', 'wendys', 'subway', 'chilis', 'applebees',
    'panera', 'chipotle', 'buffalo wild', 'dennys', 'ihop', 'waffle',
    'bestbuy', 'walmart', 'target', 'costco', 'sams club', 'lowes',
    'home depot', 'kroger', 'publix', 'heb', 'whataburger',
    'attwifi', 'cablewifi', 'xfinity wifi', 'spectrum wifi',
    'airport', 'terminal', 'lounge', 'lobby', 'waiting'
]

def categorize_threat(ssid, device_type, auth_mode):
    """
    Categorize network into threat categories for filtering.
    Returns: 'corporate', 'residential', 'guest', 'iot', or 'unknown'
    """
    if not ssid:
        return 'unknown'

    ssid_lower = ssid.lower()
    device_lower = device_type.lower() if device_type else ''

    # IoT devices get their own category (printers, cameras, doorbells, etc.)
    iot_types = ['printer', 'camera', 'doorbell', 'speaker', 'thermostat', 'vacuum',
                 'robot', 'smart', 'iot', 'sensor', 'hub', 'bridge', 'bulb', 'light',
                 'plug', 'switch', 'lock', 'garage', 'sprinkler', 'tv', 'roku', 'firestick']
    for iot_type in iot_types:
        if iot_type in device_lower:
            return 'iot'

    # Check for guest network patterns first (highest priority after IoT)
    for pattern in GUEST_PATTERNS:
        if pattern in ssid_lower:
            return 'guest'

    # Check for corporate patterns
    for pattern in CORPORATE_PATTERNS:
        if pattern in ssid_lower:
            return 'corporate'

    # Check for residential patterns
    for pattern in RESIDENTIAL_PATTERNS:
        if pattern in ssid_lower:
            return 'residential'

    # Default: unknown (could be either corporate or residential)
    return 'unknown'

def get_threat_category_badge(category):
    """Return HTML badge for threat category"""
    # Colors adjusted for WCAG AA contrast compliance (4.5:1 minimum with white text)
    colors = {
        'corporate': '#2874a6',   # Darker Blue (was #3498db) - 5.2:1 contrast
        'residential': '#4a5a5b', # Darker Gray (was #95a5a6) - 6.8:1 contrast
        'guest': '#b7770a',       # Darker Orange (was #f39c12) - 4.6:1 contrast
        'iot': '#c0392b',         # Darker Red (was #e74c3c) - 5.9:1 contrast
        'unknown': '#1a5276'      # Teal/Dark Blue (was #7f8c8d) - distinct from Residential
    }
    labels = {
        'corporate': '🏢 Corporate',
        'residential': '🏠 Residential',
        'guest': '🌐 Guest',
        'iot': '📡 IoT/Vulnerable',
        'unknown': '📶 Other Networks'
    }
    color = colors.get(category, '#1a5276')
    label = labels.get(category, '📶 Other Networks')
    return f'<span style="background:{color};color:white;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">{label}</span>'

def get_vuln_badge(vuln_level):
    """Return HTML badge for vulnerability level"""
    colors = {
        'critical': '#e74c3c',  # Red
        'high': '#e67e22',      # Orange
        'medium': '#f39c12',    # Yellow
        'low': '#27ae60'        # Green
    }
    labels = {
        'critical': '🔴 CRITICAL',
        'high': '🟠 HIGH',
        'medium': '🟡 MEDIUM',
        'low': '🟢 LOW'
    }
    color = colors.get(vuln_level, '#95a5a6')
    label = labels.get(vuln_level, 'UNKNOWN')
    return f'<span style="background:{color};color:white;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">{label}</span>'

def check_internet_connection():
    """Check if we can actually reach Google's tile servers"""
    try:
        response = requests.get('https://mt1.google.com/vt/lyrs=y&x=0&y=0&z=0', timeout=3)
        return response.status_code == 200
    except:
        return False

def init_database():
    """Initialize SQLite database for cumulative data"""
    db_path = os.path.join(SCRIPT_DIR, 'wardrive_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Main networks table - stores calculated/estimated location
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS networks (
            mac TEXT PRIMARY KEY,
            ssid TEXT,
            auth_mode TEXT,
            first_seen TEXT,
            channel INTEGER,
            rssi INTEGER,
            latitude REAL,
            longitude REAL,
            altitude REAL,
            accuracy REAL,
            last_updated TEXT,
            observation_count INTEGER DEFAULT 1
        )
    ''')

    # Sessions table - each file import is a separate session
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            imported_at TEXT NOT NULL,
            network_count INTEGER DEFAULT 0,
            new_networks INTEGER DEFAULT 0
        )
    ''')

    # Observations table - stores ALL captures for triangulation
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            session_id INTEGER,
            rssi INTEGER,
            latitude REAL,
            longitude REAL,
            captured_at TEXT,
            FOREIGN KEY (mac) REFERENCES networks(mac),
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )
    ''')

    # Add observation_count column if it doesn't exist (for existing databases)
    try:
        cursor.execute('ALTER TABLE networks ADD COLUMN observation_count INTEGER DEFAULT 1')
    except:
        pass  # Column already exists

    # Add session_id column to observations if it doesn't exist
    try:
        cursor.execute('ALTER TABLE observations ADD COLUMN session_id INTEGER')
    except:
        pass  # Column already exists

    # Add target_tag columns for network tagging (for existing databases)
    try:
        cursor.execute('ALTER TABLE networks ADD COLUMN target_tag TEXT DEFAULT NULL')
    except:
        pass  # Column already exists
    try:
        cursor.execute('ALTER TABLE networks ADD COLUMN target_notes TEXT DEFAULT NULL')
    except:
        pass  # Column already exists
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_networks_target_tag ON networks(target_tag)')
    except:
        pass  # Index already exists

    conn.commit()
    return conn


def estimate_ap_location(observations):
    """
    Estimate AP location using weighted centroid based on RSSI.
    Stronger signals (closer to 0) get higher weight.
    """
    if not observations:
        return None, None

    # Filter out observations with None values
    valid_obs = [(r, lat, lon) for r, lat, lon in observations if r is not None and lat is not None and lon is not None]

    if not valid_obs:
        return None, None

    if len(valid_obs) == 1:
        return valid_obs[0][1], valid_obs[0][2]  # lat, lon

    total_weight = 0
    weighted_lat = 0
    weighted_lon = 0

    for rssi, lat, lon in valid_obs:
        # Convert RSSI to weight: -50 dBm -> weight 50, -90 dBm -> weight 10
        # Stronger signal = higher weight = pulls location more
        weight = max(1, 100 + rssi)  # -50 -> 50, -90 -> 10, -100 -> 1
        weight = weight ** 2  # Square it to emphasize stronger signals more

        weighted_lat += lat * weight
        weighted_lon += lon * weight
        total_weight += weight

    if total_weight == 0:
        return valid_obs[0][1], valid_obs[0][2]

    return weighted_lat / total_weight, weighted_lon / total_weight

def parse_wardrive_file(filename):
    """Parse Flipper Zero wardrive .txt file"""
    print(f"📂 Reading {filename}...")
    
    try:
        # Read the file, skip first line (WigleWifi header)
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Find the column header line
        header_line = None
        data_start = 0
        for i, line in enumerate(lines):
            if line.startswith('MAC,SSID'):
                header_line = line.strip()
                data_start = i + 1
                break
        
        if header_line is None:
            print("❌ Error: Could not find column headers in file")
            return None
        
        # Parse CSV data
        csv_data = '\n'.join([header_line] + lines[data_start:])
        df = pd.read_csv(pd.io.common.StringIO(csv_data))
        
        print(f"✅ Found {len(df)} networks in file")
        return df
        
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return None

def update_database(conn, df, filename):
    """Add all observations to database, recalculate AP locations"""
    cursor = conn.cursor()
    added = 0
    updated = 0
    observations_added = 0

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Create a new session for this file import
    cursor.execute('''
        INSERT INTO sessions (filename, imported_at, network_count, new_networks)
        VALUES (?, ?, 0, 0)
    ''', (os.path.basename(filename), current_time))
    session_id = cursor.lastrowid
    print(f"📝 Created session #{session_id} for {os.path.basename(filename)}")

    for _, row in df.iterrows():
        mac = row['MAC']
        rssi = row['RSSI']
        lat = row['CurrentLatitude']
        lon = row['CurrentLongitude']

        # Always add observation with session_id
        cursor.execute('''
            INSERT INTO observations (mac, session_id, rssi, latitude, longitude, captured_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (mac, session_id, rssi, lat, lon, row['FirstSeen']))
        observations_added += 1

        # Check if network exists
        cursor.execute('SELECT mac FROM networks WHERE mac = ?', (mac,))
        result = cursor.fetchone()

        if result:
            updated += 1
        else:
            # Insert new network entry (location will be calculated below)
            cursor.execute('''
                INSERT INTO networks
                (mac, ssid, auth_mode, first_seen, channel, rssi,
                 latitude, longitude, altitude, accuracy, last_updated, observation_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                mac,
                row['SSID'],
                row['AuthMode'],
                row['FirstSeen'],
                row['Channel'],
                rssi,
                lat,
                lon,
                row['AltitudeMeters'],
                row['AccuracyMeters'],
                current_time
            ))
            added += 1

    # Update session stats
    cursor.execute('''
        UPDATE sessions SET network_count = ?, new_networks = ? WHERE id = ?
    ''', (len(df), added, session_id))

    conn.commit()

    # Now recalculate locations for all networks that got new observations
    print(f"📍 Recalculating AP locations...")
    macs_to_update = set(df['MAC'].tolist())

    for mac in macs_to_update:
        # Get all observations for this MAC
        cursor.execute('''
            SELECT rssi, latitude, longitude FROM observations WHERE mac = ?
        ''', (mac,))
        observations = cursor.fetchall()

        if observations:
            valid_obs = [(r, lat, lon) for r, lat, lon in observations if r is not None and lat is not None and lon is not None]

            if not valid_obs:
                continue

            obs_count = len(valid_obs)
            valid_rssi = [obs[0] for obs in valid_obs]
            best_rssi = max(valid_rssi)

            if obs_count >= 3:
                # 3+ observations: use triangulation
                est_lat, est_lon = estimate_ap_location(observations)
            else:
                # <3 observations: use strongest signal location
                strongest_obs = max(valid_obs, key=lambda x: x[0])
                est_lat, est_lon = strongest_obs[1], strongest_obs[2]

            # Update network with calculated location
            cursor.execute('''
                UPDATE networks
                SET latitude = ?, longitude = ?, rssi = ?, observation_count = ?, last_updated = ?
                WHERE mac = ?
            ''', (est_lat, est_lon, best_rssi, obs_count, current_time, mac))

    conn.commit()
    print(f"✅ Added {added} new networks, updated {updated} existing, {observations_added} observations stored")

def create_map(conn):
    """Create interactive HTML map from database"""
    output_file = os.path.join(os.path.dirname(SCRIPT_DIR), 'wardrive_master_map.html')

    cursor = conn.cursor()
    cursor.execute('SELECT * FROM networks ORDER BY rssi DESC')
    all_networks = cursor.fetchall()

    if not all_networks:
        print("❌ No networks in database!")
        return

    # Categorize all networks
    print(f"🗺️  Processing {len(all_networks)} total APs from database...")

    networks = []          # Regular named networks
    hidden_networks = []   # Blank/hidden SSIDs

    # Vehicle SSID patterns to EXCLUDE from map entirely
    vehicle_patterns = [
        'chevy', 'chevrolet', 'ford', 'gmc', 'dodge', 'ram', 'jeep', 'chrysler',
        'toyota', 'honda', 'nissan', 'hyundai', 'kia', 'mazda', 'subaru',
        'bmw', 'mercedes', 'audi', 'volkswagen', 'vw', 'lexus', 'acura',
        'infiniti', 'cadillac', 'buick', 'lincoln', 'tesla', 'rivian',
        'mylink', 'uconnect', 'sync', 'entune', 'bluelink', 'carplay',
        'onstar', 'wifi hotspot', 'car wifi', 'vehicle', 'truck'
    ]

    vehicles_skipped = 0
    for network in all_networks:
        mac = network[0]
        ssid = network[1]
        rssi = network[5]

        # Skip networks with no RSSI data
        if rssi is None:
            continue

        # Skip vehicle networks entirely - don't add to map
        if ssid and any(pattern in ssid.lower() for pattern in vehicle_patterns):
            vehicles_skipped += 1
            continue

        # Categorize by SSID
        if not ssid or ssid.strip() == '':
            hidden_networks.append(network)
        else:
            networks.append(network)

    print(f"📍 Regular: {len(networks)}, Hidden: {len(hidden_networks)}, Vehicles skipped: {vehicles_skipped}")

    # Query sessions with wardrive dates (use earliest observation date, not import date)
    cursor.execute('''
        SELECT s.id, s.filename, s.imported_at,
               (SELECT MIN(captured_at) FROM observations WHERE session_id = s.id) as wardrive_date
        FROM sessions s ORDER BY s.id
    ''')
    sessions = cursor.fetchall()
    print(f"📅 Sessions: {len(sessions)}")

    # Build network -> session mapping from observations
    network_sessions = {}
    cursor.execute('SELECT mac, session_id FROM observations GROUP BY mac, session_id')
    for row in cursor.fetchall():
        mac, session_id = row
        if mac not in network_sessions:
            network_sessions[mac] = set()
        network_sessions[mac].add(session_id)

    # Identify networks NEW in the most recent session
    # A network is "new" if its first observation was in the latest session
    new_this_session = set()
    if sessions:
        latest_session_id = max(s[0] for s in sessions)
        # Only calculate if not the first session (otherwise all would be "new")
        if len(sessions) > 1:
            cursor.execute("""
                SELECT n.mac
                FROM networks n
                WHERE n.mac IN (
                    SELECT mac FROM observations WHERE session_id = ?
                )
                AND n.mac NOT IN (
                    SELECT DISTINCT mac FROM observations WHERE session_id < ?
                )
            """, (latest_session_id, latest_session_id))
            new_this_session = {row[0] for row in cursor.fetchall()}
            print(f"🆕 New This Session: {len(new_this_session)} networks (session #{latest_session_id})")
        else:
            print(f"🆕 First session - all networks are baseline (no 'new' highlighting)")

    # Calculate center point (average of all coordinates)
    lats = [n[6] for n in networks]
    lons = [n[7] for n in networks]
    center_lat = sum(lats) / len(lats)
    center_lon = sum(lons) / len(lons)
    
    # Start with satellite view as base
    m = folium.Map(
        location=[center_lat, center_lon],
        zoom_start=13,  # City-level view, will auto-fit to markers
        tiles=None
    )
    
    # Check if we have internet connectivity
    tiles_dir = os.path.join(SCRIPT_DIR, 'tiles')
    has_internet = check_internet_connection()
    has_local_tiles = os.path.exists(tiles_dir)
    
    # Use local tiles ONLY if offline AND tiles exist
    use_local_tiles = not has_internet and has_local_tiles
    
    if use_local_tiles:
        print("🗺️  Using offline tiles from ./tiles/ (no internet connection)")
        # Add local Google Satellite Hybrid tiles
        folium.TileLayer(
            tiles='tiles/y/{z}/{x}/{y}.png',
            attr='Google (Offline)',
            name='Google Satellite',
            overlay=False,
            control=True,
            max_zoom=22
        ).add_to(m)
        
        # Add local Google Street Map tiles
        folium.TileLayer(
            tiles='tiles/m/{z}/{x}/{y}.png',
            attr='Google (Offline)',
            name='Google Streets',
            overlay=False,
            control=True,
            max_zoom=22
        ).add_to(m)
    else:
        if has_internet:
            print("🌐 Using online tiles (internet connected)")
        else:
            print("⚠️  No internet and no local tiles - map may not display properly")

        # Add Google Satellite Hybrid (satellite imagery with street labels/business names)
        tile_google_sat = folium.TileLayer(
            tiles='https://mt1.google.com/vt/lyrs=y&x={x}&y={y}&z={z}',
            attr='Google',
            name='🛰️ Google Satellite',
            overlay=False,
            control=False,
            max_zoom=22
        )
        tile_google_sat.add_to(m)

        # Add Google Maps (street view with labels)
        tile_google_str = folium.TileLayer(
            tiles='https://mt1.google.com/vt/lyrs=m&x={x}&y={y}&z={z}',
            attr='Google',
            name='🗺️ Google Streets',
            overlay=False,
            control=False,
            max_zoom=22
        )
        tile_google_str.add_to(m)

    # Always add local tiles as fallback options if they exist
    tile_offline_sat = None
    tile_offline_str = None
    if has_local_tiles:
        print("📦 Adding offline tile layers as fallback options")
        tile_offline_sat = folium.TileLayer(
            tiles='tiles/y/{z}/{x}/{y}.png',
            attr='Google (Offline)',
            name='📴 Offline Satellite',
            overlay=False,
            control=False,
            max_zoom=22
        )
        tile_offline_sat.add_to(m)

        tile_offline_str = folium.TileLayer(
            tiles='tiles/m/{z}/{x}/{y}.png',
            attr='Google (Offline)',
            name='📴 Offline Streets',
            overlay=False,
            control=False,
            max_zoom=22
        )
        tile_offline_str.add_to(m)
    
    # Add heat map layer (WiFi density) - include all networks
    all_coords = [[n[6], n[7]] for n in networks + hidden_networks]
    heat_map = plugins.HeatMap(
        all_coords,
        name='📊 Density Heat Map',
        min_opacity=0.3,
        radius=25,
        blur=15,
        gradient={0.4: 'blue', 0.6: 'lime', 0.8: 'yellow', 1.0: 'red'}
    )
    heat_map.add_to(m)

    # Create CLUSTERED groups (default view - ON)
    # disableClusteringAtZoom: 19 = clusters NEVER auto-uncluster (max useful zoom is ~18)
    # maxClusterRadius: 80 = group markers within 80px (default)
    cluster_options = {
        'disableClusteringAtZoom': 19,
        'maxClusterRadius': 80,
        'spiderfyOnMaxZoom': False  # Don't spiderfy even at max zoom
    }

    open_cluster = plugins.MarkerCluster(
        name='🔓 Open (clustered)',
        overlay=True,
        control=False,
        show=True,
        options=cluster_options
    )
    open_cluster.add_to(m)

    secured_cluster = plugins.MarkerCluster(
        name='🔒 Secured (clustered)',
        overlay=True,
        control=False,
        show=True,
        options=cluster_options
    )
    secured_cluster.add_to(m)

    # Create UNCLUSTERED groups (OFF by default - turn on to see all markers)
    open_unclustered = folium.FeatureGroup(
        name='🔓 Open (all markers)',
        overlay=True,
        control=False,
        show=False
    )
    open_unclustered.add_to(m)

    secured_unclustered = folium.FeatureGroup(
        name='🔒 Secured (all markers)',
        overlay=True,
        control=False,
        show=False
    )
    secured_unclustered.add_to(m)

    # Hidden networks group (off by default)
    hidden_group = folium.FeatureGroup(
        name='👻 Hidden Networks',
        overlay=True,
        control=False,
        show=False
    )
    hidden_group.add_to(m)

    # IoT/Vulnerable devices group (off by default)
    iot_group = folium.FeatureGroup(
        name='🔌 IoT Devices',
        overlay=True,
        control=False,
        show=False
    )
    iot_group.add_to(m)

    # Risk level groups (off by default - turn on to filter by risk)
    risk_critical = folium.FeatureGroup(
        name='🔴 CRITICAL',
        overlay=True,
        control=False,
        show=False
    )
    risk_critical.add_to(m)

    risk_high = folium.FeatureGroup(
        name='🟠 HIGH',
        overlay=True,
        control=False,
        show=False
    )
    risk_high.add_to(m)

    risk_medium = folium.FeatureGroup(
        name='🟡 MEDIUM',
        overlay=True,
        control=False,
        show=False
    )
    risk_medium.add_to(m)

    risk_low = folium.FeatureGroup(
        name='🟢 LOW',
        overlay=True,
        control=False,
        show=False
    )
    risk_low.add_to(m)

    # ========== SIGNAL STRENGTH LAYERS (CLUSTERED) ==========
    # Filter networks by signal strength (RSSI) - strong signals shown by default
    signal_green = plugins.MarkerCluster(
        name='💚 Strong (≥ -65 dBm)',
        overlay=True,
        control=False,
        show=True,  # ON by default
        options=cluster_options
    )
    signal_green.add_to(m)

    signal_lightgreen = plugins.MarkerCluster(
        name='💚 Good (-72 to -65 dBm)',
        overlay=True,
        control=False,
        show=True,  # ON by default
        options=cluster_options
    )
    signal_lightgreen.add_to(m)

    signal_beige = plugins.MarkerCluster(
        name='💛 Fair (-78 to -72 dBm)',
        overlay=True,
        control=False,
        show=False,  # OFF by default
        options=cluster_options
    )
    signal_beige.add_to(m)

    signal_orange = plugins.MarkerCluster(
        name='🧡 Moderate (-84 to -78 dBm)',
        overlay=True,
        control=False,
        show=False,  # OFF by default
        options=cluster_options
    )
    signal_orange.add_to(m)

    signal_lightred = plugins.MarkerCluster(
        name='🩷 Weak (-92 to -84 dBm)',
        overlay=True,
        control=False,
        show=False,  # OFF by default
        options=cluster_options
    )
    signal_lightred.add_to(m)

    signal_red = plugins.MarkerCluster(
        name='❤️ Very Weak (< -92 dBm)',
        overlay=True,
        control=False,
        show=False,  # OFF by default
        options=cluster_options
    )
    signal_red.add_to(m)

    # Threat category groups (for filtering by target type)
    threat_corporate = folium.FeatureGroup(
        name='🏢 Corporate',
        overlay=True,
        control=False,
        show=False
    )
    threat_corporate.add_to(m)

    threat_residential = folium.FeatureGroup(
        name='🏠 Residential',
        overlay=True,
        control=False,
        show=False
    )
    threat_residential.add_to(m)

    threat_guest = folium.FeatureGroup(
        name='🌐 Guest Networks',
        overlay=True,
        control=False,
        show=False
    )
    threat_guest.add_to(m)

    threat_iot = folium.FeatureGroup(
        name='📡 IoT/Vulnerable',
        overlay=True,
        control=False,
        show=False
    )
    threat_iot.add_to(m)

    threat_unknown = folium.FeatureGroup(
        name='📶 Other Networks',
        overlay=True,
        control=False,
        show=False
    )
    threat_unknown.add_to(m)

    # ========== TARGET TAG LAYERS ==========
    # Create FeatureGroups for tagged networks (OFF by default, visible via layer control)
    tag_primary = folium.FeatureGroup(
        name='🎯 Primary Targets',
        overlay=True,
        control=False,
        show=False
    )
    tag_primary.add_to(m)

    tag_secondary = folium.FeatureGroup(
        name='📌 Secondary Targets',
        overlay=True,
        control=False,
        show=False
    )
    tag_secondary.add_to(m)

    tag_out_of_scope = folium.FeatureGroup(
        name='⛔ Out of Scope',
        overlay=True,
        control=False,
        show=False
    )
    tag_out_of_scope.add_to(m)

    # Create "New This Session" layer (shows networks discovered in most recent session)
    new_session_count = len(new_this_session)
    new_session_group = folium.FeatureGroup(
        name=f'🆕 New This Session ({new_session_count})',
        overlay=True,
        control=False,
        show=False  # OFF by default, user can toggle on
    )
    new_session_group.add_to(m)

    # Create FeatureGroup for each session (OFF by default - filter view)
    session_groups = {}
    for session in sessions:
        session_id, filename, imported_at, wardrive_date = session
        # Use wardrive datetime if valid, otherwise fall back to import datetime
        if wardrive_date and not wardrive_date.startswith('1963'):  # Skip malformed dates
            # Use full datetime to make labels unique (date + time)
            date_label = wardrive_date.replace(' ', ' @ ')  # "2026-01-14 @ 13:32:15"
        else:
            date_label = imported_at.replace(' ', ' @ ') if imported_at else f"Session {session_id}"

        group_name = f"📅 {date_label}"

        session_groups[session_id] = {
            'group': folium.FeatureGroup(name=group_name, overlay=True, control=False, show=False),
            'label': group_name,
            'date': date_label
        }
        session_groups[session_id]['group'].add_to(m)

    print(f"📅 Created {len(session_groups)} session layers")

    # ========== GPS TRACK LAYERS ==========
    # Create GPS track polylines for each session
    gps_tracks = {}
    gps_track_stats = {}

    for idx, session in enumerate(sessions):
        session_id, filename, imported_at, wardrive_date = session

        # Get GPS points for this session
        cursor.execute("""
            SELECT DISTINCT latitude, longitude, captured_at
            FROM observations
            WHERE session_id = ? AND latitude IS NOT NULL AND longitude IS NOT NULL
            AND latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180
            ORDER BY captured_at
        """, (session_id,))
        gps_rows = cursor.fetchall()

        if len(gps_rows) < 2:
            print(f"   📍 Session {session_id}: No GPS track (< 2 points)")
            continue

        # Extract points and timestamps
        raw_points = [(row[0], row[1]) for row in gps_rows]
        timestamps = [row[2] for row in gps_rows if row[2]]

        # Filter out GPS outliers (points that jump more than 5 miles from previous point)
        # This handles cases where a session has data from multiple unrelated wardrive runs
        MAX_JUMP_MILES = 5.0
        filtered_points = [raw_points[0]] if raw_points else []
        outliers_removed = 0
        for i in range(1, len(raw_points)):
            dist = haversine_distance(
                filtered_points[-1][0], filtered_points[-1][1],
                raw_points[i][0], raw_points[i][1]
            )
            if dist <= MAX_JUMP_MILES:
                filtered_points.append(raw_points[i])
            else:
                outliers_removed += 1

        if outliers_removed > 0:
            print(f"   ⚠️  Session {session_id}: Removed {outliers_removed} GPS outliers (>{MAX_JUMP_MILES} mi jumps)")
            raw_points = filtered_points

        if len(raw_points) < 2:
            print(f"   📍 Session {session_id}: No GPS track after filtering (< 2 points)")
            continue

        # Simplify track if too many points (performance optimization)
        if len(raw_points) > 500:
            # Adaptive tolerance based on route size
            tolerance = 0.0001 if len(raw_points) < 2000 else 0.0002
            track_points = simplify_track(raw_points, tolerance)
            print(f"   📍 Session {session_id}: {len(raw_points)} → {len(track_points)} points (simplified)")
        else:
            track_points = raw_points
            print(f"   📍 Session {session_id}: {len(track_points)} GPS points")

        # Calculate stats
        distance, duration, avg_speed = calculate_track_stats(raw_points, timestamps)
        gps_track_stats[session_id] = {
            'distance': distance,
            'duration': duration,
            'duration_str': format_duration(duration),
            'avg_speed': avg_speed,
            'point_count': len(raw_points),
            'date': wardrive_date or imported_at
        }

        # Get color for this session
        track_color = GPS_TRACK_COLORS[idx % len(GPS_TRACK_COLORS)]

        # Create date/time label (include time for uniqueness when multiple sessions on same day)
        if wardrive_date and not wardrive_date.startswith('1963'):
            # Format: "2026-01-14 13:32" (date + hour:minute for uniqueness)
            date_part = wardrive_date.split(' ')[0]
            time_part = wardrive_date.split(' ')[1][:5] if ' ' in wardrive_date else ''  # HH:MM
            track_label = f"{date_part} {time_part}".strip()
        else:
            # Fallback to imported_at with time
            date_part = imported_at.split(' ')[0] if imported_at else f"Session {session_id}"
            time_part = imported_at.split(' ')[1][:5] if imported_at and ' ' in imported_at else ''
            track_label = f"{date_part} {time_part}".strip() if imported_at else f"Session {session_id}"

        # Create FeatureGroup for this track
        # Note: control=True is required for Folium to add to map; we hide default control via CSS
        track_group = folium.FeatureGroup(
            name=f"🛣️ {track_label}",
            overlay=True,
            control=True,
            show=False  # OFF by default
        )

        # Create polyline
        polyline = folium.PolyLine(
            locations=track_points,
            color=track_color,
            weight=3,
            opacity=0.7,
            smooth_factor=1.5,
            popup=f"""<b>GPS Track: {track_label}</b><br>
                     Distance: {distance} miles<br>
                     Duration: {format_duration(duration)}<br>
                     Avg Speed: {avg_speed} mph<br>
                     Points: {len(raw_points)}"""
        )
        polyline.add_to(track_group)
        track_group.add_to(m)

        # Store polyline and group names for JavaScript fix-up (Folium bug workaround)
        polyline_name = polyline.get_name()
        group_name = track_group.get_name()

        gps_tracks[session_id] = {
            'group': track_group,
            'label': f"🛣️ {track_label}",
            'color': track_color,
            'stats': gps_track_stats[session_id],
            'polyline_name': polyline_name,
            'group_name': group_name
        }

    print(f"🛣️  Created {len(gps_tracks)} GPS track layers")

    # Store layer references for grouped control - collect all non-None layers
    base_layers = {}
    try:
        base_layers['🗺️ Google Streets'] = tile_google_str.get_name()
        base_layers['🛰️ Google Satellite'] = tile_google_sat.get_name()
    except:
        pass
    if tile_offline_sat:
        base_layers['📴 Offline Satellite'] = tile_offline_sat.get_name()
    if tile_offline_str:
        base_layers['📴 Offline Streets'] = tile_offline_str.get_name()

    layer_refs = {
        'base': base_layers,
        'views': {
            '📊 Heat Map': heat_map.get_name(),
            '🔓 Open (clustered)': open_cluster.get_name(),
            '🔒 Secured (clustered)': secured_cluster.get_name(),
            '🔓 Open (all)': open_unclustered.get_name(),
            '🔒 Secured (all)': secured_unclustered.get_name(),
        },
        'types': {
            '👻 Hidden': hidden_group.get_name(),
            '🔌 IoT': iot_group.get_name(),
        },
        'risk': {
            '🔴 Critical': risk_critical.get_name(),
            '🟠 High': risk_high.get_name(),
            '🟡 Medium': risk_medium.get_name(),
            '🟢 Low': risk_low.get_name(),
        },
        'signal_strength': {
            '💚 Strong': signal_green.get_name(),
            '💚 Good': signal_lightgreen.get_name(),
            '💛 Fair': signal_beige.get_name(),
            '🧡 Moderate': signal_orange.get_name(),
            '🩷 Weak': signal_lightred.get_name(),
            '❤️ Very Weak': signal_red.get_name(),
        },
        'threat': {
            '🏢 Corporate': threat_corporate.get_name(),
            '🏠 Residential': threat_residential.get_name(),
            '🌐 Guest': threat_guest.get_name(),
            '📡 IoT': threat_iot.get_name(),
            '📶 Other Networks': threat_unknown.get_name(),
        },
        'tags': {
            '🎯 Primary Targets': tag_primary.get_name(),
            '📌 Secondary Targets': tag_secondary.get_name(),
            '⛔ Out of Scope': tag_out_of_scope.get_name(),
            f'🆕 New This Session ({new_session_count})': new_session_group.get_name(),
        },
        'gps_tracks': {data['label']: {'layer': data['group'].get_name(), 'color': data['color'], 'stats': data['stats'], 'polyline': data.get('polyline_name', ''), 'group_var': data.get('group_name', '')} for session_id, data in gps_tracks.items()},
        'sessions': {data['label']: data['group'].get_name() for session_id, data in session_groups.items()}
    }

    # Track coordinates to detect overlaps and add small offsets
    coord_counts = {}
    iot_count = 0  # Count identified IoT devices
    search_data = []  # Collect data for search functionality

    def create_marker(network, category='regular'):
        """Create a marker for a network and return it with metadata"""
        nonlocal coord_counts, iot_count

        # Handle schema evolution: 11 cols (old), 12 cols (with obs_count), 14 cols (with target_tag)
        if len(network) >= 14:
            mac, ssid, auth_mode, first_seen, channel, rssi, lat, lon, alt, acc, last_updated, obs_count, target_tag, target_notes = network[:14]
        elif len(network) >= 12:
            mac, ssid, auth_mode, first_seen, channel, rssi, lat, lon, alt, acc, last_updated, obs_count = network[:12]
            target_tag = None
            target_notes = None
        else:
            mac, ssid, auth_mode, first_seen, channel, rssi, lat, lon, alt, acc, last_updated = network[:11]
            obs_count = 1
            target_tag = None
            target_notes = None

        # Add tiny offset to prevent perfect stacking
        coord_key = f"{lat:.6f},{lon:.6f}"
        if coord_key in coord_counts:
            offset = coord_counts[coord_key] * 0.00002
            angle = coord_counts[coord_key] * 60
            lat_offset = offset * math.cos(math.radians(angle))
            lon_offset = offset * math.sin(math.radians(angle))
            lat += lat_offset
            lon += lon_offset
            coord_counts[coord_key] += 1
        else:
            coord_counts[coord_key] = 1

        # Determine marker color
        color = get_marker_color(rssi)
        signal_text = get_signal_strength_text(rssi)

        # Create popup content
        is_open = '[OPEN]' in auth_mode
        is_wep = '[WEP]' in auth_mode
        security_color = '#ff0000' if is_open or is_wep else '#333'
        security_warning = '<br><b style="color:red;">⚠️ NO PASSWORD!</b>' if is_open else ''
        if is_wep:
            security_warning = '<br><b style="color:red;">⚠️ WEP IS CRACKABLE!</b>'

        # Show if location is estimated vs single observation
        location_note = f"📍 Estimated from {obs_count} observations" if obs_count > 1 else "📍 Single observation"

        # Try to identify the device
        device_info = identify_device(ssid, auth_mode)
        device_section = ''
        is_iot = False

        if device_info:
            # NOT IoT: routers, gateways, APs, hotspots, business/commercial networks
            not_iot_types = [
                'Consumer Router', 'ISP Router', 'ISP Router (Setup)', 'ISP Hotspot',
                'Cable Modem', 'Cable Gateway', 'Cable Router', 'Cable Modem/Router',
                'Fiber Gateway', 'FiOS Router', 'Fiber/DSL Gateway', 'Gateway',
                'Mesh Router', 'WiFi Extender', 'Travel Router', 'Mobile Router',
                'LTE Home Router', 'Home Internet Gateway', 'ISP Router/Gateway',
                'Enterprise AP', 'Business AP', 'Commercial WiFi', 'Commercial Device',
                'Hotel WiFi', 'Restaurant WiFi', 'Retail WiFi', 'Educational WiFi',
                'Residential Network', 'WEP Encrypted', 'Mobile Hotspot', 'Phone Hotspot',
                'Vehicle Hotspot', 'Vehicle WiFi', 'Vehicle Entertainment', 'Vehicle Tuner',
                'Backup Camera', 'Hidden Network'
            ]
            device_type = device_info.get('type', '')
            if device_type and device_type not in not_iot_types:
                is_iot = True
                iot_count += 1
            vuln_badge = get_vuln_badge(device_info['vuln_level'])
            device_section = f'''
                <tr><td colspan="2" style="padding-top:8px;border-top:1px solid #ddd;">
                    <b style="color:#9b59b6;">🔍 DEVICE IDENTIFIED</b>
                </td></tr>
                <tr><td><b>Type:</b></td><td>{device_info['type']}</td></tr>
                <tr><td><b>Brand:</b></td><td>{device_info['brand']}</td></tr>
                <tr><td><b>Risk:</b></td><td>{vuln_badge}</td></tr>
                <tr><td colspan="2" style="padding-top:5px;">
                    <b>Description:</b><br>
                    <span style="color:#666;font-size:11px;">{device_info['desc']}</span>
                </td></tr>
                <tr><td colspan="2" style="padding-top:5px;">
                    <b style="color:#e74c3c;">💀 Exploit:</b><br>
                    <span style="color:#c0392b;font-size:11px;">{device_info['exploit']}</span>
                </td></tr>
                <tr><td colspan="2" style="padding-top:5px;">
                    <b>Setup/Access:</b><br>
                    <span style="color:#2980b9;font-size:11px;">{device_info['setup_url']}</span>
                </td></tr>
            '''

        # Category badge
        # XSS protection: escape SSID for HTML display (SSIDs can contain malicious content)
        safe_ssid = html.escape(ssid) if ssid else ''

        # Determine threat category BEFORE popup creation so we can include badge
        device_type_str = device_info.get('type', '') if device_info else ''
        threat_category = categorize_threat(ssid, device_type_str, auth_mode)
        threat_badge = get_threat_category_badge(threat_category)

        if category == 'hidden':
            category_badge = '<tr><td colspan="2"><b style="color:#666;">👻 Hidden Network</b></td></tr>'
            display_ssid = f"[Hidden: {mac[-8:]}]"
            # Add hidden network info
            device_section = f'''
                <tr><td colspan="2" style="padding-top:8px;border-top:1px solid #ddd;">
                    <b style="color:#9b59b6;">📡 HIDDEN NETWORK</b>
                </td></tr>
                <tr><td colspan="2" style="padding-top:5px;">
                    <b>How to connect:</b><br>
                    <span style="color:#666;font-size:11px;">
                    1. Go to WiFi settings<br>
                    2. "Add network" / "Other..."<br>
                    3. Enter SSID manually (need to know it)<br>
                    4. Select security type & password<br>
                    <br>
                    <b>Note:</b> Hidden SSIDs can be revealed with airodump-ng<br>
                    or by deauthing a client and capturing probe requests.
                    </span>
                </td></tr>
            '''
        elif category == 'vehicle':
            category_badge = '<tr><td colspan="2"><b style="color:#3498db;">🚗 Vehicle Hotspot</b></td></tr>'
            display_ssid = safe_ssid
        elif is_iot:
            category_badge = f'<tr><td colspan="2"><b style="color:#9b59b6;">🔌 IoT Device</b></td></tr>'
            display_ssid = safe_ssid
        else:
            category_badge = ''
            display_ssid = safe_ssid

        # Target tag badge and buttons
        tag_badge = ''
        tag_section = ''
        if target_tag:
            tag_colors = {
                'primary': ('#9b59b6', '🎯 Primary Target'),
                'secondary': ('#3498db', '📌 Secondary'),
                'out_of_scope': ('#95a5a6', '⛔ Out of Scope'),
                'custom': ('#27ae60', '🏷️ Tagged')
            }
            tag_color, tag_label = tag_colors.get(target_tag, ('#666', '🏷️ Tagged'))
            tag_badge = f'<span style="background:{tag_color};color:white;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:bold;margin-left:5px;">{tag_label}</span>'
            notes_display = f'<br><small style="color:#666;">Notes: {html.escape(target_notes)}</small>' if target_notes else ''
            tag_section = f'''
                <tr><td colspan="2" style="padding:8px 0;border-top:1px solid #eee;">
                    <div style="background:#f8f9fa;padding:8px;border-radius:4px;border-left:3px solid {tag_color};">
                        <b style="color:{tag_color};">{tag_label}</b>{notes_display}
                        <div style="margin-top:6px;">
                            <button onclick="window.parent.removeNetworkTag('{mac}')" style="background:#e74c3c;color:white;border:none;padding:4px 10px;border-radius:3px;cursor:pointer;font-size:11px;">Remove Tag</button>
                        </div>
                    </div>
                </td></tr>
            '''
        else:
            # Show tag buttons for untagged networks
            tag_section = f'''
                <tr><td colspan="2" style="padding:8px 0;border-top:1px solid #eee;">
                    <div style="display:flex;gap:4px;flex-wrap:wrap;">
                        <button onclick="window.parent.tagNetwork('{mac}','primary')" style="background:#9b59b6;color:white;border:none;padding:4px 8px;border-radius:3px;cursor:pointer;font-size:10px;">🎯 Primary</button>
                        <button onclick="window.parent.tagNetwork('{mac}','secondary')" style="background:#3498db;color:white;border:none;padding:4px 8px;border-radius:3px;cursor:pointer;font-size:10px;">📌 Secondary</button>
                        <button onclick="window.parent.tagNetwork('{mac}','out_of_scope')" style="background:#95a5a6;color:white;border:none;padding:4px 8px;border-radius:3px;cursor:pointer;font-size:10px;">⛔ Out of Scope</button>
                    </div>
                </td></tr>
            '''

        # Check if this network is new this session
        is_new_this_session = mac in new_this_session
        new_badge = ''
        if is_new_this_session:
            new_badge = '<div style="background: linear-gradient(135deg, #00d4ff 0%, #00ff88 100%); color: #000; font-weight: 700; padding: 6px 12px; border-radius: 6px; text-align: center; margin-bottom: 10px; font-size: 11px; box-shadow: 0 2px 8px rgba(0,212,255,0.4);">🆕 NEW THIS SESSION</div>'

        popup_html = f"""
        <div style="font-family: Arial; font-size: 12px; min-width: 250px; max-width: 350px;">
            {new_badge}
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap;">
                <h4 style="margin: 0; color: #333;">{display_ssid}</h4>
                <div>{tag_badge}{threat_badge}</div>
            </div>
            <table style="width: 100%; border-collapse: collapse;">
                {category_badge}
                <tr><td><b>MAC:</b></td><td style="font-family:monospace;font-size:11px;">{mac}</td></tr>
                <tr><td><b>Security:</b></td><td style="color:{security_color};">{auth_mode}{security_warning}</td></tr>
                <tr><td><b>Channel:</b></td><td>{channel}</td></tr>
                <tr><td><b>Best Signal:</b></td><td>{rssi} dBm ({signal_text})</td></tr>
                <tr><td><b>Observations:</b></td><td>{obs_count}</td></tr>
                <tr><td><b>First Seen:</b></td><td>{first_seen}</td></tr>
                <tr><td><b>Last Updated:</b></td><td>{last_updated}</td></tr>
                {device_section}
                <tr><td colspan="2" style="padding-top:5px;"><small>{location_note}</small></td></tr>
                {tag_section}
            </table>
        </div>
        """

        # Icon based on category, device type, and target tag
        if category == 'hidden':
            icon_name = 'question'
        elif category == 'vehicle':
            icon_name = 'car'
        elif device_info:
            # Use device-specific icon if available
            icon_name = device_info.get('icon', 'microchip')
        else:
            icon_name = 'wifi' if not is_open else 'unlock'

        # Override color and icon for tagged networks
        marker_color = color
        if target_tag == 'primary':
            marker_color = 'purple'
            icon_name = 'bullseye'  # Target icon for primary
        elif target_tag == 'secondary':
            marker_color = 'blue'
            icon_name = 'bookmark'
        elif target_tag == 'out_of_scope':
            marker_color = 'gray'
            icon_name = 'ban'

        icon = folium.Icon(
            color=marker_color,
            icon=icon_name,
            prefix='fa'
        )

        return {
            'lat': lat,
            'lon': lon,
            'popup_html': popup_html,
            'tooltip': f"{display_ssid} ({rssi} dBm)",
            'icon': icon,
            'is_open': is_open,
            'is_iot': is_iot,
            'rssi': rssi,
            'ssid': ssid,
            'mac': mac,
            'device_type': device_type_str,
            'brand': device_info.get('brand', '') if device_info else '',
            'risk': device_info.get('vuln_level', 'low') if device_info else 'low',
            'threat_category': threat_category,
            'target_tag': target_tag,
            'is_new_this_session': is_new_this_session
        }

    # Build network properties map for JavaScript filtering (NO DUPLICATES - property-based filtering)
    network_properties = {}

    # Add regular networks to both clustered and unclustered groups
    for network in networks:
        marker_data = create_marker(network, 'regular')
        mac = marker_data['mac']
        auth_mode = network[2] if len(network) > 2 else ''

        # Determine risk level from auth_mode
        if '[OPEN]' in auth_mode or '[WEP]' in auth_mode:
            risk_level = 'critical'
        elif 'WPA3' in auth_mode:
            risk_level = 'low'
        elif 'WPA2' in auth_mode:
            risk_level = 'medium'
        elif 'WPA' in auth_mode:
            risk_level = 'high'
        else:
            risk_level = 'low'

        # Determine signal strength category from RSSI
        rssi_val = marker_data.get('rssi', -100)
        if rssi_val >= -65:
            signal_category = 'strong'
        elif rssi_val >= -72:
            signal_category = 'good'
        elif rssi_val >= -78:
            signal_category = 'fair'
        elif rssi_val >= -84:
            signal_category = 'moderate'
        elif rssi_val >= -92:
            signal_category = 'weak'
        else:
            signal_category = 'very_weak'

        # Get session IDs this network was observed in
        session_ids = list(network_sessions.get(mac, []))

        # Store properties for JavaScript filtering
        network_properties[mac] = {
            'risk': risk_level,
            'signal': signal_category,
            'sessions': session_ids,
            'threat': marker_data['threat_category'],
            'tag': marker_data['target_tag'].lower() if marker_data['target_tag'] else None,
            'is_open': marker_data['is_open'],
            'is_hidden': False,
            'is_iot': marker_data.get('is_iot', False),
            'is_new': marker_data.get('is_new_this_session', False),
        }

        # Collect search data
        search_data.append({
            'ssid': marker_data['ssid'],
            'mac': marker_data['mac'],
            'type': marker_data['device_type'],
            'brand': marker_data['brand'],
            'lat': marker_data['lat'],
            'lon': marker_data['lon'],
            'popup': marker_data['popup_html']
        })

        # Add to clustered group (default view)
        target_cluster = open_cluster if marker_data['is_open'] else secured_cluster
        folium.Marker(
            location=[marker_data['lat'], marker_data['lon']],
            popup=folium.Popup(marker_data['popup_html'], max_width=350),
            tooltip=marker_data['tooltip'],
            icon=marker_data['icon']
        ).add_to(target_cluster)

        # Add to unclustered group (all markers visible when enabled)
        target_unclustered = open_unclustered if marker_data['is_open'] else secured_unclustered
        folium.Marker(
            location=[marker_data['lat'], marker_data['lon']],
            popup=folium.Popup(marker_data['popup_html'], max_width=350),
            tooltip=marker_data['tooltip'],
            icon=marker_data['icon']
        ).add_to(target_unclustered)

        # Also add IoT devices to the IoT group
        if marker_data.get('is_iot'):
            folium.Marker(
                location=[marker_data['lat'], marker_data['lon']],
                popup=folium.Popup(marker_data['popup_html'], max_width=350),
                tooltip=marker_data['tooltip'],
                icon=marker_data['icon']
            ).add_to(iot_group)

        # NO MORE DUPLICATE MARKERS - filtering handled by JavaScript

        # Add to "New This Session" group if network is new
        if marker_data.get('is_new_this_session'):
            folium.Marker(
                location=[marker_data['lat'], marker_data['lon']],
                popup=folium.Popup(marker_data['popup_html'], max_width=350),
                tooltip=marker_data['tooltip'],
                icon=marker_data['icon']
            ).add_to(new_session_group)

    # Add hidden networks
    for network in hidden_networks:
        marker_data = create_marker(network, 'hidden')
        mac = marker_data['mac']
        auth_mode = network[2] if len(network) > 2 else ''

        # Determine risk level
        if '[OPEN]' in auth_mode or '[WEP]' in auth_mode:
            risk_level = 'critical'
        else:
            risk_level = 'high'  # Hidden networks default to HIGH risk

        # Determine signal strength
        rssi_val = marker_data.get('rssi', -100)
        if rssi_val >= -65:
            signal_category = 'strong'
        elif rssi_val >= -72:
            signal_category = 'good'
        elif rssi_val >= -78:
            signal_category = 'fair'
        elif rssi_val >= -84:
            signal_category = 'moderate'
        elif rssi_val >= -92:
            signal_category = 'weak'
        else:
            signal_category = 'very_weak'

        # Get session IDs
        session_ids = list(network_sessions.get(mac, []))

        # Store properties for filtering
        network_properties[mac] = {
            'risk': risk_level,
            'signal': signal_category,
            'sessions': session_ids,
            'threat': marker_data['threat_category'],
            'tag': marker_data['target_tag'].lower() if marker_data['target_tag'] else None,
            'is_open': marker_data['is_open'],
            'is_hidden': True,
            'is_iot': marker_data.get('is_iot', False),
            'is_new': marker_data.get('is_new_this_session', False),
        }

        # Collect search data for hidden networks
        search_data.append({
            'ssid': marker_data['ssid'] or '[Hidden Network]',
            'mac': marker_data['mac'],
            'type': 'Hidden Network',
            'brand': marker_data['brand'],
            'lat': marker_data['lat'],
            'lon': marker_data['lon'],
            'popup': marker_data['popup_html']
        })
        folium.Marker(
            location=[marker_data['lat'], marker_data['lon']],
            popup=folium.Popup(marker_data['popup_html'], max_width=350),
            tooltip=marker_data['tooltip'],
            icon=marker_data['icon']
        ).add_to(hidden_group)

        # NO MORE DUPLICATE MARKERS FOR HIDDEN NETWORKS - filtering handled by JavaScript

    # Add fullscreen button
    plugins.Fullscreen().add_to(m)
    
    # Calculate statistics for dashboard (using filtered networks)
    open_networks = sum(1 for n in networks if '[OPEN]' in n[2])
    secured_networks = len(networks) - open_networks
    
    # Channel distribution
    channels = {}
    for n in networks:
        ch = n[4]
        channels[ch] = channels.get(ch, 0) + 1
    most_common_channel = max(channels, key=channels.get) if channels else 'N/A'
    
    # Signal strength stats
    rssi_values = [n[5] for n in networks]
    strongest_signal = max(rssi_values) if rssi_values else 'N/A'
    weakest_signal = min(rssi_values) if rssi_values else 'N/A'
    avg_signal = sum(rssi_values) / len(rssi_values) if rssi_values else 0
    
    # We'll add a custom grouped layer control via JavaScript instead of the default

    # Add collapsible legend at TOP RIGHT - collapsed by default
    legend_html = '''
    <div id="legend-panel" style="position: fixed;
                top: 10px; right: 10px; width: 220px;
                background-color: white; border:2px solid grey; z-index:9999;
                font-size:12px; border-radius: 5px;
                box-shadow: 0 0 15px rgba(0,0,0,0.2);">
        <div onclick="document.getElementById('legend-content').style.display = document.getElementById('legend-content').style.display === 'none' ? 'block' : 'none'; document.getElementById('legend-toggle').textContent = document.getElementById('legend-content').style.display === 'none' ? '▶' : '▼';"
             style="padding: 8px 10px; cursor: pointer; background: #f8f9fa; border-radius: 5px; border-bottom: 1px solid #ddd;">
            <span id="legend-toggle" style="margin-right: 5px;">▶</span>
            <b>Signal Strength</b>
        </div>
        <div id="legend-content" style="padding: 10px; display: none;">
            <p style="margin:3px 0;"><i class="fa fa-map-marker" style="color:#2ecc71"></i> -65+ dBm (Strong)</p>
            <p style="margin:3px 0;"><i class="fa fa-map-marker" style="color:#90EE90"></i> -72 to -66 (Good)</p>
            <p style="margin:3px 0;"><i class="fa fa-map-marker" style="color:#F5DEB3"></i> -78 to -73 (Fair)</p>
            <p style="margin:3px 0;"><i class="fa fa-map-marker" style="color:#FFA500"></i> -84 to -79 (Moderate)</p>
            <p style="margin:3px 0;"><i class="fa fa-map-marker" style="color:#FF6B6B"></i> -92 to -85 (Weak)</p>
            <p style="margin:3px 0;"><i class="fa fa-map-marker" style="color:#FF0000"></i> Below -92 (Very Weak)</p>
            <hr style="margin: 8px 0;">
            <p style="margin:3px 0;"><i class="fa fa-unlock" style="color:red"></i> Open Network</p>
            <p style="margin:3px 0;"><i class="fa fa-question" style="color:#666"></i> Hidden Network</p>
            <p style="margin:3px 0; font-size:10px; color:#666; padding-top:5px;">📍 Locations estimated via triangulation</p>
        </div>
    </div>
    '''
    m.get_root().html.add_child(folium.Element(legend_html))

    # Add collapsible statistics dashboard at TOP LEFT - collapsed by default
    stats_html = f'''
    <div id="stats-panel" style="position: fixed;
                top: 10px; left: 10px; width: 260px;
                background-color: white; border:2px solid grey; z-index:9999;
                font-size:13px; border-radius: 5px;
                box-shadow: 0 0 15px rgba(0,0,0,0.2);">
        <div onclick="document.getElementById('stats-content').style.display = document.getElementById('stats-content').style.display === 'none' ? 'block' : 'none'; document.getElementById('stats-toggle').textContent = document.getElementById('stats-content').style.display === 'none' ? '▶' : '▼';"
             style="padding: 8px 10px; cursor: pointer; background: #f8f9fa; border-radius: 5px; border-bottom: 1px solid #ddd;">
            <span id="stats-toggle" style="margin-right: 5px;">▶</span>
            <b>📊 Wardrive Statistics</b>
        </div>
        <div id="stats-content" style="padding: 10px; display: none;">
            <table style="width: 100%; font-size: 12px;">
                <tr><td><b>Regular Networks:</b></td><td>{len(networks)}</td></tr>
                <tr><td><b>🔒 Secured:</b></td><td>{secured_networks}</td></tr>
                <tr><td><b>🔓 Open:</b></td><td style="color:red;">{open_networks}</td></tr>
                <tr><td colspan="2"><hr style="margin: 5px 0;"></td></tr>
                <tr><td><b>👻 Hidden:</b></td><td>{len(hidden_networks)}</td></tr>
                <tr><td><b>🔌 IoT Devices:</b></td><td style="color:#9b59b6;">{iot_count}</td></tr>
                <tr><td><b>📡 Total APs:</b></td><td><b>{len(networks) + len(hidden_networks)}</b></td></tr>
                <tr><td colspan="2"><hr style="margin: 5px 0;"></td></tr>
                <tr><td><b>Most Used Ch:</b></td><td>{most_common_channel}</td></tr>
                <tr><td><b>Strongest:</b></td><td>{strongest_signal} dBm</td></tr>
                <tr><td><b>Weakest:</b></td><td>{weakest_signal} dBm</td></tr>
                <tr><td><b>Average:</b></td><td>{avg_signal:.1f} dBm</td></tr>
            </table>
        </div>
    </div>
    '''
    m.get_root().html.add_child(folium.Element(stats_html))

    # Add search box with autocomplete
    import json
    search_data_json = json.dumps(search_data)
    network_properties_json = json.dumps(network_properties)

    # Create session name -> ID mapping for JavaScript
    session_id_mapping = {data['label']: session_id for session_id, data in session_groups.items()}
    session_id_mapping_json = json.dumps(session_id_mapping)

    search_html = f'''
    <div id="search-panel" style="position: fixed;
                top: 55px; left: 10px; width: 300px;
                z-index:9990;">
        <div style="background-color: white; border:2px solid grey; border-radius: 5px;
                    box-shadow: 0 0 15px rgba(0,0,0,0.2);">
            <input type="text" id="network-search"
                   placeholder="🔍 Search SSID, MAC, type, brand..."
                   style="width: 100%; padding: 10px; border: none; border-radius: 5px;
                          font-size: 14px; box-sizing: border-box;"
                   autocomplete="off">
            <div id="search-results" style="max-height: 400px; overflow-y: auto; display: none;
                                           border-top: 1px solid #ddd;"></div>
        </div>
    </div>

    <script>
    // Global scope so filter script can access these
    var networkProperties = {network_properties_json};
    var sessionIdMapping = {session_id_mapping_json};
    (function() {{
        var searchData = {search_data_json};
        var searchInput = document.getElementById('network-search');
        var resultsDiv = document.getElementById('search-results');
        var currentPopup = null;

        // Get the map object (folium names it with a hash)
        var mapObj = null;
        for (var key in window) {{
            if (key.startsWith('map_') && window[key] instanceof L.Map) {{
                mapObj = window[key];
                break;
            }}
        }}

        searchInput.addEventListener('input', function() {{
            var query = this.value.toLowerCase().trim();

            if (query.length === 0) {{
                resultsDiv.style.display = 'none';
                resultsDiv.innerHTML = '';
                return;
            }}

            // Split query into words for word-based matching
            var queryWords = query.split(/\\s+/).filter(function(w) {{ return w.length > 0; }});

            // Score and filter results
            var scored = [];
            searchData.forEach(function(item) {{
                var ssidLower = (item.ssid || '').toLowerCase();
                var macLower = (item.mac || '').toLowerCase();
                var typeLower = (item.type || '').toLowerCase();
                var brandLower = (item.brand || '').toLowerCase();

                // Check if ANY query word matches ANY field
                var matched = false;
                var score = 0;

                for (var i = 0; i < queryWords.length; i++) {{
                    var word = queryWords[i];

                    // SSID matching (highest priority)
                    if (ssidLower === word) {{
                        score += 1000;  // Exact match
                        matched = true;
                    }} else if (ssidLower.startsWith(word)) {{
                        score += 500;   // Starts with
                        matched = true;
                    }} else if (ssidLower.includes(word)) {{
                        score += 100;   // Contains
                        matched = true;
                    }}

                    // MAC matching
                    if (macLower.includes(word)) {{
                        score += 50;
                        matched = true;
                    }}

                    // Type matching (lower priority)
                    if (typeLower.includes(word)) {{
                        score += 10;
                        matched = true;
                    }}

                    // Brand matching (lower priority)
                    if (brandLower.includes(word)) {{
                        score += 10;
                        matched = true;
                    }}
                }}

                if (matched) {{
                    scored.push({{item: item, score: score}});
                }}
            }});

            // Sort by score (highest first) and take top 15
            scored.sort(function(a, b) {{ return b.score - a.score; }});
            var matches = scored.slice(0, 15).map(function(s) {{ return s.item; }});

            if (matches.length === 0) {{
                resultsDiv.innerHTML = '<div style="padding: 10px; color: #666;">No results found</div>';
                resultsDiv.style.display = 'block';
                return;
            }}

            // Build results HTML
            var html = '';
            matches.forEach(function(item, index) {{
                var displayName = item.ssid || '[Hidden]';
                var subtitle = [];
                if (item.type) subtitle.push(item.type);
                if (item.brand && item.brand !== 'Unknown') subtitle.push(item.brand);
                var subtitleText = subtitle.length > 0 ? subtitle.join(' - ') : item.mac;

                html += '<div class="search-result" data-index="' + index + '" ' +
                        'style="padding: 8px 10px; cursor: pointer; border-bottom: 1px solid #eee;" ' +
                        'onmouseover="this.style.backgroundColor=\\'#f0f0f0\\'" ' +
                        'onmouseout="this.style.backgroundColor=\\'white\\'">' +
                        '<div style="font-weight: bold; font-size: 13px;">' + escapeHtml(displayName) + '</div>' +
                        '<div style="font-size: 11px; color: #666;">' + escapeHtml(subtitleText) + '</div>' +
                        '</div>';
            }});

            resultsDiv.innerHTML = html;
            resultsDiv.style.display = 'block';

            // Add click handlers to results
            var resultElements = resultsDiv.querySelectorAll('.search-result');
            resultElements.forEach(function(el) {{
                el.addEventListener('click', function() {{
                    var idx = parseInt(this.getAttribute('data-index'));
                    var item = matches[idx];

                    // Close any existing popup
                    if (currentPopup) {{
                        mapObj.closePopup(currentPopup);
                    }}

                    // Zoom to location
                    mapObj.setView([item.lat, item.lon], 18);

                    // Create and open popup
                    currentPopup = L.popup({{maxWidth: 350}})
                        .setLatLng([item.lat, item.lon])
                        .setContent(item.popup)
                        .openOn(mapObj);

                    // Clear search
                    searchInput.value = '';
                    resultsDiv.style.display = 'none';
                    resultsDiv.innerHTML = '';
                }});
            }});
        }});

        // Close results when clicking outside
        document.addEventListener('click', function(e) {{
            if (!searchInput.contains(e.target) && !resultsDiv.contains(e.target)) {{
                resultsDiv.style.display = 'none';
            }}
        }});

        // Helper function to escape HTML
        function escapeHtml(text) {{
            if (!text) return '';
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
    }})();
    </script>
    '''
    m.get_root().html.add_child(folium.Element(search_html))

    # Build JavaScript for grouped layer control using actual variable names from Python
    import json

    # Build base layers JS object
    base_js_parts = []
    for name, var_name in layer_refs['base'].items():
        if var_name:
            base_js_parts.append(f'"{name}": {var_name}')
    base_js = '{' + ', '.join(base_js_parts) + '}'

    # Build grouped overlays JS object
    views_js_parts = []
    for name, var_name in layer_refs['views'].items():
        views_js_parts.append(f'"{name}": {var_name}')

    types_js_parts = []
    for name, var_name in layer_refs['types'].items():
        types_js_parts.append(f'"{name}": {var_name}')

    risk_js_parts = []
    for name, var_name in layer_refs['risk'].items():
        risk_js_parts.append(f'"{name}": {var_name}')

    signal_js_parts = []
    for name, var_name in layer_refs['signal_strength'].items():
        signal_js_parts.append(f'"{name}": {var_name}')

    threat_js_parts = []
    for name, var_name in layer_refs['threat'].items():
        threat_js_parts.append(f'"{name}": {var_name}')

    tag_js_parts = []
    for name, var_name in layer_refs['tags'].items():
        tag_js_parts.append(f'"{name}": {var_name}')

    # GPS track layers with stats
    gps_track_js_parts = []
    for name, data in layer_refs.get('gps_tracks', {}).items():
        var_name = data['layer']
        color = data['color']
        stats = data['stats']
        gps_track_js_parts.append(f'"{name}": {{"layer": {var_name}, "color": "{color}", "distance": {stats["distance"]}, "duration": "{stats["duration_str"]}", "speed": {stats["avg_speed"]}, "points": {stats["point_count"]}}}')

    session_js_parts = []
    for name, var_name in layer_refs['sessions'].items():
        session_js_parts.append(f'"{name}": {var_name}')

    grouped_control_html = f'''
    <style>
        #custom-layer-control {{
            position: fixed;
            bottom: 10px;
            left: 10px;
            background: white;
            border: 2px solid rgba(0,0,0,0.2);
            border-radius: 5px;
            padding: 0;
            font-size: 12px;
            max-height: 80vh;
            overflow-y: auto;
            z-index: 1000;
            box-shadow: 0 1px 5px rgba(0,0,0,0.4);
            min-width: 200px;
        }}
        .layer-group {{
            border-bottom: 1px solid #ddd;
        }}
        .layer-group:last-child {{
            border-bottom: none;
        }}
        .layer-group-header {{
            font-weight: bold;
            padding: 8px 10px;
            cursor: pointer;
            background: #f8f8f8;
            user-select: none;
        }}
        .layer-group-header:hover {{
            background: #eee;
        }}
        .layer-group-header::before {{
            content: "▼ ";
            font-size: 10px;
        }}
        .layer-group.collapsed .layer-group-header::before {{
            content: "▶ ";
        }}
        .layer-group-content {{
            padding: 5px 10px;
        }}
        .layer-group.collapsed .layer-group-content {{
            display: none;
        }}
        .layer-item {{
            display: block;
            padding: 3px 0;
            cursor: pointer;
        }}
        .layer-item:hover {{
            background: #f0f0f0;
        }}
        .layer-item input {{
            margin-right: 6px;
        }}
    </style>
    <div id="custom-layer-control">
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">🗺️ Base Maps</div>
            <div class="layer-group-content" id="base-layers"></div>
        </div>
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">📺 Views</div>
            <div class="layer-group-content" id="view-layers"></div>
        </div>
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">📡 Network Types</div>
            <div class="layer-group-content" id="type-layers"></div>
        </div>
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">⚠️ Risk Levels</div>
            <div class="layer-group-content" id="risk-layers"></div>
        </div>
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">📡 Signal Strength</div>
            <div class="layer-group-content" id="signal-layers"></div>
        </div>
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">📊 Threat Categories</div>
            <div class="layer-group-content" id="threat-layers"></div>
        </div>
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">🏷️ Target Tags</div>
            <div class="layer-group-content" id="tag-layers"></div>
        </div>
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">🛣️ GPS Tracks</div>
            <div class="layer-group-content" id="gps-track-layers"></div>
        </div>
        <div class="layer-group collapsed">
            <div class="layer-group-header" onclick="this.parentElement.classList.toggle('collapsed')">📅 Sessions</div>
            <div class="layer-group-content" id="session-layers"></div>
        </div>
    </div>
    <script>
    (function() {{
        function initLayerControl() {{
            var mapEl = document.querySelector('.folium-map');
            if (!mapEl) {{ setTimeout(initLayerControl, 1000); return; }}
            var map = window[mapEl.id];
            if (!map) {{ setTimeout(initLayerControl, 1000); return; }}

            // Layer definitions - retry if Folium variables not ready yet
            try {{
                var baseLayers = {base_js};
                var viewLayers = {{ {', '.join(views_js_parts)} }};
                var typeLayers = {{ {', '.join(types_js_parts)} }};
                var riskLayers = {{ {', '.join(risk_js_parts)} }};
                var signalLayers = {{ {', '.join(signal_js_parts)} }};
                var threatLayers = {{ {', '.join(threat_js_parts)} }};
                var tagLayers = {{ {', '.join(tag_js_parts)} }};
            }} catch(e) {{
                console.log('Waiting for map layers to load...');
                setTimeout(initLayerControl, 1000);
                return;
            }}
            var gpsTrackLayers = {{ {', '.join(gps_track_js_parts) if gps_track_js_parts else ''} }};
            var sessionLayers = {{ {', '.join(session_js_parts)} }};

            // Current base layer
            var currentBase = Object.keys(baseLayers)[0];

            // Populate base layers (radio buttons)
            var baseDiv = document.getElementById('base-layers');
            for (var name in baseLayers) {{
                var label = document.createElement('label');
                label.className = 'layer-item';
                var input = document.createElement('input');
                input.type = 'radio';
                input.name = 'base-layer';
                input.checked = (name === currentBase);
                input.onchange = (function(layerName) {{
                    return function() {{
                        for (var n in baseLayers) {{
                            if (n === layerName) {{
                                map.addLayer(baseLayers[n]);
                            }} else {{
                                map.removeLayer(baseLayers[n]);
                            }}
                        }}
                    }};
                }})(name);
                label.appendChild(input);
                label.appendChild(document.createTextNode(name));
                baseDiv.appendChild(label);
            }}

            // Helper to populate checkbox layers (simple - no cluster hiding)
            function populateCheckboxes(container, layers) {{
                for (var name in layers) {{
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    var isOn = map.hasLayer(layers[name]);
                    input.checked = isOn;
                    input.onchange = (function(layer) {{
                        return function() {{
                            if (this.checked) {{
                                map.addLayer(layer);
                            }} else {{
                                map.removeLayer(layer);
                            }}
                        }};
                    }})(layers[name]);
                    label.appendChild(input);
                    label.appendChild(document.createTextNode(name));
                    container.appendChild(label);
                }}
            }}

            // Track type/risk/session filter checkboxes for cluster hiding
            var typeCheckboxes = [];
            var riskCheckboxes = [];
            var threatCheckboxes = [];
            var tagCheckboxes = [];
            var allMarkersCheckboxes = [];
            var sessionCheckboxes = [];
            var viewLayerCheckboxes = [];  // Track view layer checkboxes

            // Helper: Check if any session filter is active
            function anySessionActive() {{
                return sessionCheckboxes.some(function(item) {{ return item.checked; }});
            }}

            // Helper: Check if any type or risk or threat or tag filter or "all markers" view is active
            function anyFilterActive() {{
                return typeCheckboxes.some(function(item) {{ return item.checked; }}) ||
                       riskCheckboxes.some(function(item) {{ return item.checked; }}) ||
                       threatCheckboxes.some(function(item) {{ return item.checked; }}) ||
                       tagCheckboxes.some(function(item) {{ return item.checked; }}) ||
                       allMarkersCheckboxes.some(function(item) {{ return item.checked; }}) ||
                       anySessionActive();
            }}

            // Helper: Hide clustered AND all marker views when sessions are active
            function updateClusterVisibility() {{
                var sessionsActive = anySessionActive();
                var filtersActive = anyFilterActive();

                for (var name in viewLayers) {{
                    // When sessions are checked, hide ALL open/secured layers (clustered and all)
                    if (sessionsActive) {{
                        if (name.includes('Open') || name.includes('Secured')) {{
                            map.removeLayer(viewLayers[name]);
                            var cb = document.querySelector('#view-layers input[data-layer="' + name + '"]');
                            if (cb) cb.checked = false;
                        }}
                    }} else if (name.includes('clustered')) {{
                        // No sessions active - restore clustered views unless other filters active
                        if (filtersActive) {{
                            map.removeLayer(viewLayers[name]);
                        }} else {{
                            map.addLayer(viewLayers[name]);
                        }}
                        var cb = document.querySelector('#view-layers input[data-layer="' + name + '"]');
                        if (cb) cb.checked = !filtersActive;
                    }}
                }}
            }}

            // Populate type layers with cluster hiding
            function populateFilterCheckboxes(container, layers, checkboxArray) {{
                for (var name in layers) {{
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    var isOn = map.hasLayer(layers[name]);
                    input.checked = isOn;
                    input.onchange = (function(layer) {{
                        return function() {{
                            if (this.checked) {{
                                map.addLayer(layer);
                            }} else {{
                                map.removeLayer(layer);
                            }}
                        }};
                    }})(layers[name]);
                    checkboxArray.push(input);
                    label.appendChild(input);
                    label.appendChild(document.createTextNode(name));
                    container.appendChild(label);
                }}
            }}

            // Populate view layers with data attribute for updating
            (function() {{
                var container = document.getElementById('view-layers');
                for (var name in viewLayers) {{
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    input.setAttribute('data-layer', name);
                    var isOn = map.hasLayer(viewLayers[name]);
                    input.checked = isOn;

                    // Track "all markers" checkboxes
                    var isAllMarkers = name.includes('(all)');
                    if (isAllMarkers) {{
                        allMarkersCheckboxes.push(input);
                    }}

                    input.onchange = (function(layer, layerName, isAll) {{
                        return function() {{
                            if (this.checked) {{
                                map.addLayer(layer);
                            }} else {{
                                map.removeLayer(layer);
                            }}
                            // If this is an "all markers" checkbox, update cluster visibility
                            if (isAll) {{
                                updateClusterVisibility();
                            }}
                        }};
                    }})(viewLayers[name], name, isAllMarkers);
                    label.appendChild(input);
                    label.appendChild(document.createTextNode(name));
                    container.appendChild(label);
                }}
            }})();

            // Helper: Extract MAC from marker popup
            function getMACFromMarker(marker) {{
                try {{
                    var popup = marker.getPopup();
                    if (!popup) return null;
                    var content = popup.getContent();
                    // Folium popups use jQuery DOM elements, not strings
                    var html;
                    if (typeof content === 'string') {{
                        html = content;
                    }} else if (content instanceof HTMLElement) {{
                        html = content.innerHTML;
                    }} else if (content && content[0] && content[0].innerHTML) {{
                        // jQuery object - get first element's HTML
                        html = content[0].innerHTML;
                    }} else {{
                        return null;
                    }}
                    var match = html.match(/MAC:<\\/b><\\/td><td[^>]*>([0-9A-F:]{{17}})/i);
                    return match ? match[1].toUpperCase() : null;
                }} catch(e) {{
                    return null;
                }}
            }}

            // Store all markers with their parent groups for filtering
            var allMarkers = [];
            function cacheAllMarkers() {{
                // MarkerCluster groups need getAllChildMarkers() to enumerate individual markers
                var clusterGroups = [
                    viewLayers['🔓 Open (clustered)'],
                    viewLayers['🔒 Secured (clustered)']
                ];
                var clusterCount = 0;
                clusterGroups.forEach(function(group) {{
                    if (!group) return;
                    var markers = [];
                    if (group.getAllChildMarkers) {{
                        markers = group.getAllChildMarkers();
                    }}
                    if (markers.length === 0 && group.getLayers) {{
                        markers = group.getLayers();
                    }}
                    markers.forEach(function(marker) {{
                        if (!marker.getPopup) return;
                        var mac = getMACFromMarker(marker);
                        if (mac && networkProperties[mac]) {{
                            allMarkers.push({{
                                marker: marker,
                                group: group,
                                mac: mac,
                                props: networkProperties[mac]
                            }});
                            clusterCount++;
                        }}
                    }});
                }});

                // Regular FeatureGroups work with eachLayer()
                var featureGroups = [
                    viewLayers['🔓 Open (all)'],
                    viewLayers['🔒 Secured (all)'],
                    typeLayers['👻 Hidden'],
                    typeLayers['🔌 IoT']
                ];
                featureGroups.forEach(function(group) {{
                    if (!group) return;
                    group.eachLayer(function(marker) {{
                        var mac = getMACFromMarker(marker);
                        if (mac && networkProperties[mac]) {{
                            allMarkers.push({{
                                marker: marker,
                                group: group,
                                mac: mac,
                                props: networkProperties[mac]
                            }});
                        }}
                    }});
                }});
                var featureCount = allMarkers.length - clusterCount;
                console.log('FILTER TOTAL: ' + allMarkers.length + ' (clusters: ' + clusterCount + ', features: ' + featureCount + ')');
            }}

            // Active filters
            var activeFilters = {{
                risk: new Set(),      // HIDDEN risk levels
                signal: new Set(),    // HIDDEN signal levels
                threat: new Set(),    // HIDDEN threat categories
                tag: new Set(),       // SHOWN tags (if empty, show all)
                sessions: new Set()   // SHOWN sessions (if empty, show all)
            }};

            // Apply all active filters - clear and rebuild clusters for reliable visual update
            function applyFilters() {{
                // Determine which markers pass the filter
                var clusterShow = {{}};  // gid -> [markers to show]
                var clusterAll = {{}};   // gid -> group reference

                allMarkers.forEach(function(item) {{
                    var props = item.props;
                    var shouldShow = true;

                    // Risk filter - hide if unchecked
                    if (activeFilters.risk.has(props.risk)) shouldShow = false;

                    // Signal filter - hide if unchecked
                    if (activeFilters.signal.has(props.signal)) shouldShow = false;

                    // Threat filter - hide if unchecked
                    if (props.threat && activeFilters.threat.has(props.threat)) shouldShow = false;

                    // Tag filter - positive filter (if any checked, show only matching)
                    if (activeFilters.tag.size > 0) {{
                        var tagVal = props.tag || 'untagged';
                        if (!activeFilters.tag.has(tagVal)) shouldShow = false;
                    }}

                    // Session filter - positive filter (if any checked, show only matching)
                    if (activeFilters.sessions.size > 0) {{
                        var inSession = props.sessions && props.sessions.some(function(sid) {{
                            return activeFilters.sessions.has(sid);
                        }});
                        if (!inSession) shouldShow = false;
                    }}

                    var gid = L.Util.stamp(item.group);
                    if (!clusterAll[gid]) {{
                        clusterAll[gid] = item.group;
                        clusterShow[gid] = [];
                    }}

                    if (shouldShow) {{
                        clusterShow[gid].push(item.marker);
                    }}
                }});

                // For each group: clear all markers then add back only visible ones
                for (var gid in clusterAll) {{
                    var group = clusterAll[gid];
                    if (group.clearLayers) {{
                        group.clearLayers();
                        if (clusterShow[gid].length > 0) {{
                            if (group.addLayers) {{
                                group.addLayers(clusterShow[gid]);
                            }} else {{
                                clusterShow[gid].forEach(function(m) {{ group.addLayer(m); }});
                            }}
                        }}
                    }} else {{
                        // Fallback for non-standard groups
                        group.eachLayer(function(m) {{ group.removeLayer(m); }});
                        clusterShow[gid].forEach(function(m) {{ group.addLayer(m); }});
                    }}
                }}
            }}

            // Populate Risk checkboxes with property-based filtering
            (function() {{
                var container = document.getElementById('risk-layers');
                var riskLevels = [
                    {{name: '🔴 CRITICAL', value: 'critical'}},
                    {{name: '🟠 HIGH', value: 'high'}},
                    {{name: '🟡 MEDIUM', value: 'medium'}},
                    {{name: '🟢 LOW', value: 'low'}}
                ];

                riskLevels.forEach(function(level) {{
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    input.checked = true;  // All visible by default

                    input.onchange = function() {{
                        if (this.checked) {{
                            activeFilters.risk.delete(level.value);
                        }} else {{
                            activeFilters.risk.add(level.value);
                        }}
                        applyFilters();
                    }};

                    riskCheckboxes.push(input);
                    label.appendChild(input);
                    label.appendChild(document.createTextNode(' ' + level.name));
                    container.appendChild(label);
                }});
            }})();

            // Populate Signal checkboxes with property-based filtering
            (function() {{
                var container = document.getElementById('signal-layers');
                var signalLevels = [
                    {{name: '💚 Strong (≥ -65 dBm)', value: 'strong'}},
                    {{name: '💚 Good (-72 to -65 dBm)', value: 'good'}},
                    {{name: '💛 Fair (-78 to -72 dBm)', value: 'fair'}},
                    {{name: '🧡 Moderate (-84 to -78 dBm)', value: 'moderate'}},
                    {{name: '🩷 Weak (-92 to -84 dBm)', value: 'weak'}},
                    {{name: '❤️ Very Weak (< -92 dBm)', value: 'very_weak'}}
                ];

                signalLevels.forEach(function(level) {{
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    input.checked = true;  // All visible by default

                    input.onchange = function() {{
                        if (this.checked) {{
                            activeFilters.signal.delete(level.value);
                        }} else {{
                            activeFilters.signal.add(level.value);
                        }}
                        applyFilters();
                    }};

                    label.appendChild(input);
                    label.appendChild(document.createTextNode(' ' + level.name));
                    container.appendChild(label);
                }});
            }})();

            populateFilterCheckboxes(document.getElementById('type-layers'), typeLayers, typeCheckboxes);

            // Populate threat category checkboxes with property-based filtering
            (function() {{
                var container = document.getElementById('threat-layers');
                var categories = [
                    {{name: '🏢 Corporate', value: 'corporate'}},
                    {{name: '🏠 Residential', value: 'residential'}},
                    {{name: '🌐 Guest', value: 'guest'}},
                    {{name: '📡 IoT/Vulnerable', value: 'iot'}},
                    {{name: '📶 Other Networks', value: 'unknown'}}
                ];
                categories.forEach(function(cat) {{
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    input.checked = true;  // All visible by default
                    input.onchange = function() {{
                        if (this.checked) {{
                            activeFilters.threat.delete(cat.value);
                        }} else {{
                            activeFilters.threat.add(cat.value);
                        }}
                        applyFilters();
                    }};
                    threatCheckboxes.push(input);
                    label.appendChild(input);
                    label.appendChild(document.createTextNode(' ' + cat.name));
                    container.appendChild(label);
                }});
            }})();

            // Populate target tag checkboxes with property-based filtering
            (function() {{
                var container = document.getElementById('tag-layers');
                var tags = [
                    {{name: '🎯 Primary Targets', value: 'primary'}},
                    {{name: '📌 Secondary Targets', value: 'secondary'}},
                    {{name: '⛔ Out of Scope', value: 'out_of_scope'}}
                ];
                tags.forEach(function(t) {{
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    input.checked = false;  // OFF by default - positive filter
                    input.onchange = function() {{
                        if (this.checked) {{
                            activeFilters.tag.add(t.value);
                        }} else {{
                            activeFilters.tag.delete(t.value);
                        }}
                        applyFilters();
                    }};
                    tagCheckboxes.push(input);
                    label.appendChild(input);
                    label.appendChild(document.createTextNode(' ' + t.name));
                    container.appendChild(label);
                }});
            }})();

            // Populate GPS track layers with color swatches and stats
            (function() {{
                var container = document.getElementById('gps-track-layers');
                for (var name in gpsTrackLayers) {{
                    var trackData = gpsTrackLayers[name];
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    label.style.display = 'flex';
                    label.style.alignItems = 'center';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    var isOn = map.hasLayer(trackData.layer);
                    input.checked = isOn;
                    input.onchange = (function(layer, stats) {{
                        return function() {{
                            if (this.checked) {{
                                map.addLayer(layer);
                                updateGpsStatsPanel();
                            }} else {{
                                map.removeLayer(layer);
                                updateGpsStatsPanel();
                            }}
                        }};
                    }})(trackData.layer, trackData);
                    label.appendChild(input);

                    // Color swatch
                    var swatch = document.createElement('span');
                    swatch.style.cssText = 'width: 12px; height: 3px; background: ' + trackData.color + '; display: inline-block; margin: 0 5px;';
                    label.appendChild(swatch);

                    // Name with stats on hover
                    var text = document.createElement('span');
                    text.textContent = name;
                    text.title = trackData.distance + ' mi | ' + trackData.duration + ' | ' + trackData.speed + ' mph';
                    label.appendChild(text);
                    container.appendChild(label);
                }}
            }})();

            // GPS Track stats panel (bottom-left)
            function updateGpsStatsPanel() {{
                var panel = document.getElementById('gps-track-stats');
                if (!panel) return;

                var activeCount = 0;
                var totalDistance = 0;
                var statsHtml = '';

                for (var name in gpsTrackLayers) {{
                    var trackData = gpsTrackLayers[name];
                    if (map.hasLayer(trackData.layer)) {{
                        activeCount++;
                        totalDistance += trackData.distance;
                        statsHtml += '<div style="margin: 5px 0; font-size: 11px;">';
                        statsHtml += '<span style="width: 12px; height: 3px; background: ' + trackData.color + '; display: inline-block; margin-right: 5px;"></span>';
                        statsHtml += '<b>' + name.replace('🛣️ ', '') + '</b><br>';
                        statsHtml += '<span style="margin-left: 17px; color: #666;">' + trackData.distance + ' mi | ' + trackData.duration + '</span>';
                        statsHtml += '</div>';
                    }}
                }}

                if (activeCount > 0) {{
                    panel.style.display = 'block';
                    var content = '<b>📍 GPS Tracks Active</b><br>' + statsHtml;
                    if (activeCount > 1) {{
                        content += '<hr style="margin: 5px 0; border-color: #ddd;"><b>Total:</b> ' + totalDistance.toFixed(2) + ' miles';
                    }}
                    panel.querySelector('.stats-content').innerHTML = content;
                }} else {{
                    panel.style.display = 'none';
                }}
            }}

            // Populate Session checkboxes with property-based filtering
            (function() {{
                var container = document.getElementById('session-layers');

                for (var name in sessionLayers) {{
                    var label = document.createElement('label');
                    label.className = 'layer-item';
                    var input = document.createElement('input');
                    input.type = 'checkbox';
                    input.checked = false;  // All OFF by default
                    var sessionId = sessionIdMapping[name];

                    input.onchange = function(sid) {{
                        return function() {{
                            if (this.checked) {{
                                activeFilters.sessions.add(sid);
                            }} else {{
                                activeFilters.sessions.delete(sid);
                            }}
                            applyFilters();
                        }};
                    }}(sessionId);

                    sessionCheckboxes.push(input);
                    label.appendChild(input);
                    label.appendChild(document.createTextNode(' ' + name));
                    container.appendChild(label);
                }}
            }})();

            // Cache all markers and set up filtering
            setTimeout(function() {{
                cacheAllMarkers();
            }}, 2000);

        }}
        // Start initialization - retries automatically until Folium layers are ready
        setTimeout(initLayerControl, 2000);
    }})();
    </script>

    <!-- GPS Track Stats Panel -->
    <div id="gps-track-stats" style="
        display: none;
        position: fixed;
        bottom: 10px;
        right: 10px;
        background: white;
        border: 2px solid #333;
        border-radius: 5px;
        padding: 10px;
        font-size: 12px;
        z-index: 999;
        max-width: 250px;
        box-shadow: 0 0 10px rgba(0,0,0,0.3);
    ">
        <div class="stats-content"></div>
    </div>
    '''
    m.get_root().html.add_child(folium.Element(grouped_control_html))

    # ========== GEOFENCE DRAWING CONTROLS ==========
    # Add Leaflet.draw library and geofence drawing/management UI
    geofence_html = '''
    <!-- Leaflet.draw CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet.draw/1.0.4/leaflet.draw.css"/>

    <!-- Leaflet.draw JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet.draw/1.0.4/leaflet.draw.js"></script>

    <style>
    #geofencePanel {
        position: fixed;
        top: 10px;
        right: 10px;
        background: rgba(0, 0, 0, 0.85);
        border: 2px solid #00ff00;
        border-radius: 8px;
        padding: 15px;
        z-index: 10000;
        width: 280px;
        font-family: 'Consolas', monospace;
        color: #00ff00;
        max-height: 400px;
        overflow-y: auto;
    }
    #geofencePanel h3 {
        margin: 0 0 10px 0;
        color: #00ff00;
        font-size: 14px;
        border-bottom: 1px solid #00ff00;
        padding-bottom: 5px;
    }
    #geofencePanel button {
        background: #001100;
        border: 1px solid #00ff00;
        color: #00ff00;
        padding: 8px 12px;
        cursor: pointer;
        font-family: inherit;
        font-size: 12px;
        border-radius: 4px;
        margin: 2px;
    }
    #geofencePanel button:hover {
        background: #002200;
    }
    #geofencePanel button.active {
        background: #00ff00;
        color: #000;
    }
    #geofencePanel button.danger {
        border-color: #ff3300;
        color: #ff3300;
    }
    #geofencePanel button.danger:hover {
        background: #330000;
    }
    #geofencePanel input, #geofencePanel textarea {
        background: #001100;
        border: 1px solid #00ff00;
        color: #00ff00;
        padding: 5px;
        font-family: inherit;
        width: 100%;
        box-sizing: border-box;
        margin-bottom: 5px;
    }
    .geofence-item {
        background: #001100;
        border: 1px solid #004400;
        padding: 8px;
        margin: 5px 0;
        border-radius: 4px;
        font-size: 11px;
    }
    .geofence-item.enabled {
        border-color: #00ff00;
    }
    .geofence-item .name {
        font-weight: bold;
        font-size: 12px;
    }
    .geofence-item .stats {
        color: #888;
        font-size: 10px;
    }
    #geofenceToggle {
        position: fixed;
        top: 10px;
        right: 300px;
        background: rgba(0, 0, 0, 0.85);
        border: 2px solid #00ff00;
        border-radius: 4px;
        padding: 8px 12px;
        z-index: 10001;
        cursor: pointer;
        color: #00ff00;
        font-family: 'Consolas', monospace;
        font-size: 12px;
    }
    #geofenceToggle:hover {
        background: #002200;
    }
    #drawingStatus {
        background: #002200;
        padding: 8px;
        border-radius: 4px;
        margin: 10px 0;
        font-size: 11px;
        display: none;
    }
    #drawingStatus.active {
        display: block;
        border: 1px solid #ffff00;
        color: #ffff00;
    }
    </style>

    <button id="geofenceToggle" onclick="toggleGeofencePanel()">🎯 Geofence</button>

    <div id="geofencePanel" style="display: none;">
        <h3>🎯 Geofence Boundaries</h3>

        <div style="margin-bottom: 10px;">
            <button onclick="startDrawPolygon()" id="drawPolygonBtn">📐 Draw Polygon</button>
            <button onclick="startDrawRectangle()" id="drawRectangleBtn">⬜ Rectangle</button>
            <button onclick="startDrawCircle()" id="drawCircleBtn">🔵 Circle</button>
        </div>

        <div id="drawingStatus">
            <strong>Drawing Mode Active</strong><br>
            Click on map to place points. Double-click to finish.
            <br><button onclick="cancelDrawing()" class="danger" style="margin-top: 5px;">Cancel</button>
        </div>

        <div id="saveGeofenceForm" style="display: none; margin: 10px 0; padding: 10px; background: #002200; border-radius: 4px;">
            <input type="text" id="geofenceName" placeholder="Boundary name (e.g., Acme Corp Campus)">
            <textarea id="geofenceDesc" placeholder="Description (optional)" rows="2"></textarea>
            <div style="margin-top: 5px;">
                <label style="font-size: 11px;">Color: </label>
                <input type="color" id="geofenceColor" value="#00ff00" style="width: 50px; height: 25px; padding: 0;">
            </div>
            <div style="margin-top: 10px;">
                <button onclick="saveGeofence()">💾 Save Boundary</button>
                <button onclick="cancelSave()" class="danger">Cancel</button>
            </div>
        </div>

        <div style="margin-top: 15px;">
            <h4 style="margin: 0 0 5px 0; font-size: 12px; color: #888;">Saved Boundaries</h4>
            <div id="geofenceList">
                <div style="color: #666; font-size: 11px;">Loading...</div>
            </div>
        </div>

        <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #004400;">
            <button onclick="refreshGeofences()" style="width: 100%;">🔄 Refresh</button>
        </div>
    </div>

    <script>
    (function() {
        // Wait for map to be ready
        setTimeout(function() {
            // Find the Leaflet map object
            var mapId = Object.keys(window).find(k => window[k] instanceof L.Map);
            if (!mapId) {
                // Try to find map in document
                var mapElements = document.querySelectorAll('.folium-map');
                if (mapElements.length > 0) {
                    var mapEl = mapElements[0];
                    for (var key in window) {
                        if (window[key] && window[key]._container === mapEl) {
                            window.leafletMap = window[key];
                            break;
                        }
                    }
                }
            } else {
                window.leafletMap = window[mapId];
            }

            if (!window.leafletMap) {
                console.error('Could not find Leaflet map');
                return;
            }

            // Initialize drawing layer
            window.drawnItems = new L.FeatureGroup();
            window.leafletMap.addLayer(window.drawnItems);

            // Layer to hold saved geofences
            window.geofenceLayers = new L.FeatureGroup();
            window.leafletMap.addLayer(window.geofenceLayers);

            // Current drawing shape
            window.currentDrawing = null;
            window.drawMode = null;

            // Load saved geofences
            refreshGeofences();
        }, 1500);
    })();

    function toggleGeofencePanel() {
        var panel = document.getElementById('geofencePanel');
        panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    }

    function setDrawingMode(mode) {
        window.drawMode = mode;
        document.getElementById('drawingStatus').className = mode ? 'active' : '';

        // Highlight active button
        document.querySelectorAll('#geofencePanel button').forEach(function(btn) {
            btn.classList.remove('active');
        });
        if (mode === 'polygon') document.getElementById('drawPolygonBtn').classList.add('active');
        if (mode === 'rectangle') document.getElementById('drawRectangleBtn').classList.add('active');
        if (mode === 'circle') document.getElementById('drawCircleBtn').classList.add('active');
    }

    function startDrawPolygon() {
        if (!window.leafletMap) return;
        setDrawingMode('polygon');

        window.currentDrawing = new L.Draw.Polygon(window.leafletMap, {
            shapeOptions: {
                color: '#00ff00',
                fillColor: '#00ff00',
                fillOpacity: 0.2
            }
        });
        window.currentDrawing.enable();

        window.leafletMap.once(L.Draw.Event.CREATED, function(e) {
            window.drawnItems.addLayer(e.layer);
            window.pendingGeofence = e.layer;
            setDrawingMode(null);
            showSaveForm();
        });
    }

    function startDrawRectangle() {
        if (!window.leafletMap) return;
        setDrawingMode('rectangle');

        window.currentDrawing = new L.Draw.Rectangle(window.leafletMap, {
            shapeOptions: {
                color: '#00ff00',
                fillColor: '#00ff00',
                fillOpacity: 0.2
            }
        });
        window.currentDrawing.enable();

        window.leafletMap.once(L.Draw.Event.CREATED, function(e) {
            window.drawnItems.addLayer(e.layer);
            window.pendingGeofence = e.layer;
            setDrawingMode(null);
            showSaveForm();
        });
    }

    function startDrawCircle() {
        if (!window.leafletMap) return;
        setDrawingMode('circle');

        window.currentDrawing = new L.Draw.Circle(window.leafletMap, {
            shapeOptions: {
                color: '#00ff00',
                fillColor: '#00ff00',
                fillOpacity: 0.2
            }
        });
        window.currentDrawing.enable();

        window.leafletMap.once(L.Draw.Event.CREATED, function(e) {
            // Convert circle to polygon (GeoJSON doesn't support circles)
            var center = e.layer.getLatLng();
            var radius = e.layer.getRadius();
            var points = [];
            var numPoints = 64;

            for (var i = 0; i < numPoints; i++) {
                var angle = (i / numPoints) * 2 * Math.PI;
                var lat = center.lat + (radius / 111320) * Math.cos(angle);
                var lng = center.lng + (radius / (111320 * Math.cos(center.lat * Math.PI / 180))) * Math.sin(angle);
                points.push([lat, lng]);
            }
            points.push(points[0]); // Close polygon

            var polygon = L.polygon(points, {
                color: '#00ff00',
                fillColor: '#00ff00',
                fillOpacity: 0.2
            });

            window.drawnItems.addLayer(polygon);
            window.pendingGeofence = polygon;
            setDrawingMode(null);
            showSaveForm();
        });
    }

    function cancelDrawing() {
        if (window.currentDrawing) {
            window.currentDrawing.disable();
        }
        setDrawingMode(null);
    }

    function showSaveForm() {
        document.getElementById('saveGeofenceForm').style.display = 'block';
        document.getElementById('geofenceName').focus();
    }

    function cancelSave() {
        document.getElementById('saveGeofenceForm').style.display = 'none';
        if (window.pendingGeofence) {
            window.drawnItems.removeLayer(window.pendingGeofence);
            window.pendingGeofence = null;
        }
        document.getElementById('geofenceName').value = '';
        document.getElementById('geofenceDesc').value = '';
    }

    function saveGeofence() {
        if (!window.pendingGeofence) return;

        var name = document.getElementById('geofenceName').value || 'Unnamed Boundary';
        var desc = document.getElementById('geofenceDesc').value || '';
        var color = document.getElementById('geofenceColor').value || '#00ff00';

        // Convert to GeoJSON
        var geoJson = window.pendingGeofence.toGeoJSON();

        // POST to server
        fetch('/api/wardrive/geofence', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: name,
                description: desc,
                polygon_json: JSON.stringify(geoJson.geometry),
                color: color
            })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success) {
                // Style the saved geofence
                window.pendingGeofence.setStyle({color: color, fillColor: color});
                window.pendingGeofence.bindPopup('<b>' + name + '</b><br>' + desc);

                // Move from drawn to saved layer
                window.drawnItems.removeLayer(window.pendingGeofence);
                window.geofenceLayers.addLayer(window.pendingGeofence);

                window.pendingGeofence = null;
                document.getElementById('saveGeofenceForm').style.display = 'none';
                document.getElementById('geofenceName').value = '';
                document.getElementById('geofenceDesc').value = '';

                refreshGeofences();
            } else {
                alert('Error saving: ' + data.error);
            }
        })
        .catch(function(err) {
            alert('Network error: ' + err);
        });
    }

    // Escape HTML to prevent XSS
    function escapeHtml(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Validate hex color format
    function isValidColor(color) {
        return /^#[0-9A-Fa-f]{6}$/.test(color);
    }

    function refreshGeofences() {
        fetch('/api/wardrive/geofences')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var list = document.getElementById('geofenceList');

            // Clear existing geofence layers
            window.geofenceLayers.clearLayers();

            if (!data.success || !data.geofences || data.geofences.length === 0) {
                list.innerHTML = '<div style="color: #666; font-size: 11px;">No boundaries saved yet. Draw one above!</div>';
                return;
            }

            var html = '';
            data.geofences.forEach(function(gf) {
                var enabledClass = gf.enabled ? 'enabled' : '';
                var safeColor = isValidColor(gf.color) ? gf.color : '#00ff00';
                var safeName = escapeHtml(gf.name);
                var safeDesc = escapeHtml(gf.description);

                html += '<div class="geofence-item ' + enabledClass + '" data-geofence-id="' + gf.id + '">';
                html += '<div class="name" style="color: ' + safeColor + ';">⬡ ' + safeName + '</div>';
                if (safeDesc) {
                    html += '<div style="color: #aaa; font-size: 10px; margin: 3px 0;">' + safeDesc + '</div>';
                }
                html += '<div class="stats">Created: ' + escapeHtml(gf.created_at) + '</div>';
                html += '<div style="margin-top: 5px;">';
                html += '<button onclick="toggleGeofenceEnabled(' + gf.id + ')" style="padding: 3px 6px; font-size: 10px;">' + (gf.enabled ? '✓ On' : '✗ Off') + '</button> ';
                html += '<button onclick="zoomToGeofence(' + gf.id + ')" style="padding: 3px 6px; font-size: 10px;">🔍 Zoom</button> ';
                html += '<button onclick="countNetworks(' + gf.id + ')" style="padding: 3px 6px; font-size: 10px;">📊 Count</button> ';
                html += '<button onclick="deleteGeofence(' + gf.id + ')" class="danger" style="padding: 3px 6px; font-size: 10px;">🗑️</button>';
                html += '</div>';
                html += '</div>';

                // Add to map if enabled
                if (gf.enabled && gf.polygon_json) {
                    try {
                        var geojson = JSON.parse(gf.polygon_json);
                        var layer = L.geoJSON(geojson, {
                            style: {
                                color: safeColor,
                                fillColor: safeColor,
                                fillOpacity: 0.2,
                                weight: 2
                            }
                        });
                        layer.bindPopup('<b>' + safeName + '</b><br>' + (safeDesc || ''));
                        layer.geofenceId = gf.id;
                        window.geofenceLayers.addLayer(layer);
                    } catch(e) {
                        console.error('Error adding geofence to map:', e);
                    }
                }
            });
            list.innerHTML = html;
        })
        .catch(function(err) {
            document.getElementById('geofenceList').innerHTML = '<div style="color: #ff3300;">Error: ' + err + '</div>';
        });
    }

    function zoomToGeofence(id) {
        window.geofenceLayers.eachLayer(function(layer) {
            if (layer.geofenceId === id) {
                window.leafletMap.fitBounds(layer.getBounds(), {padding: [50, 50]});
            }
        });
    }

    function countNetworks(id) {
        fetch('/api/wardrive/geofence/' + id + '/networks')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var item = document.querySelector('[data-geofence-id="' + id + '"] .stats');
            if (data.success) {
                if (item) {
                    var countInfo = item.querySelector('.network-count');
                    if (countInfo) {
                        countInfo.textContent = '📡 ' + data.count + ' networks';
                    } else {
                        item.innerHTML += '<br><span class="network-count" style="color: #00ff00;">📡 ' + data.count + ' networks</span>';
                    }
                }
            } else {
                if (item) {
                    item.innerHTML += '<br><span style="color: #ff3300;">Error: ' + escapeHtml(data.error) + '</span>';
                }
            }
        })
        .catch(function(err) {
            console.error('Count networks error:', err);
        });
    }

    function toggleGeofenceEnabled(id) {
        fetch('/api/wardrive/geofence/' + id + '/toggle', {method: 'POST'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success) {
                refreshGeofences();
            } else {
                console.error('Toggle failed:', data.error);
            }
        })
        .catch(function(err) {
            console.error('Toggle error:', err);
        });
    }

    function deleteGeofence(id) {
        if (!confirm('Delete this boundary?')) return;

        fetch('/api/wardrive/geofence/' + id, {method: 'DELETE'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success) {
                refreshGeofences();
            } else {
                alert('Error: ' + data.error);
            }
        });
    }
    </script>
    '''
    m.get_root().html.add_child(folium.Element(geofence_html))

    # Save map
    m.save(output_file)
    
    print(f"✅ Map saved to: {os.path.abspath(output_file)}")
    print(f"   🔒 Secured: {secured_networks}")
    print(f"   🔓 Open: {open_networks}")

def main():
    """Main execution"""
    print("=" * 60)
    print("🗺️  WARDRIVE MAPPER - CUMULATIVE EDITION")
    print("=" * 60)

    # Check for --regen flag to regenerate map from existing database
    if len(sys.argv) >= 2 and sys.argv[1] == '--regen':
        print("\n🔄 Regenerating map from existing database...")
        conn = init_database()
        print("\n🗺️  Generating map...")
        create_map(conn)
        conn.close()
        print("\n" + "=" * 60)
        print("✅ MAP REGENERATED!")
        print("=" * 60)
        print("\n📂 Open 'wardrive_master_map.html' in your browser to view the map\n")
        sys.exit(0)

    if len(sys.argv) < 2:
        print("\n❌ Usage: python wardrive_mapper.py <wardrive_file.txt>")
        print("         python wardrive_mapper.py --regen  (regenerate map from database)")
        print("\nExample: python wardrive_mapper.py wardrive_1.txt")
        print("\nThis will add the data to your cumulative map.")
        sys.exit(1)

    wardrive_file = sys.argv[1]

    if not os.path.exists(wardrive_file):
        print(f"\n❌ Error: File '{wardrive_file}' not found!")
        sys.exit(1)

    # Initialize database
    print("\n📊 Initializing database...")
    conn = init_database()

    # Parse wardrive file
    df = parse_wardrive_file(wardrive_file)
    if df is None:
        sys.exit(1)

    # Update database
    print("\n💾 Updating database...")
    update_database(conn, df, wardrive_file)

    # Create map
    print("\n🗺️  Generating map...")
    create_map(conn)

    conn.close()

    print("\n" + "=" * 60)
    print("✅ COMPLETE!")
    print("=" * 60)
    print("\n📂 Open 'wardrive_master_map.html' in your browser to view the map")
    print("💡 Run this script again with new wardrive files to add them to the map\n")

if __name__ == "__main__":
    main()
