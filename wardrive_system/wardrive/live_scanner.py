#!/usr/bin/env python3
"""
Live Scanner - Real-time wardriving module for WiFi Arsenal.
Coordinates GPS reading, WiFi beacon sniffing, and database persistence.

Hardware:
  - u-blox 8 GPS on /dev/ttyACM0 (9600 baud, NMEA)
  - Alfa adapter (alfa0) in monitor mode

Classes:
  - GPSReader: NMEA sentence parser for u-blox 8
  - WiFiScanner: Scapy-based 802.11 beacon frame sniffer
  - LiveWardriveSession: Coordinates GPS + WiFi + DB writes

Utility:
  - calculate_ap_position(): Weighted centroid AP triangulation
"""

import serial
import threading
import time
import queue
import sqlite3
import signal
import os
import subprocess
import math
from datetime import datetime


class GPSReader:
    """Reads NMEA sentences from u-blox 8 GPS via serial."""

    def __init__(self, port=None, baudrate=9600):
        self.port = port or self._find_gps_device()
        self.baudrate = baudrate
        self.serial_conn = None
        self.running = False
        self.lock = threading.Lock()
        self.track_points = []
        self.current_position = {
            'latitude': 0.0,
            'longitude': 0.0,
            'altitude': 0.0,
            'speed_knots': 0.0,
            'speed_mph': 0.0,
            'heading': 0.0,
            'satellites': 0,
            'fix_quality': 0,
            'hdop': 0.0,
            'timestamp': None,
            'valid': False
        }

    @staticmethod
    def _find_gps_device():
        """Auto-detect u-blox GPS serial device."""
        import glob
        for dev in sorted(glob.glob('/dev/ttyACM*')):
            try:
                ser = serial.Serial(dev, 9600, timeout=2)
                line = ser.readline().decode('ascii', errors='ignore')
                ser.close()
                if '$G' in line:
                    return dev
            except Exception:
                continue
        return '/dev/ttyACM0'  # fallback

    def start(self):
        """Open serial connection and start reading NMEA sentences."""
        self.serial_conn = serial.Serial(
            port=self.port,
            baudrate=self.baudrate,
            timeout=1
        )
        self.running = True
        thread = threading.Thread(target=self._read_loop, daemon=True)
        thread.start()

    def stop(self):
        """Stop reading and close serial connection."""
        self.running = False
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.close()
            except Exception:
                pass

    def _read_loop(self):
        """Continuously read and parse NMEA sentences from serial."""
        while self.running:
            try:
                if not self.serial_conn or not self.serial_conn.is_open:
                    time.sleep(0.1)
                    continue
                line = self.serial_conn.readline().decode('ascii', errors='ignore').strip()
                if not line:
                    continue

                if line.startswith('$GPGGA') or line.startswith('$GNGGA'):
                    self._parse_gga(line)
                elif line.startswith('$GPRMC') or line.startswith('$GNRMC'):
                    self._parse_rmc(line)

                # On valid fix, record track point
                with self.lock:
                    if self.current_position['valid']:
                        lat = self.current_position['latitude']
                        lon = self.current_position['longitude']
                        ts = self.current_position['timestamp']
                        self.track_points.append((lat, lon, ts))

            except serial.SerialException:
                # Device disconnected
                time.sleep(1)
            except Exception:
                time.sleep(0.1)

    def _parse_gga(self, sentence):
        """Parse $GPGGA/$GNGGA sentence for position, altitude, fix quality, satellites, HDOP."""
        try:
            # Strip checksum
            if '*' in sentence:
                sentence = sentence.split('*')[0]
            fields = sentence.split(',')
            if len(fields) < 10:
                return

            fix_quality = int(fields[6]) if fields[6] else 0
            satellites = int(fields[7]) if fields[7] else 0
            hdop = float(fields[8]) if fields[8] else 0.0
            altitude = float(fields[9]) if fields[9] else 0.0

            with self.lock:
                self.current_position['fix_quality'] = fix_quality
                self.current_position['satellites'] = satellites
                self.current_position['hdop'] = hdop
                self.current_position['altitude'] = altitude
                self.current_position['timestamp'] = datetime.utcnow().isoformat()

                if fix_quality > 0 and fields[2] and fields[4]:
                    lat = self._nmea_to_decimal(fields[2], fields[3])
                    lon = self._nmea_to_decimal(fields[4], fields[5])
                    self.current_position['latitude'] = lat
                    self.current_position['longitude'] = lon
                    self.current_position['valid'] = True
                else:
                    self.current_position['valid'] = False

        except (ValueError, IndexError):
            pass

    def _parse_rmc(self, sentence):
        """Parse $GPRMC/$GNRMC sentence for speed and heading."""
        try:
            if '*' in sentence:
                sentence = sentence.split('*')[0]
            fields = sentence.split(',')
            if len(fields) < 9:
                return

            speed_knots = float(fields[7]) if fields[7] else 0.0
            speed_mph = speed_knots * 1.15078
            heading = float(fields[8]) if fields[8] else 0.0

            with self.lock:
                self.current_position['speed_knots'] = speed_knots
                self.current_position['speed_mph'] = speed_mph
                self.current_position['heading'] = heading

        except (ValueError, IndexError):
            pass

    def _nmea_to_decimal(self, coord, direction):
        """Convert NMEA ddmm.mmmm format to decimal degrees."""
        if not coord:
            return 0.0
        # Find the split point: degrees are first 2 chars for lat, 3 for lon
        # But we can use the decimal point position: degrees = everything before last 7 chars of mm.mmmm
        dot_pos = coord.index('.')
        degrees = float(coord[:dot_pos - 2])
        minutes = float(coord[dot_pos - 2:])
        decimal = degrees + minutes / 60.0
        if direction in ('S', 'W'):
            decimal = -decimal
        return decimal

    def get_position(self):
        """Return thread-safe copy of current GPS position."""
        with self.lock:
            return dict(self.current_position)


class WiFiScanner:
    """Sniffs 802.11 beacon frames using scapy on a monitor-mode interface."""

    def __init__(self, interface='alfa0', gps_reader=None):
        self.interface = interface
        self.gps_reader = gps_reader
        self.networks = {}       # MAC -> {mac, ssid, auth_mode, channel, rssi, first_seen, last_seen}
        self.observations = {}   # MAC -> [(lat, lon, rssi, timestamp), ...]
        self.event_queue = queue.Queue()
        self.running = False
        self.lock = threading.Lock()
        self.total_observations = 0

    def ensure_monitor_mode(self):
        """Ensure interface is in monitor mode using mode_manager.sh."""
        try:
            result = subprocess.run(
                ['bash', '/home/ov3rr1d3/wifi_arsenal/scripts/mode_manager.sh',
                 'ensure', self.interface, 'monitor'],
                capture_output=True, text=True, timeout=15
            )
            return result.returncode == 0
        except Exception:
            return False

    def start(self):
        """Start monitor mode, channel hopping, and packet sniffing."""
        self.ensure_monitor_mode()
        self.running = True
        sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        hop_thread = threading.Thread(target=self._channel_hop_loop, daemon=True)
        sniff_thread.start()
        hop_thread.start()

    def stop(self):
        """Stop sniffing (scapy stop_filter will pick up self.running=False)."""
        self.running = False

    def _channel_hop_loop(self):
        """Cycle through 2.4GHz and 5GHz channels."""
        channels_24 = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13]
        channels_5 = [
            36, 40, 44, 48, 52, 56, 60, 64,
            100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
            149, 153, 157, 161, 165
        ]
        all_channels = channels_24 + channels_5

        idx = 0
        while self.running:
            ch = all_channels[idx % len(all_channels)]
            try:
                subprocess.run(
                    ['iwconfig', self.interface, 'channel', str(ch)],
                    capture_output=True, timeout=2
                )
            except Exception:
                pass  # Some 5GHz channels may not be supported
            time.sleep(0.15)
            idx += 1

    def _sniff_loop(self):
        """Sniff beacon frames using scapy."""
        try:
            from scapy.all import sniff
            print(f"[LIVE] Scapy sniff starting on {self.interface}...")
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=0,
                stop_filter=lambda x: not self.running
            )
            print("[LIVE] Scapy sniff loop ended")
        except Exception as e:
            print(f"[LIVE] Scapy sniff FAILED: {e}")
            import traceback
            traceback.print_exc()

    def _handle_packet(self, packet):
        """Process a captured 802.11 beacon frame."""
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

            if not packet.haslayer(Dot11Beacon):
                return

            # Extract BSSID
            bssid = packet[Dot11].addr2
            if not bssid:
                return
            mac = bssid.upper()
            # Validate MAC format
            if len(mac) != 17 or mac.count(':') != 5:
                return

            # Extract RSSI
            rssi = -100
            if packet.haslayer(RadioTap):
                try:
                    rssi_val = packet[RadioTap].dBm_AntSignal
                    if rssi_val is not None:
                        rssi = rssi_val
                except Exception:
                    rssi = -100

            # Extract SSID and channel from Dot11Elt layers
            ssid = ''
            channel = 0
            elt = packet[Dot11Elt] if packet.haslayer(Dot11Elt) else None
            while elt:
                try:
                    if elt.ID == 0:  # SSID
                        try:
                            ssid = elt.info.decode('utf-8', errors='replace')
                        except Exception:
                            ssid = ''
                    elif elt.ID == 3:  # DS Parameter Set (channel)
                        if elt.info:
                            channel = elt.info[0] if isinstance(elt.info[0], int) else ord(elt.info[0])
                except Exception:
                    pass
                elt = elt.payload if elt.payload and elt.payload.name != 'Raw' and elt.payload.name != 'Padding' else None
                if elt and not hasattr(elt, 'ID'):
                    break

            # Extract encryption info
            cap = packet[Dot11Beacon].cap
            crypto = set()
            if cap.privacy:
                # Check for RSN (WPA2) - Element ID 48
                rsn_found = False
                wpa_found = False
                elt2 = packet[Dot11Elt] if packet.haslayer(Dot11Elt) else None
                while elt2:
                    try:
                        if elt2.ID == 48:
                            crypto.add('WPA2')
                            rsn_found = True
                        elif elt2.ID == 221:
                            # Check for WPA vendor element (Microsoft OUI: 00:50:F2)
                            if elt2.info and len(elt2.info) >= 4:
                                oui = elt2.info[:3]
                                if oui == b'\x00\x50\xf2' and elt2.info[3] == 1:
                                    crypto.add('WPA')
                                    wpa_found = True
                    except Exception:
                        pass
                    elt2 = elt2.payload if elt2.payload and hasattr(elt2.payload, 'ID') else None

                if not rsn_found and not wpa_found:
                    crypto.add('WEP')
            else:
                crypto.add('OPEN')

            # Build auth_mode string
            auth_parts = sorted(crypto, reverse=True)  # WPA2 before WPA before WEP
            auth_mode = ''.join(f'[{c}]' for c in auth_parts)

            # Get GPS position
            if self.gps_reader:
                pos = self.gps_reader.get_position()
                if not pos.get('valid'):
                    return
                lat = pos['latitude']
                lon = pos['longitude']
            else:
                return  # No GPS, skip

            if lat == 0 and lon == 0:
                return

            # RSSI floor filter — discard very weak/distant signals from Alfa's extended range
            if rssi < -85:
                return

            # Skip own hotspot — MAC randomizes each session, pollutes DB
            if ssid == 'Arsenal-Control':
                return

            now = datetime.utcnow().isoformat()

            with self.lock:
                is_new = mac not in self.networks

                if is_new:
                    self.networks[mac] = {
                        'mac': mac,
                        'ssid': ssid,
                        'auth_mode': auth_mode,
                        'channel': channel,
                        'rssi': rssi,
                        'first_seen': now,
                        'last_seen': now
                    }
                    self.observations[mac] = []
                else:
                    net = self.networks[mac]
                    # Keep strongest RSSI
                    if rssi > net['rssi']:
                        net['rssi'] = rssi
                    net['last_seen'] = now
                    # Fill in SSID if it was empty
                    if not net['ssid'] and ssid:
                        net['ssid'] = ssid

                # Record observation
                self.observations[mac].append((lat, lon, rssi, now))
                self.total_observations += 1
                obs_count = len(self.observations[mac])

                # Throttle events: push if new OR every 10th observation
                if is_new or obs_count % 10 == 0:
                    event = {
                        'type': 'network',
                        'mac': mac,
                        'ssid': ssid,
                        'auth_mode': auth_mode,
                        'channel': channel,
                        'rssi': rssi,
                        'lat': lat,
                        'lon': lon,
                        'is_new': is_new,
                        'observation_count': obs_count
                    }
                    try:
                        self.event_queue.put_nowait(event)
                    except queue.Full:
                        pass

        except Exception:
            pass

    def get_networks(self):
        """Return thread-safe copy of all discovered networks."""
        with self.lock:
            return dict(self.networks)

    def get_network_count(self):
        """Return count of unique networks found."""
        with self.lock:
            return len(self.networks)

    def get_observations(self, mac):
        """Return thread-safe copy of observations for a specific MAC."""
        with self.lock:
            return list(self.observations.get(mac, []))


def calculate_ap_position(observations):
    """
    Calculate estimated AP position using weighted centroid.

    Args:
        observations: list of (lat, lon, rssi) tuples

    Returns:
        (lat, lon) estimated AP position
    """
    if not observations:
        return (0, 0)
    if len(observations) == 1:
        return (observations[0][0], observations[0][1])

    total_weight = 0
    weighted_lat = 0
    weighted_lon = 0

    for lat, lon, rssi in observations:
        if lat == 0 and lon == 0:
            continue  # Skip invalid GPS readings
        # Convert RSSI to weight - stronger signal = exponentially more weight
        # RSSI is negative (e.g., -30 is strong, -90 is weak)
        # Using 10^(rssi/20) gives exponential weighting
        weight = 10 ** (rssi / 20.0)
        weighted_lat += lat * weight
        weighted_lon += lon * weight
        total_weight += weight

    if total_weight == 0:
        return (observations[0][0], observations[0][1])

    return (weighted_lat / total_weight, weighted_lon / total_weight)


class LiveWardriveSession:
    """Coordinates GPS reading, WiFi scanning, and database persistence for a live wardrive session."""

    DB_PATH = '/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db'

    def __init__(self):
        self.gps = GPSReader()
        self.scanner = None
        self.session_id = None
        self.running = False
        self.start_time = None
        self.networks_found = 0
        self.new_networks = 0
        self.db_writer_thread = None
        self.event_queue = queue.Queue()

    def start(self):
        """Start a new live wardrive session."""
        # Create session in DB
        now = datetime.utcnow().isoformat()
        filename = f"live_wardrive_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
        conn = sqlite3.connect(self.DB_PATH)
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO sessions (filename, imported_at, network_count, new_networks) VALUES (?, ?, 0, 0)',
            (filename, now)
        )
        self.session_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Start GPS reader
        try:
            self.gps.start()
        except Exception as e:
            print(f"[WARNING] GPS failed to start: {e} - continuing without GPS")

        # Create and start WiFi scanner
        self.scanner = WiFiScanner(gps_reader=self.gps)

        # Preload known MACs from DB so they aren't falsely flagged as is_new
        try:
            conn = sqlite3.connect(self.DB_PATH)
            cur = conn.cursor()
            cur.execute('SELECT mac, ssid, auth_mode, channel, rssi FROM networks')
            for row in cur.fetchall():
                mac, ssid, auth_mode, channel, rssi = row
                self.scanner.networks[mac] = {
                    'mac': mac,
                    'ssid': ssid or '',
                    'auth_mode': auth_mode or '',
                    'channel': channel or 0,
                    'rssi': rssi if rssi is not None else -100,
                    'first_seen': None,
                    'last_seen': None
                }
                self.scanner.observations[mac] = []
            conn.close()
            print(f"[LIVE] Preloaded {len(self.scanner.networks)} known MACs from DB")
        except Exception as e:
            print(f"[WARNING] Failed to preload MACs from DB: {e}")

        self.scanner.start()

        # Start DB writer thread
        self.running = True
        self.start_time = time.time()
        self.db_writer_thread = threading.Thread(target=self._db_writer_loop, daemon=True)
        self.db_writer_thread.start()

        # Push status event
        try:
            self.event_queue.put_nowait({
                'type': 'session_start',
                'session_id': self.session_id,
                'timestamp': now
            })
        except queue.Full:
            pass

    def stop(self):
        """Stop the live wardrive session and finalize data."""
        self.running = False

        # Wait for DB writer thread to finish its current batch
        if hasattr(self, 'db_writer_thread') and self.db_writer_thread.is_alive():
            self.db_writer_thread.join(timeout=10)

        # Stop scanner
        if self.scanner:
            self.scanner.stop()

        # Stop GPS
        if self.gps:
            self.gps.stop()

        # Final triangulation pass
        if self.scanner:
            conn = sqlite3.connect(self.DB_PATH)
            cur = conn.cursor()
            try:
                for mac, obs_list in self.scanner.observations.items():
                    if obs_list:
                        # Build (lat, lon, rssi) tuples for triangulation
                        tri_obs = [(lat, lon, rssi) for lat, lon, rssi, ts in obs_list]
                        est_lat, est_lon = calculate_ap_position(tri_obs)
                        cur.execute(
                            'UPDATE networks SET latitude = ?, longitude = ? WHERE mac = ?',
                            (est_lat, est_lon, mac)
                        )

                # Save GPS track as observations with special MAC
                if self.gps and self.gps.track_points:
                    for lat, lon, ts in self.gps.track_points:
                        cur.execute(
                            'INSERT INTO observations (mac, session_id, rssi, latitude, longitude, captured_at) VALUES (?, ?, ?, ?, ?, ?)',
                            ('__GPS_TRACK__', self.session_id, 0, lat, lon, ts)
                        )

                # Update session counts
                cur.execute(
                    'UPDATE sessions SET network_count = ?, new_networks = ? WHERE id = ?',
                    (self.networks_found, self.new_networks, self.session_id)
                )
                conn.commit()
            except Exception as e:
                print(f"[ERROR] Final save failed: {e}")
            finally:
                conn.close()

        # Push session end event
        try:
            self.event_queue.put_nowait({
                'type': 'session_end',
                'session_id': self.session_id,
                'networks_found': self.networks_found,
                'new_networks': self.new_networks,
                'elapsed': time.time() - self.start_time if self.start_time else 0
            })
        except queue.Full:
            pass

    def _db_writer_loop(self):
        """Periodically drain scanner events and write to database."""
        while self.running:
            time.sleep(2)
            try:
                # Drain scanner event queue into batch
                batch = []
                while True:
                    try:
                        event = self.scanner.event_queue.get_nowait()
                        batch.append(event)
                    except queue.Empty:
                        break

                if not batch:
                    # Still push GPS position event if valid
                    if self.gps:
                        pos = self.gps.get_position()
                        if pos.get('valid'):
                            try:
                                self.event_queue.put_nowait({
                                    'type': 'gps',
                                    'position': pos,
                                    'track_points': len(self.gps.track_points)
                                })
                            except queue.Full:
                                pass
                    continue

                conn = sqlite3.connect(self.DB_PATH)
                cur = conn.cursor()

                for event in batch:
                    if event.get('type') != 'network':
                        continue

                    mac = event['mac']

                    # Get current observations for triangulation
                    obs_list = self.scanner.get_observations(mac)
                    tri_obs = [(lat, lon, rssi) for lat, lon, rssi, ts in obs_list]
                    est_lat, est_lon = calculate_ap_position(tri_obs)

                    # Check if MAC exists in DB
                    cur.execute('SELECT mac, rssi FROM networks WHERE mac = ?', (mac,))
                    existing = cur.fetchone()

                    if existing is None:
                        # New network - INSERT
                        now = datetime.utcnow().isoformat()
                        cur.execute(
                            '''INSERT INTO networks
                               (mac, ssid, auth_mode, first_seen, channel, rssi,
                                latitude, longitude, last_updated, observation_count)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (mac, event['ssid'], event['auth_mode'], now,
                             event['channel'], event['rssi'],
                             est_lat, est_lon, now, event['observation_count'])
                        )
                        self.new_networks += 1
                        self.networks_found += 1
                    else:
                        # Existing network - UPDATE
                        existing_rssi = existing[1] if existing[1] is not None else -100
                        new_rssi = max(event['rssi'], existing_rssi)
                        now = datetime.utcnow().isoformat()
                        cur.execute(
                            '''UPDATE networks
                               SET observation_count = observation_count + 1,
                                   last_updated = ?,
                                   latitude = ?,
                                   longitude = ?,
                                   rssi = ?
                               WHERE mac = ?''',
                            (now, est_lat, est_lon, new_rssi, mac)
                        )
                        if not event.get('is_new', True):
                            # Already counted if is_new was true in a previous batch
                            pass
                        else:
                            self.networks_found += 1

                    # INSERT observation row
                    cur.execute(
                        '''INSERT INTO observations
                           (mac, session_id, rssi, latitude, longitude, captured_at)
                           VALUES (?, ?, ?, ?, ?, ?)''',
                        (mac, self.session_id, event['rssi'],
                         event['lat'], event['lon'],
                         datetime.utcnow().isoformat())
                    )

                conn.commit()
                conn.close()

                # Forward events to SSE event queue
                for event in batch:
                    try:
                        self.event_queue.put_nowait(event)
                    except queue.Full:
                        pass

                # Push GPS position event
                if self.gps:
                    pos = self.gps.get_position()
                    if pos.get('valid'):
                        try:
                            self.event_queue.put_nowait({
                                'type': 'gps',
                                'position': pos,
                                'track_points': len(self.gps.track_points)
                            })
                        except queue.Full:
                            pass

            except Exception as e:
                print(f"[ERROR] DB writer error: {e}")

    def get_status(self):
        """Return current session status."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        gps_pos = self.gps.get_position() if self.gps else {}
        track_count = len(self.gps.track_points) if self.gps else 0

        return {
            'running': self.running,
            'session_id': self.session_id,
            'elapsed': elapsed,
            'networks_found': self.networks_found,
            'new_networks': self.new_networks,
            'total_in_scan': self.scanner.get_network_count() if self.scanner else 0,
            'total_observations': self.scanner.total_observations if self.scanner else 0,
            'gps': gps_pos,
            'gps_track_points': track_count
        }
