"""
Report Generator — WiFi Security Assessment Reports
S.P.A.R.K. Initiative Labs

Generates professional client-facing PDF and HTML reports from wardrive data.
Used by server.py endpoints: /api/wardrive/report/{generate,preview,stats}
"""

import sqlite3
import json
import math
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wardrive', 'wardrive_data.db')
RISK_WEIGHTS = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


class ReportGenerator:
    """Generates security assessment reports from wardrive data."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH

    def _get_db_connection(self) -> sqlite3.Connection:
        """Open a database connection with Row factory for dict-like access."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Core data retrieval
    # ------------------------------------------------------------------

    def get_networks_for_report(
        self,
        geofence_id: Optional[int] = None,
        vuln_threshold: str = 'all'
    ) -> List[dict]:
        """
        Retrieve all networks, optionally filtered by geofence and vulnerability
        threshold, enriched with risk levels and per-session observation counts.
        """
        conn = self._get_db_connection()
        try:
            cursor = conn.execute("SELECT * FROM networks")
            rows = cursor.fetchall()
            networks = [dict(row) for row in rows]

            # Geofence filtering
            if geofence_id is not None:
                geofence_row = conn.execute(
                    "SELECT polygon_json FROM geofences WHERE id = ?",
                    (geofence_id,)
                ).fetchone()
                if geofence_row is None:
                    logger.warning("Geofence id=%s not found, returning all networks", geofence_id)
                else:
                    polygon_data = json.loads(geofence_row['polygon_json'])
                    if isinstance(polygon_data, dict):
                        polygon = polygon_data.get('coordinates', [[]])[0]
                    elif isinstance(polygon_data, list):
                        polygon = polygon_data
                    else:
                        polygon = []

                    if polygon:
                        networks = [
                            n for n in networks
                            if n.get('latitude') is not None
                            and n.get('longitude') is not None
                            and self._point_in_polygon(n['latitude'], n['longitude'], polygon)
                        ]

            # Enrich with risk level
            for net in networks:
                net['risk_level'] = self.categorize_risk(net)

            # Per-session observation counts
            for net in networks:
                obs_cursor = conn.execute(
                    "SELECT session_id, COUNT(*) as cnt FROM observations "
                    "WHERE mac = ? GROUP BY session_id",
                    (net['mac'],)
                )
                net['session_observations'] = {
                    row['session_id']: row['cnt'] for row in obs_cursor.fetchall()
                }

            # Vulnerability threshold filter
            if vuln_threshold == 'critical':
                networks = [n for n in networks if n['risk_level'] == 'critical']
            elif vuln_threshold == 'high':
                networks = [n for n in networks if n['risk_level'] in ('critical', 'high')]

            # Sort: risk score desc, then rssi desc
            networks.sort(
                key=lambda n: (
                    self._get_risk_score(n['risk_level']),
                    n.get('rssi') or -999
                ),
                reverse=True
            )

            return networks
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Geometry
    # ------------------------------------------------------------------

    def _point_in_polygon(self, lat: float, lon: float, polygon: list) -> bool:
        """Ray-casting algorithm. polygon is list of [lon, lat] pairs (GeoJSON order)."""
        n = len(polygon)
        inside = False

        j = n - 1
        for i in range(n):
            xi, yi = polygon[i][0], polygon[i][1]
            xj, yj = polygon[j][0], polygon[j][1]

            if ((yi > lat) != (yj > lat)) and \
               (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi):
                inside = not inside
            j = i

        return inside

    # ------------------------------------------------------------------
    # Risk categorization
    # ------------------------------------------------------------------

    def categorize_risk(self, network: dict) -> str:
        """
        Categorize a network's risk level based on auth_mode and SSID patterns.
        Returns: 'critical', 'high', 'medium', or 'low'.
        """
        auth = (network.get('auth_mode') or '').upper()
        ssid = (network.get('ssid') or '').lower()

        # CRITICAL
        if not auth or auth.strip('[] ') == '':
            return 'critical'
        if 'OPEN' in auth or 'WEP' in auth:
            return 'critical'

        # Setup-mode IoT SSIDs without WPA3
        iot_setup_patterns = ('ring setup', 'hp-setup', 'blink-', 'direct-', 'ecovacs')
        if any(p in ssid for p in iot_setup_patterns) and 'WPA3' not in auth:
            return 'critical'

        # HIGH
        if 'WPS' in auth:
            return 'high'
        if 'WPA' in auth and 'WPA2' not in auth and 'WPA3' not in auth:
            return 'high'
        if 'WPA_WPA2' in auth:
            return 'high'

        guest_patterns = ('guest', 'public', 'visitor', 'free wifi', 'free-wifi')
        if any(p in ssid for p in guest_patterns):
            return 'high'

        # LOW (checked before MEDIUM so WPA3/Enterprise aren't caught)
        if 'WPA3' in auth:
            return 'low'
        if 'WPA2_WPA3' in auth:
            return 'low'
        if 'ENTERPRISE' in auth or 'EAP' in auth:
            return 'low'

        # MEDIUM
        if 'WPA2' in auth:
            return 'medium'

        return 'medium'

    def _get_risk_score(self, risk_level: str) -> int:
        """Return numeric weight for a risk level string."""
        return RISK_WEIGHTS.get(risk_level, 0)

    # ------------------------------------------------------------------
    # Time / statistics helpers
    # ------------------------------------------------------------------

    def _get_assessment_period(self, networks: List[dict]) -> str:
        """Determine the assessment time window from network dates."""
        if not networks:
            today = datetime.now().strftime('%Y-%m-%d')
            return f"{today} to {today}"

        dates: List[str] = []
        for n in networks:
            if n.get('first_seen'):
                dates.append(n['first_seen'])
            if n.get('last_updated'):
                dates.append(n['last_updated'])

        if not dates:
            today = datetime.now().strftime('%Y-%m-%d')
            return f"{today} to {today}"

        def to_date(s: str):
            """Extract valid date, or None for malformed."""
            candidate = s[:10]
            try:
                return datetime.strptime(candidate, '%Y-%m-%d')
            except (ValueError, TypeError):
                return None

        valid_dates = [to_date(d) for d in dates]
        valid_dates = [d for d in valid_dates if d is not None]
        if not valid_dates:
            today = datetime.now().strftime('%m/%d/%Y')
            return f"{today} to {today}"

        valid_dates.sort()
        fmt = '%m/%d/%Y'
        return f"{valid_dates[0].strftime(fmt)} to {valid_dates[-1].strftime(fmt)}"

    def _get_report_statistics(self, networks: List[dict]) -> dict:
        """Compute summary statistics across the provided network list."""
        total = len(networks)

        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for n in networks:
            level = n.get('risk_level', 'medium')
            if level in risk_counts:
                risk_counts[level] += 1

        risk_percentages = {}
        for level, count in risk_counts.items():
            risk_percentages[level] = round((count / total * 100) if total > 0 else 0.0, 1)

        auth_counts = {'OPEN': 0, 'WEP': 0, 'WPA': 0, 'WPA2': 0, 'WPA3': 0}
        for n in networks:
            auth = (n.get('auth_mode') or '').upper()
            if 'OPEN' in auth or not auth.strip('[] '):
                auth_counts['OPEN'] += 1
            elif 'WEP' in auth:
                auth_counts['WEP'] += 1
            elif 'WPA3' in auth:
                auth_counts['WPA3'] += 1
            elif 'WPA2' in auth:
                auth_counts['WPA2'] += 1
            elif 'WPA' in auth:
                auth_counts['WPA'] += 1
            else:
                auth_counts['OPEN'] += 1

        channels = set()
        for n in networks:
            ch = n.get('channel')
            if ch is not None:
                channels.add(ch)

        rssi_values = [n['rssi'] for n in networks if n.get('rssi') is not None]
        avg_rssi = round(sum(rssi_values) / len(rssi_values), 1) if rssi_values else 0.0

        tagged_counts = {'primary': 0, 'secondary': 0, 'out_of_scope': 0}
        for n in networks:
            tag = n.get('target_tag')
            if tag in tagged_counts:
                tagged_counts[tag] += 1

        return {
            'total_networks': total,
            'risk_counts': risk_counts,
            'risk_percentages': risk_percentages,
            'auth_counts': auth_counts,
            'unique_channels': len(channels),
            'avg_rssi': avg_rssi,
            'tagged_counts': tagged_counts,
        }

    # ------------------------------------------------------------------
    # Exploitability and impact scoring
    # ------------------------------------------------------------------

    def _calculate_exploitability(self, network: dict) -> dict:
        """Calculate exploitability metrics for a single network."""
        auth = (network.get('auth_mode') or '').upper()
        rssi = network.get('rssi') or -90

        score = 50
        attack_time = '4-24 hours'
        attack_method = 'Handshake capture + offline cracking'
        complexity = 'Medium'

        if 'OPEN' in auth or not auth.strip('[] '):
            score, attack_time = 95, 'Immediate'
            attack_method, complexity = 'Direct connection, no credentials needed', 'Trivial'
        elif 'WEP' in auth:
            score, attack_time = 90, '< 5 minutes'
            attack_method, complexity = 'aircrack-ng statistical key recovery', 'Easy'
        elif 'WPA_WPA2' in auth:
            score, attack_time = 65, '2-6 hours'
            attack_method, complexity = 'Force WPA downgrade + TKIP attack', 'Medium'
        elif 'WPA2_WPA3' in auth:
            score, attack_time = 35, 'Days'
            attack_method, complexity = 'Limited — must target WPA2 clients', 'Hard'
        elif 'WPA3' in auth:
            score, attack_time = 20, 'Days to infeasible'
            attack_method, complexity = 'SAE handshake resistant to offline attacks', 'Hard'
        elif 'WPA2' in auth:
            score, attack_time = 50, '4-24 hours'
            attack_method, complexity = '4-way handshake capture + GPU brute force', 'Medium'
        elif 'WPA' in auth:
            score, attack_time = 70, '1-4 hours'
            attack_method, complexity = 'PMKID capture + dictionary/GPU cracking', 'Medium'

        # Signal-strength modifier
        if rssi >= -65:
            score += 10
        elif rssi >= -72:
            score += 5
        elif rssi <= -85:
            score -= 10

        score = max(0, min(100, score))

        return {
            'score': score,
            'attack_time': attack_time,
            'attack_method': attack_method,
            'complexity': complexity,
        }

    def _calculate_impact(self, network: dict) -> dict:
        """Estimate business/data impact if the network is compromised."""
        ssid = (network.get('ssid') or '').lower()

        if any(kw in ssid for kw in ('medical', 'clinic', 'hospital', 'health')):
            return {'score': 95, 'impact_type': 'Healthcare network access',
                    'data_risk': 'PHI/patient data — HIPAA violation'}

        if any(kw in ssid for kw in ('bank', 'finance', 'credit', 'payment')):
            return {'score': 95, 'impact_type': 'Financial network access',
                    'data_risk': 'Financial data — PCI-DSS scope'}

        if any(kw in ssid for kw in ('corp', 'office', 'enterprise', 'internal', 'business')):
            return {'score': 90, 'impact_type': 'Corporate network access',
                    'data_risk': 'Business data, credentials, internal systems'}

        if any(kw in ssid for kw in ('camera', 'doorbell', 'thermostat', 'sensor', 'printer')):
            return {'score': 60, 'impact_type': 'IoT device control',
                    'data_risk': 'Physical security, surveillance access'}

        if any(kw in ssid for kw in ('guest', 'visitor', 'public')):
            return {'score': 40, 'impact_type': 'Guest network access',
                    'data_risk': 'Limited — isolated guest network'}

        residential_kw = (
            'netgear', 'linksys', 'tp-link', 'tplink', 'asus', 'dlink', 'd-link',
            'spectrum', 'xfinity', 'att', 'verizon', 'tmobile', 't-mobile',
            'frontier', 'cox', 'comcast', 'arris', 'motorola', 'ubee',
            'home', 'mynetwork', 'setup',
        )
        if any(kw in ssid for kw in residential_kw):
            return {'score': 50, 'impact_type': 'Home network access',
                    'data_risk': 'Personal data, connected devices'}

        return {'score': 55, 'impact_type': 'Network access',
                'data_risk': 'Connected devices and traffic'}

    # ------------------------------------------------------------------
    # Priority targets
    # ------------------------------------------------------------------

    def _get_priority_targets(self, networks: List[dict], limit: int = 10) -> List[dict]:
        """Identify the highest-priority targets by exploitability + impact."""
        targets: List[dict] = []

        for net in networks:
            exploitability = self._calculate_exploitability(net)
            impact = self._calculate_impact(net)
            priority_score = round((exploitability['score'] + impact['score']) / 2, 1)

            targets.append({
                'mac': net.get('mac'),
                'ssid': net.get('ssid'),
                'auth_mode': net.get('auth_mode'),
                'rssi': net.get('rssi'),
                'risk_level': net.get('risk_level'),
                'priority_score': priority_score,
                'exploitability': exploitability,
                'impact': impact,
            })

        targets.sort(key=lambda t: t['priority_score'], reverse=True)
        return targets[:limit]

    # ------------------------------------------------------------------
    # Vulnerability analysis
    # ------------------------------------------------------------------

    def _get_vulnerability_analysis(self, networks: List[dict]) -> List[dict]:
        """Group networks by vulnerability type and return structured analysis."""
        open_nets: List[dict] = []
        wep_nets: List[dict] = []
        wpa_only_nets: List[dict] = []
        wpa_wpa2_nets: List[dict] = []
        wpa2_nets: List[dict] = []

        for net in networks:
            auth = (net.get('auth_mode') or '').upper()
            if 'OPEN' in auth or not auth.strip('[] '):
                open_nets.append(net)
            elif 'WEP' in auth:
                wep_nets.append(net)
            elif 'WPA_WPA2' in auth:
                wpa_wpa2_nets.append(net)
            elif 'WPA2' not in auth and 'WPA3' not in auth and 'WPA' in auth:
                wpa_only_nets.append(net)
            elif 'WPA2' in auth and 'WPA3' not in auth:
                wpa2_nets.append(net)

        analysis: List[dict] = []

        if open_nets:
            analysis.append({
                'name': 'Unencrypted Networks',
                'severity': 'CRITICAL',
                'severity_color': '#e74c3c',
                'count': len(open_nets),
                'description': (
                    'Networks transmitting all data in plaintext. Any device within '
                    'range can passively intercept all traffic including credentials, '
                    'emails, and session tokens.'
                ),
                'plain_description': 'Anyone within range of your building can connect to these networks without a password. Once connected, they have the same access as your employees — including any shared files, printers, cameras, and potentially point-of-sale systems.',
                'attack_method': 'Connect directly — no password required',
                'attack_time': 'Immediate',
                'tools': 'Any WiFi-capable device',
                'skill_level': 'None',
                'remediation': 'Enable WPA2-PSK or WPA3-SAE encryption',
                'remediation_cost': '$0 (configuration change)',
                'remediation_time': '30-60 minutes per access point',
                'networks': open_nets,
            })

        if wep_nets:
            analysis.append({
                'name': 'WEP Encryption',
                'severity': 'CRITICAL',
                'severity_color': '#e74c3c',
                'count': len(wep_nets),
                'description': (
                    'WEP encryption is cryptographically broken. The static key can '
                    'be recovered in minutes by passively capturing traffic, regardless '
                    'of key length or complexity.'
                ),
                'plain_description': 'Using freely available software, an attacker passively records your WiFi traffic for a few minutes, then mathematically recovers your encryption key. This works 100% of the time regardless of password complexity. WEP has been considered broken since 2004.',
                'attack_method': 'Capture ~40,000 IVs then run aircrack-ng for key recovery',
                'attack_time': '< 5 minutes',
                'tools': 'aircrack-ng suite, compatible wireless adapter',
                'skill_level': 'Low',
                'remediation': 'Upgrade to WPA2-PSK or WPA3-SAE; replace hardware if it only supports WEP',
                'remediation_cost': '$0-150 (config change or AP replacement)',
                'remediation_time': '30-60 minutes per access point',
                'networks': wep_nets,
            })

        if wpa_only_nets:
            analysis.append({
                'name': 'Legacy WPA (TKIP)',
                'severity': 'HIGH',
                'severity_color': '#e67e22',
                'count': len(wpa_only_nets),
                'description': (
                    'WPA with TKIP encryption has known vulnerabilities including '
                    'the Beck-Tews and Ohigashi-Morii attacks. PMKID-based attacks '
                    'allow offline key recovery without capturing a full handshake.'
                ),
                'plain_description': 'An attacker can extract your encrypted password signature without even connecting to your network, then use powerful computers to guess your password offline. Common passwords like "BusinessName2024" or "wifi12345" are cracked in seconds.',
                'attack_method': 'PMKID capture + dictionary/GPU cracking',
                'attack_time': '1-4 hours',
                'tools': 'hcxdumptool, hashcat, wordlists',
                'skill_level': 'Moderate',
                'remediation': 'Upgrade to WPA2-AES (CCMP) or WPA3-SAE',
                'remediation_cost': '$0 (configuration change)',
                'remediation_time': '20-45 minutes per access point',
                'networks': wpa_only_nets,
            })

        if wpa_wpa2_nets:
            analysis.append({
                'name': 'WPA/WPA2 Mixed Mode',
                'severity': 'HIGH',
                'severity_color': '#e67e22',
                'count': len(wpa_wpa2_nets),
                'description': (
                    'Mixed WPA/WPA2 mode allows clients to connect using WPA-TKIP, '
                    'enabling downgrade attacks. An attacker can force the weaker '
                    'protocol and exploit TKIP vulnerabilities.'
                ),
                'plain_description': 'An attacker can force your network to use its weakest security setting, then exploit known flaws in that weaker mode to gain access. This is like having a strong front door but leaving the back door on a simple latch.',
                'attack_method': 'Force WPA downgrade via deauth + rogue AP, then TKIP attack',
                'attack_time': '2-6 hours',
                'tools': 'hostapd-mana, aircrack-ng, hashcat',
                'skill_level': 'Moderate',
                'remediation': 'Disable WPA compatibility; use WPA2-only or WPA3',
                'remediation_cost': '$0 (configuration change)',
                'remediation_time': '20-45 minutes per access point',
                'networks': wpa_wpa2_nets,
            })

        if wpa2_nets:
            analysis.append({
                'name': 'Standard WPA2',
                'severity': 'MEDIUM',
                'severity_color': '#f39c12',
                'count': len(wpa2_nets),
                'description': (
                    'WPA2-PSK is the current baseline standard. While not immediately '
                    'vulnerable, it is susceptible to offline brute-force attacks if '
                    'a weak passphrase is used. Consider upgrading to WPA3 where possible.'
                ),
                'plain_description': 'An attacker waits for any device to connect to your WiFi, records the encrypted connection process, then takes that recording offline to crack the password using specialized hardware. Strong passwords (14+ random characters) make this significantly harder.',
                'attack_method': '4-way handshake capture + GPU brute force',
                'attack_time': '4-24 hours (passphrase dependent)',
                'tools': 'hcxdumptool, hashcat, GPU cluster',
                'skill_level': 'Moderate to High',
                'remediation': 'Use strong passphrases (14+ chars); upgrade to WPA3-SAE',
                'remediation_cost': '$0 (configuration change) to $100+ (AP upgrade)',
                'remediation_time': '20-45 minutes per access point',
                'networks': wpa2_nets,
            })

        return analysis

    # ------------------------------------------------------------------
    # Remediation roadmap
    # ------------------------------------------------------------------

    def _get_remediation_roadmap(self, networks: List[dict]) -> List[dict]:
        """Build a prioritized remediation roadmap. Only includes items with affected networks."""
        open_count = wep_count = wpa_only_count = wpa_wpa2_count = wpa2_count = wps_count = 0

        for net in networks:
            auth = (net.get('auth_mode') or '').upper()
            if 'OPEN' in auth or not auth.strip('[] '):
                open_count += 1
            elif 'WEP' in auth:
                wep_count += 1
            elif 'WPA_WPA2' in auth:
                wpa_wpa2_count += 1
            elif 'WPA2' not in auth and 'WPA3' not in auth and 'WPA' in auth:
                wpa_only_count += 1
            elif 'WPA2' in auth and 'WPA3' not in auth:
                wpa2_count += 1
            if 'WPS' in auth:
                wps_count += 1

        roadmap: List[dict] = []
        priority = 0

        if open_count > 0:
            priority += 1
            roadmap.append({
                'priority': priority,
                'action': 'Secure unencrypted networks',
                'description': 'Enable WPA2-PSK or WPA3 on all open access points',
                'risk_reduction': 'Eliminates immediate unauthorized access',
                'cost': '$0 (configuration change)',
                'time': '30-60 minutes per access point',
                'affected_count': open_count,
                'compliance': 'PCI-DSS Req. 4.1, HIPAA \u00a7164.312(e)(1)',
            })

        if wep_count > 0:
            priority += 1
            roadmap.append({
                'priority': priority,
                'action': 'Replace WEP encryption',
                'description': 'Upgrade all WEP access points to WPA2-PSK or WPA3-SAE; replace hardware that only supports WEP',
                'risk_reduction': 'Eliminates trivially breakable encryption',
                'cost': '$0-150 per device (config change or AP replacement)',
                'time': '30-90 minutes per access point',
                'affected_count': wep_count,
                'compliance': 'PCI-DSS Req. 4.1, NIST SP 800-153',
            })

        if wpa_only_count > 0:
            priority += 1
            roadmap.append({
                'priority': priority,
                'action': 'Upgrade legacy WPA to WPA2/WPA3',
                'description': 'Disable TKIP and enable AES-CCMP on all WPA-only access points',
                'risk_reduction': 'Removes TKIP vulnerabilities and PMKID attack surface',
                'cost': '$0 (configuration change)',
                'time': '20-45 minutes per access point',
                'affected_count': wpa_only_count,
                'compliance': 'PCI-DSS Req. 4.1',
            })

        if wpa_wpa2_count > 0:
            priority += 1
            roadmap.append({
                'priority': priority,
                'action': 'Disable WPA/WPA2 mixed mode',
                'description': 'Switch to WPA2-only or WPA3-only to prevent protocol downgrade attacks',
                'risk_reduction': 'Prevents forced downgrade to weaker WPA-TKIP',
                'cost': '$0 (configuration change)',
                'time': '20-45 minutes per access point',
                'affected_count': wpa_wpa2_count,
                'compliance': 'CIS Controls v8 \u2014 Control 3.10',
            })

        if wps_count > 0:
            priority += 1
            roadmap.append({
                'priority': priority,
                'action': 'Disable WPS on all access points',
                'description': 'WPS PIN brute-force can recover the PSK regardless of password complexity',
                'risk_reduction': 'Removes PIN brute-force bypass of WPA2 passwords',
                'cost': '$0 (configuration change)',
                'time': '10-20 minutes per access point',
                'affected_count': wps_count,
                'compliance': 'CIS Controls v8 \u2014 Control 3.10',
            })

        if wpa2_count > 0:
            priority += 1
            roadmap.append({
                'priority': priority,
                'action': 'Upgrade WPA2 to WPA3 where supported',
                'description': 'Enable WPA3-SAE on compatible access points; enforce strong passphrases on remaining WPA2 devices',
                'risk_reduction': 'Adds forward secrecy and resistance to offline dictionary attacks',
                'cost': '$0-200 per device (firmware update or AP replacement)',
                'time': '30-90 minutes per access point',
                'affected_count': wpa2_count,
                'compliance': 'WPA3 recommended by CISA, NSA cybersecurity guidance',
            })

        return roadmap

    # ------------------------------------------------------------------
    # Overall risk score
    # ------------------------------------------------------------------

    def _calculate_overall_risk_score(self, networks: List[dict]) -> Tuple[int, str]:
        """Calculate composite risk score (0-100) and risk level."""
        total = len(networks)
        if total == 0:
            return (0, 'low')

        critical = sum(1 for n in networks if n.get('risk_level') == 'critical')
        high = sum(1 for n in networks if n.get('risk_level') == 'high')
        medium = sum(1 for n in networks if n.get('risk_level') == 'medium')

        base = min(critical * 40, 100) + min(high * 20, 60) + min(medium * 5, 20)
        ratio_bonus = (critical / total) * 10 + (high / total) * 10
        score = min(100, int(base + ratio_bonus))

        if score >= 30:
            level = 'critical'
        elif score >= 25:
            level = 'high'
        elif score >= 20:
            level = 'moderate'
        else:
            level = 'low'

        return (score, level)

    # ------------------------------------------------------------------
    # HTML Template
    # ------------------------------------------------------------------

    def _get_inline_template(self, template_name):
        """Returns a complete Jinja2 HTML template string for the assessment report."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{{ title }}</title>
<style>
/* PAGE SETUP */
@page {
    size: letter;
    margin: 1in 0.85in 0.8in 1in;
    @top-left {
        content: "Wireless Security Assessment";
        font-size: 8pt;
        color: #aaa;
    }
    @top-right {
        content: "S.P.A.R.K. Initiative Labs";
        font-size: 8pt;
        color: #aaa;
    }
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 8pt;
        color: #aaa;
    }
    @bottom-right {
        content: "CONFIDENTIAL";
        font-size: 7pt;
        color: #ccc;
        letter-spacing: 1px;
    }
}
@page :first {
    margin: 0;
    @top-left { content: none; }
    @top-right { content: none; }
    @bottom-center { content: none; }
    @bottom-right { content: none; }
}

/* BASE TYPOGRAPHY */
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: "Inter", "Helvetica Neue", Helvetica, Arial, sans-serif;
    font-size: 12pt;
    line-height: 1.6;
    color: #293241;
    background: #ffffff;
    padding: 0.5in 1in;
}
h1 {
    font-size: 22pt; font-weight: 700; color: #293241;
    margin-top: 36px; margin-bottom: 14px; padding-bottom: 8px;
    border-bottom: 2px solid #27ae60;
    letter-spacing: -0.2px;
}
h2 {
    font-size: 16pt; font-weight: 700; color: #293241;
    margin-top: 32px; margin-bottom: 12px;
    padding-bottom: 6px; border-bottom: 1.5px solid #ddd;
}
h3 {
    font-size: 14pt; font-weight: 600; color: #293241;
    margin-top: 16px; margin-bottom: 10px;
}
h1, h2, h3 { page-break-after: avoid; }
thead { display: table-header-group; }
p { margin-bottom: 12px; }
a { color: #1E4CA1; text-decoration: none; }

/* LAYOUT HELPERS */
.clearfix::after { content: ""; display: table; clear: both; }
.col-25 { float: left; width: 23%; margin: 0 1%; }
.col-50 { float: left; width: 48%; margin: 0 1%; }
.page-break { page-break-before: always; }
.no-break { page-break-inside: avoid; }

/* COVER PAGE */
.cover-page {
    width: 100%; min-height: 11in; text-align: center;
    padding-top: 140px; page-break-after: always;
    background: linear-gradient(135deg, #1a2332 0%, #1E4CA1 60%, #293241 100%);
    color: #ffffff;
}
.cover-logo { width: 180px; height: 180px; margin: 0 auto 20px auto; }
.cover-logo img { width: 100%; height: 100%; }
.cover-brand {
    font-size: 20pt; font-weight: 700; color: #ffffff;
    letter-spacing: 2.5px; margin-bottom: 6px;
}
.cover-subtitle { font-size: 14pt; font-weight: 300; color: #a8c4e0; margin-bottom: 30px; letter-spacing: 2px; }
.cover-line {
    width: 280px; height: 5px; margin: 0 auto 30px auto;
    background: linear-gradient(90deg, #27ae60, #2ecc71);
    border-radius: 3px;
}
.cover-client { font-size: 22pt; font-weight: 600; color: #ffffff; margin-bottom: 16px; }
.cover-period { font-size: 13pt; color: #a8c4e0; margin-bottom: 6px; }
.cover-date { font-size: 12pt; color: #7a9cc6; margin-bottom: 60px; }
.cover-confidential {
    font-size: 10pt; color: #c0d0e0; max-width: 460px;
    margin: 0 auto; line-height: 1.7; padding: 20px 24px;
    border: 1px solid rgba(255,255,255,0.15); border-radius: 6px;
    background: rgba(0,0,0,0.2);
}

/* STAT CARDS */
.stat-card {
    float: left; width: 21.5%; margin: 0 1.25%;
    padding: 20px 14px; text-align: center;
    background: #ffffff; border: 1px solid #e8e8e8;
    border-radius: 8px; page-break-inside: avoid;
    /* box-shadow removed for print */
}
.stat-card-critical { border-top: 4px solid #e74c3c; background: linear-gradient(135deg, #ffffff 0%, #fef0ef 100%); }
.stat-card-high { border-top: 4px solid #e67e22; background: linear-gradient(135deg, #ffffff 0%, #fef6ee 100%); }
.stat-card-medium { border-top: 4px solid #f39c12; background: linear-gradient(135deg, #ffffff 0%, #fef8ee 100%); }
.stat-card-low { border-top: 4px solid #27ae60; background: linear-gradient(135deg, #ffffff 0%, #eef8f0 100%); }
.stat-number { font-size: 30pt; font-weight: 800; line-height: 1.2; }
.stat-label { font-size: 11pt; color: #666; text-transform: uppercase; letter-spacing: 1.2px; margin-top: 6px; font-weight: 600; }
.stat-pct { font-size: 11pt; color: #888; margin-top: 3px; }
.critical-color { color: #e74c3c; }
.high-color { color: #e67e22; }
.medium-color { color: #f39c12; }
.low-color { color: #27ae60; }

/* GAUGE */
.gauge-container { text-align: center; margin: 24px 0 28px 0; }
.gauge-container svg { }

/* SUMMARY BOX */
.summary-box {
    background: linear-gradient(135deg, #f8f9fa 0%, #f0f4f8 100%);
    border-left: 5px solid #1E4CA1;
    padding: 18px 22px; margin: 20px 0; font-size: 12pt; line-height: 1.7;
    border-radius: 0 6px 6px 0;
    /* box-shadow removed for print */
}

/* KEY FINDINGS */
.finding-list { list-style: none; padding: 0; margin: 10px 0; }
.finding-list li {
    padding: 8px 0 8px 28px; position: relative;
    border-bottom: 1px solid #f0f0f0; page-break-inside: avoid;
}
.finding-list li::before {
    content: "\\26A0"; position: absolute; left: 4px; top: 10px;
    color: #e67e22; font-size: 14pt;
}
.finding-critical::before { content: "\\2716" !important; color: #e74c3c !important; }
.finding-info::before { content: "\\2139" !important; color: #3498db !important; }

/* TABLES */
table { width: 100%; border-collapse: collapse; margin: 14px 0 22px 0; font-size: 11pt; table-layout: fixed; }
th {
    background: linear-gradient(135deg, #293241 0%, #3d5a80 100%); color: #ffffff;
    padding: 11px 14px; text-align: left; font-weight: 600; font-size: 11pt;
    text-transform: uppercase; letter-spacing: 0.8px;
    word-break: break-word; overflow-wrap: break-word;
}
td { padding: 10px 14px; border-bottom: 1px solid #eaeaea; word-break: break-word; overflow-wrap: break-word; }
tr:nth-child(even) { background: #f7f8fa; }
tr { page-break-inside: avoid; }

/* BADGES */
.badge {
    display: inline-block; padding: 3px 10px; border-radius: 4px;
    font-size: 11pt; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.6px; color: #ffffff;
    max-width: 100%; overflow: hidden; text-overflow: ellipsis;
}
.badge-critical { background: #e74c3c; }
.badge-high { background: #d35400; }
.badge-medium { background: #f39c12; }
.badge-low { background: #27ae60; }
.badge-severity {
    display: inline-block; padding: 3px 12px; border-radius: 4px;
    font-size: 11pt; font-weight: 700; color: #ffffff;
}

/* VULNERABILITY CARDS */
.vuln-card {
    border: 1px solid #e8e8e8; border-radius: 8px;
    margin: 18px 0; padding: 20px 22px; page-break-inside: avoid;
    /* box-shadow removed for print */
}
.vuln-card-critical { border-left: 5px solid #e74c3c; }
.vuln-card-high { border-left: 5px solid #e67e22; }
.vuln-card-medium { border-left: 5px solid #f39c12; }
.vuln-card-low { border-left: 5px solid #27ae60; }
.vuln-header { margin-bottom: 12px; }
.vuln-title { font-size: 14pt; font-weight: 700; color: #293241; margin-right: 10px; }
.vuln-count { font-size: 11pt; color: #666; }
.vuln-description { margin: 10px 0 14px 0; color: #444; line-height: 1.7; font-size: 11pt; }
.vuln-info-grid {
    display: table; width: 100%; margin: 12px 0;
    background: #f5f7fa; border-radius: 6px; padding: 12px;
    table-layout: fixed;
}
.vuln-info-row { display: table-row; }
.vuln-info-label {
    display: table-cell; width: 150px; padding: 6px 12px;
    font-weight: 600; font-size: 11pt; color: #555; vertical-align: top;
}
.vuln-info-value {
    display: table-cell; padding: 6px 12px;
    font-size: 11pt; color: #293241; vertical-align: top;
    word-break: break-word; overflow-wrap: break-word;
}
.remediation-box {
    border-left: 4px solid #27ae60; background: linear-gradient(135deg, #f0faf4 0%, #e8f5ec 100%);
    padding: 14px 18px; margin-top: 14px; border-radius: 0 6px 6px 0;
}
.remediation-box h4 {
    color: #27ae60; font-size: 11pt; margin-bottom: 8px;
    text-transform: uppercase; letter-spacing: 0.8px; font-weight: 700;
}
.remediation-box p { margin: 5px 0; font-size: 11pt; color: #333; }
.remediation-meta { font-size: 11pt; color: #777; margin-top: 8px; }

.affected-networks { margin-top: 12px; font-size: 11pt; }
.affected-networks th { background: #7f8c8d; font-size: 11pt; padding: 6px 10px; }
.affected-networks td { padding: 6px 10px; font-size: 11pt; }

/* ROADMAP */
.roadmap-item {
    border: 1px solid #e8e8e8; border-radius: 8px;
    padding: 16px 20px; margin: 14px 0; page-break-inside: avoid;
    /* box-shadow removed for print */
}
.roadmap-priority {
    display: inline-block; width: 32px; height: 32px; line-height: 32px;
    text-align: center; border-radius: 50%;
    background: linear-gradient(135deg, #293241 0%, #3d5a80 100%);
    color: #ffffff; font-weight: 700; font-size: 13pt; margin-right: 12px;
    vertical-align: middle;
}
.roadmap-action { font-size: 13pt; font-weight: 700; color: #293241; vertical-align: middle; }
.roadmap-description { margin: 10px 0; color: #444; font-size: 11pt; line-height: 1.6; }
.roadmap-meta { display: table; width: 100%; margin-top: 10px; table-layout: fixed; }
.roadmap-meta-item { display: table-cell; font-size: 11pt; color: #666; word-break: break-word; overflow-wrap: break-word; padding-right: 8px; }
.roadmap-meta-item strong { color: #293241; }
.compliance-ref { font-size: 11pt; color: #888; font-style: italic; margin-top: 6px; }

/* CTA */
.cta-section { margin: 24px 0; }
.cta-steps { list-style: none; padding: 0; margin: 16px 0 28px 0; }
.cta-steps li { padding: 14px 0 14px 48px; position: relative; border-bottom: 1px solid #eee; font-size: 12pt; line-height: 1.6; }
.cta-step-num {
    position: absolute; left: 0; top: 12px; width: 32px; height: 32px;
    line-height: 32px; text-align: center; border-radius: 50%;
    background: linear-gradient(135deg, #27ae60, #2ecc71);
    color: #ffffff; font-weight: 700; font-size: 13pt;
    /* box-shadow removed for print */
}
.contact-block {
    text-align: center; padding: 28px 0; margin: 24px 0;
    border-top: 3px solid #27ae60; border-bottom: 3px solid #27ae60;
    background: linear-gradient(135deg, #f8fdf9 0%, #f0faf4 100%);
    border-radius: 8px;
}
.contact-brand { font-size: 18pt; font-weight: 800; color: #293241; margin-bottom: 6px; letter-spacing: 1px; }
.contact-tagline { font-size: 12pt; color: #666; margin-bottom: 8px; }
.contact-url { font-size: 12pt; color: #27ae60; font-weight: 700; }

/* SERVICE TIERS */
.tiers-container { margin: 28px 0; }
.tier-card {
    float: left; width: 31%; margin: 0 1.16%;
    border: 1px solid #e0e0e0; border-radius: 10px;
    padding: 24px 18px; text-align: center; page-break-inside: avoid;
    /* box-shadow removed for print */
}
.tier-card-featured {
    border: 3px solid #27ae60;
    background: linear-gradient(135deg, #f0faf4 0%, #e4f5ea 100%);
    /* box-shadow removed for print */
}
.tier-name { font-size: 15pt; font-weight: 700; color: #293241; margin-bottom: 6px; }
.tier-price { font-size: 22pt; font-weight: 700; color: #27ae60; margin-bottom: 10px; }
.tier-desc { font-size: 11pt; color: #555; line-height: 1.6; }
.tier-featured-label {
    display: inline-block; color: #ffffff;
    background: linear-gradient(135deg, #27ae60, #2ecc71);
    font-size: 11pt; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1.2px; padding: 4px 14px; border-radius: 4px; margin-bottom: 10px;
    /* box-shadow removed for print */
}

/* FOOTER */
.report-footer {
    margin-top: 40px; padding-top: 20px; border-top: 3px solid #e8e8e8;
    font-size: 11pt; color: #888; line-height: 1.8;
}
.report-footer strong { color: #555; }

/* UTILITY */
.text-center { text-align: center; }
.text-right { text-align: right; }
.text-muted { color: #999; }
.text-small { font-size: 11pt; }
.mt-10 { margin-top: 10px; }
.mt-20 { margin-top: 20px; }
.mb-10 { margin-bottom: 10px; }
.mb-20 { margin-bottom: 20px; }

/* METHOD LIST */
.method-list { list-style: none; padding: 0; margin: 10px 0 16px 0; }
.method-list li { padding: 6px 0 6px 24px; position: relative; font-size: 11pt; line-height: 1.6; }
.method-list li::before { content: "\\2713"; position: absolute; left: 2px; color: #27ae60; font-weight: 700; }
.method-list-no li::before { content: "\\2717"; color: #e74c3c; }

/* SIGNAL BARS */
.signal-bar {
    display: inline-block; width: 50px; height: 8px;
    background: #ecf0f1; border-radius: 4px; overflow: hidden; vertical-align: middle;
}
.signal-fill { height: 100%; border-radius: 4px; }
.signal-excellent { width: 100%; background: #27ae60; }
.signal-good { width: 75%; background: #27ae60; }
.signal-fair { width: 50%; background: #f39c12; }
.signal-weak { width: 25%; background: #e74c3c; }
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover-page">
    <div style="padding: 8px 0; font-size: 9pt; letter-spacing: 3px; color: rgba(255,255,255,0.4); text-transform: uppercase; margin-bottom: 30px;">CONFIDENTIAL &mdash; CLIENT PRIVILEGED</div>
    {% if logo_base64 %}
    <div class="cover-logo"><img src="data:image/png;base64,{{ logo_base64 }}" alt="S.P.A.R.K. Initiative Labs"></div>
    {% endif %}
    <div class="cover-brand">S.P.A.R.K. INITIATIVE LABS</div>
    <div class="cover-subtitle">Wireless Security Assessment</div>
    <div class="cover-line"></div>
    <div class="cover-client">{{ client_name }}</div>
    <div class="cover-period">Assessment Period: {{ assessment_period }}</div>
    <div class="cover-date">Generated: {{ generated_date }}</div>
    <div style="font-size: 11pt; color: #7a9cc6; margin-bottom: 40px; letter-spacing: 1.5px;">Report ID: SPARK-{{ report_id }}</div>
    <div class="cover-confidential">
        <strong>CONFIDENTIAL</strong><br>
        This document contains sensitive security findings and vulnerability details
        pertaining to the wireless network infrastructure of {{ client_name }}.
        Distribution is restricted to authorized personnel only. Unauthorized
        disclosure, copying, or distribution of this document is strictly prohibited.
    </div>
</div>

<!-- TABLE OF CONTENTS -->
<h1 style="margin-top: 0;">Table of Contents</h1>
<div style="font-size: 12pt; line-height: 2.4; color: #293241;">
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>1.</strong> Assessment Methodology</div>
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>2.</strong> Risk Assessment Overview</div>
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>3.</strong> Key Findings</div>
    {% if report_type != 'executive' %}
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>4.</strong> Attack Priority Matrix</div>
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>5.</strong> Vulnerability Analysis</div>
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>6.</strong> Remediation Roadmap</div>
    {% endif %}
    {% if report_type == 'full' %}
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>7.</strong> Tagged Targets</div>
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>8.</strong> Complete Network Inventory</div>
    {% endif %}
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>{{ '4' if report_type == 'executive' else '9' if report_type == 'full' else '7' }}.</strong> Risk of Inaction</div>
    <div style="border-bottom: 1px dotted #ccc; padding: 4px 0;"><strong>{{ '5' if report_type == 'executive' else '10' if report_type == 'full' else '8' }}.</strong> Recommended Next Steps</div>
    {% if report_type != 'executive' %}
    <div style="padding: 4px 0;"><strong>{{ '11' if report_type == 'full' else '9' }}.</strong> Glossary of Terms</div>
    {% endif %}
</div>
<div class="page-break"></div>

<!-- METHODOLOGY -->
<h1><span style="color: #27ae60; margin-right: 8px;">1.</span>Assessment Methodology</h1>
<div class="summary-box">
    <p>This wireless security assessment was conducted using passive radio frequency analysis from publicly accessible areas adjacent to the client premises. <strong>No networks were accessed, no credentials were tested, and no traffic was intercepted.</strong> All observations were made using signals that your wireless access points broadcast publicly.</p>
</div>

<h3>What Was Measured</h3>
<ul class="method-list">
    <li><strong>Network names (SSIDs)</strong> broadcast by your access points</li>
    <li><strong>Encryption protocols</strong> in use (Open, WEP, WPA, WPA2, WPA3)</li>
    <li><strong>Signal strength</strong> and approximate device locations via GPS triangulation</li>
    <li><strong>Channel utilization</strong> and potential interference patterns</li>
</ul>

<h3>What Was NOT Done</h3>
<ul class="method-list method-list-no">
    <li>No passwords were cracked or tested</li>
    <li>No network traffic was captured or analyzed</li>
    <li>No devices were connected to your networks</li>
    <li>No exploitation of any vulnerability was attempted</li>
</ul>

<h3>Equipment Used</h3>
<ul class="method-list">
    <li>Extended-range directional wireless antenna</li>
    <li>GPS positioning for precise network geolocation</li>
    <li>Automated signal analysis and protocol identification software</li>
</ul>

<p class="text-muted" style="margin-top: 16px; font-size: 11pt;"><strong>Limitations:</strong> This assessment reflects wireless security posture observable from outside the premises. Internal network segmentation, firewall rules, and wired infrastructure were not evaluated.</p>

<!-- RISK ASSESSMENT OVERVIEW -->
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">2.</span>Risk Assessment Overview</h1>

<div class="gauge-container">
    <svg viewBox="0 0 240 155" style="width: 360px; height: 230px;">
        <path d="M 20,120 A 100,100 0 0,1 70,28" stroke="#27ae60" stroke-width="20" fill="none" stroke-linecap="round"/>
        <path d="M 70,28 A 100,100 0 0,1 120,18" stroke="#f39c12" stroke-width="20" fill="none"/>
        <path d="M 120,18 A 100,100 0 0,1 170,28" stroke="#e67e22" stroke-width="20" fill="none"/>
        <path d="M 170,28 A 100,100 0 0,1 220,120" stroke="#e74c3c" stroke-width="20" fill="none" stroke-linecap="round"/>
        <!-- Arc labels -->
        <text x="30" y="115" text-anchor="middle" font-size="7" fill="#888" transform="rotate(-60, 30, 115)">LOW</text>
        <text x="78" y="25" text-anchor="middle" font-size="7" fill="#888">MED</text>
        <text x="162" y="25" text-anchor="middle" font-size="7" fill="#888">HIGH</text>
        <text x="210" y="115" text-anchor="middle" font-size="7" fill="#888" transform="rotate(60, 210, 115)">CRIT</text>
        <!-- Needle -->
        {% if overall_risk >= 30 %}
        <line x1="120" y1="120" x2="{{ needle_x }}" y2="{{ needle_y }}" stroke="#e74c3c" stroke-width="4" stroke-linecap="round"/>
        {% elif overall_risk >= 25 %}
        <line x1="120" y1="120" x2="{{ needle_x }}" y2="{{ needle_y }}" stroke="#e67e22" stroke-width="4" stroke-linecap="round"/>
        {% elif overall_risk >= 20 %}
        <line x1="120" y1="120" x2="{{ needle_x }}" y2="{{ needle_y }}" stroke="#f39c12" stroke-width="4" stroke-linecap="round"/>
        {% else %}
        <line x1="120" y1="120" x2="{{ needle_x }}" y2="{{ needle_y }}" stroke="#27ae60" stroke-width="4" stroke-linecap="round"/>
        {% endif %}
        <circle cx="120" cy="120" r="7" fill="#293241"/>
        <circle cx="120" cy="120" r="3.5" fill="#ffffff"/>
        <text x="120" y="82" text-anchor="middle" font-size="32" font-weight="bold" fill="#293241">{{ overall_risk }}</text>
        <text x="120" y="148" text-anchor="middle" font-size="13" font-weight="600" fill="#555">{{ overall_risk_level|upper }} RISK</text>
    </svg>
</div>

<div class="clearfix mb-20">
    <div class="stat-card stat-card-critical">
        <div class="stat-number critical-color">{{ stats.risk_counts.critical }}</div>
        <div class="stat-label">Critical</div>
        <div class="stat-pct">{{ "%.1f"|format(stats.risk_percentages.critical) }}%</div>
    </div>
    <div class="stat-card stat-card-high">
        <div class="stat-number high-color">{{ stats.risk_counts.high }}</div>
        <div class="stat-label">High</div>
        <div class="stat-pct">{{ "%.1f"|format(stats.risk_percentages.high) }}%</div>
    </div>
    <div class="stat-card stat-card-medium">
        <div class="stat-number medium-color">{{ stats.risk_counts.medium }}</div>
        <div class="stat-label">Medium</div>
        <div class="stat-pct">{{ "%.1f"|format(stats.risk_percentages.medium) }}%</div>
    </div>
    <div class="stat-card stat-card-low">
        <div class="stat-number low-color">{{ stats.risk_counts.low }}</div>
        <div class="stat-label">Low</div>
        <div class="stat-pct">{{ "%.1f"|format(stats.risk_percentages.low) }}%</div>
    </div>
</div>

<!-- RISK DISTRIBUTION BAR -->
<div style="margin: 0 1.25% 20px 1.25%;">
    <div style="font-size: 11pt; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">Risk Distribution</div>
    <div style="width: 100%; height: 28px; border-radius: 6px; overflow: hidden;">
        {% if stats.risk_percentages.critical > 0 %}
        <div style="float: left; width: {{ stats.risk_percentages.critical }}%; height: 100%; background: #e74c3c;"></div>
        {% endif %}
        {% if stats.risk_percentages.high > 0 %}
        <div style="float: left; width: {{ stats.risk_percentages.high }}%; height: 100%; background: #e67e22;"></div>
        {% endif %}
        {% if stats.risk_percentages.medium > 0 %}
        <div style="float: left; width: {{ stats.risk_percentages.medium }}%; height: 100%; background: #f39c12;"></div>
        {% endif %}
        {% if stats.risk_percentages.low > 0 %}
        <div style="float: left; width: {{ stats.risk_percentages.low }}%; height: 100%; background: #27ae60;"></div>
        {% endif %}
    </div>
    <div style="margin-top: 5px; font-size: 11pt; color: #888;">
        {% if stats.risk_percentages.critical > 0 %}<span style="color: #e74c3c; margin-right: 14px;">&#9632; Critical {{ "%.0f"|format(stats.risk_percentages.critical) }}%</span>{% endif %}
        {% if stats.risk_percentages.high > 0 %}<span style="color: #e67e22; margin-right: 14px;">&#9632; High {{ "%.0f"|format(stats.risk_percentages.high) }}%</span>{% endif %}
        {% if stats.risk_percentages.medium > 0 %}<span style="color: #f39c12; margin-right: 14px;">&#9632; Medium {{ "%.0f"|format(stats.risk_percentages.medium) }}%</span>{% endif %}
        {% if stats.risk_percentages.low > 0 %}<span style="color: #27ae60;">&#9632; Low {{ "%.0f"|format(stats.risk_percentages.low) }}%</span>{% endif %}
    </div>
</div>

<div class="summary-box">
    {% if stats.risk_counts.critical > 0 %}
    <p>During our assessment of <strong>{{ client_name }}</strong>'s wireless infrastructure, we identified
    <strong class="critical-color">{{ stats.risk_counts.critical }} network{{ 's' if stats.risk_counts.critical != 1 else '' }}
    that can be accessed by anyone within range</strong> &mdash; no password, no hacking tools, no technical skill required.
    An attacker sitting in your parking lot could connect to these networks and potentially access point-of-sale systems,
    security cameras, internal file shares, and customer data.</p>
    {% endif %}
    {% if stats.risk_counts.high > 0 %}
    <p>An additional <strong class="high-color">{{ stats.risk_counts.high }} network{{ 's' if stats.risk_counts.high != 1 else '' }}</strong>
    use outdated encryption that can be broken using freely available software in as little as 1&ndash;4 hours.</p>
    {% endif %}
    <p>Of <strong>{{ stats.total_networks }}</strong> total wireless networks identified across {{ stats.unique_channels }} channels,
    the overall security posture is rated <strong>{{ overall_risk_level|upper }}</strong> with a risk score of
    <strong>{{ overall_risk }}/100</strong>.
    {% if stats.risk_counts.critical > 0 %}<strong>Immediate action is recommended.</strong>
    Every day these vulnerabilities remain open, your business is exposed to unauthorized network access,
    potential data theft, and regulatory liability.{% endif %}</p>
</div>

<h3>Authentication Protocol Distribution</h3>
<div class="clearfix mb-20">
    <table>
        <tr><th>Protocol</th><th>Count</th><th>Security Level</th></tr>
        {% if stats.auth_counts.get('OPEN', 0) > 0 %}
        <tr><td><strong>OPEN (No Encryption)</strong></td><td>{{ stats.auth_counts.OPEN }}</td><td><span class="badge badge-critical">CRITICAL</span></td></tr>
        {% endif %}
        {% if stats.auth_counts.get('WEP', 0) > 0 %}
        <tr><td><strong>WEP</strong></td><td>{{ stats.auth_counts.WEP }}</td><td><span class="badge badge-critical">CRITICAL</span></td></tr>
        {% endif %}
        {% if stats.auth_counts.get('WPA', 0) > 0 %}
        <tr><td><strong>WPA</strong></td><td>{{ stats.auth_counts.WPA }}</td><td><span class="badge badge-high">HIGH</span></td></tr>
        {% endif %}
        {% if stats.auth_counts.get('WPA2', 0) > 0 %}
        <tr><td><strong>WPA2</strong></td><td>{{ stats.auth_counts.WPA2 }}</td><td><span class="badge badge-medium">MEDIUM</span></td></tr>
        {% endif %}
        {% if stats.auth_counts.get('WPA3', 0) > 0 %}
        <tr><td><strong>WPA3</strong></td><td>{{ stats.auth_counts.WPA3 }}</td><td><span class="badge badge-low">LOW</span></td></tr>
        {% endif %}
    </table>
</div>

<!-- KEY FINDINGS -->
<h2><span style="color: #27ae60; margin-right: 6px;">3.</span>Key Findings</h2>
<ul class="finding-list">
    {% if stats.risk_counts.critical > 0 %}
    <li class="finding-critical">
        <strong>{{ stats.risk_counts.critical }} network{{ 's' if stats.risk_counts.critical != 1 else '' }}
        operating without encryption or with broken encryption</strong> (OPEN/WEP),
        allowing immediate unauthorized access to network traffic and connected devices.
        {% if stats.auth_counts.get('OPEN', 0) > 0 %}
        {{ stats.auth_counts.OPEN }} network{{ 's' if stats.auth_counts.OPEN != 1 else '' }} have
        no encryption whatsoever.
        {% endif %}
    </li>
    {% endif %}
    {% if stats.auth_counts.get('WEP', 0) > 0 %}
    <li class="finding-critical">
        <strong>{{ stats.auth_counts.WEP }} network{{ 's' if stats.auth_counts.WEP != 1 else '' }}
        use WEP encryption</strong>, which can be broken in under 5 minutes using freely
        available tools. WEP has been deprecated since 2004.
    </li>
    {% endif %}
    {% if stats.risk_counts.high > 0 %}
    <li>
        <strong>{{ stats.risk_counts.high }} network{{ 's' if stats.risk_counts.high != 1 else '' }}
        use outdated or weak security protocols</strong> susceptible to dictionary attacks
        and PMKID-based cracking techniques.
    </li>
    {% endif %}
    {% if stats.risk_counts.medium > 0 %}
    <li class="finding-info">
        <strong>{{ stats.risk_counts.medium }} network{{ 's' if stats.risk_counts.medium != 1 else '' }}
        use WPA2 encryption</strong>. While adequate, these may be vulnerable to offline
        brute-force attacks if weak passwords are used.
    </li>
    {% endif %}
    <li class="finding-info">
        <strong>{{ stats.total_networks }} unique wireless access points</strong> identified
        across {{ stats.unique_channels }} channels. Average signal: {{ "%.0f"|format(stats.avg_rssi) }} dBm.
    </li>
    {% if stats.tagged_counts.primary > 0 %}
    <li>
        <strong>{{ stats.tagged_counts.primary }} network{{ 's' if stats.tagged_counts.primary != 1 else '' }}
        flagged as primary targets</strong> based on vulnerability severity and business impact.
    </li>
    {% endif %}
</ul>

<!-- ATTACK PRIORITY MATRIX (summary + full) -->
{% if report_type != 'executive' %}
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">4.</span>Attack Priority Matrix</h1>
<p class="text-muted mb-10">Top targets ranked by exploitability, signal strength, and potential impact.</p>

<div style="background: #f5f7fa; border-radius: 6px; padding: 12px 16px; margin-bottom: 16px; font-size: 11pt; line-height: 1.7;">
    <strong style="font-size: 11pt;">Signal Strength Guide:</strong>
    <span style="color: #27ae60; margin-left: 12px;">&#9632; Excellent (-30 to -50 dBm)</span> Attacker could be inside your building &nbsp;
    <span style="color: #3498db;">&#9632; Good (-50 to -65 dBm)</span> Attacker in the parking lot &nbsp;
    <span style="color: #e67e22;">&#9632; Fair (-65 to -75 dBm)</span> Attacker across the street &nbsp;
    <span style="color: #e74c3c;">&#9632; Weak (-75 to -90 dBm)</span> Specialized equipment needed
</div>

{% if priority_targets %}
<table>
    <thead><tr>
        <th style="width: 5%;">#</th>
        <th style="width: 25%;">Network (SSID)</th>
        <th style="width: 18%;">Security</th>
        <th style="width: 14%;">Signal</th>
        <th style="width: 14%;">Exploit Score</th>
        <th style="width: 12%;">Attack Time</th>
        <th style="width: 12%;">Complexity</th>
    </tr></thead>
    {% for target in priority_targets[:10] %}
    <tr>
        <td><strong>{{ loop.index }}</strong></td>
        <td>
            <strong>{{ target.ssid or '[Hidden Network]' }}</strong><br>
            <span class="text-muted text-small">{{ target.mac }}</span>
        </td>
        <td>
            <span class="badge badge-{{ target.risk_level }}">{{ target.auth_mode }}</span>
        </td>
        <td>
            {{ target.rssi }} dBm
            <div class="signal-bar">
                {% if target.rssi and target.rssi > -50 %}
                <div class="signal-fill signal-excellent"></div>
                {% elif target.rssi and target.rssi > -65 %}
                <div class="signal-fill signal-good"></div>
                {% elif target.rssi and target.rssi > -75 %}
                <div class="signal-fill signal-fair"></div>
                {% else %}
                <div class="signal-fill signal-weak"></div>
                {% endif %}
            </div>
        </td>
        <td><strong>{{ target.exploitability.score }}/100</strong></td>
        <td>{{ target.exploitability.attack_time }}</td>
        <td>{{ target.exploitability.complexity }}</td>
    </tr>
    {% endfor %}
</table>
{% endif %}
{% endif %}

<!-- VULNERABILITY ANALYSIS (summary + full) -->
{% if report_type != 'executive' %}
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">5.</span>Vulnerability Analysis</h1>
<p class="text-muted mb-10">Detailed breakdown of vulnerability classes and remediation actions.</p>

{% for vuln in vulnerability_analysis %}
{% if vuln.count > 0 %}
<div class="vuln-card vuln-card-{{ vuln.severity|lower }}">
    <div class="vuln-header">
        <span class="vuln-title">{{ vuln.name }}</span>
        <span class="badge-severity" style="background: {{ vuln.severity_color }};">{{ vuln.severity }}</span>
        <span class="vuln-count">&mdash; {{ vuln.count }} network{{ 's' if vuln.count != 1 else '' }} affected</span>
    </div>
    <p class="vuln-description">{{ vuln.description }}</p>
    {% if vuln.plain_description %}
    <div style="background: #fff8e1; border-left: 4px solid #e67e22; padding: 10px 14px; margin: 8px 0 12px 0; border-radius: 0 4px 4px 0; font-size: 11pt; color: #555; line-height: 1.6;">
        <strong style="color: #e67e22; font-size: 11pt; text-transform: uppercase; letter-spacing: 0.5px;">What This Means For Your Business:</strong><br>
        {{ vuln.plain_description }}
    </div>
    {% endif %}
    <div class="vuln-info-grid">
        <div class="vuln-info-row"><div class="vuln-info-label">Attack Method</div><div class="vuln-info-value">{{ vuln.attack_method }}</div></div>
        <div class="vuln-info-row"><div class="vuln-info-label">Estimated Time</div><div class="vuln-info-value">{{ vuln.attack_time }}</div></div>
        <div class="vuln-info-row"><div class="vuln-info-label">Tools Required</div><div class="vuln-info-value">{{ vuln.tools }}</div></div>
        <div class="vuln-info-row"><div class="vuln-info-label">Skill Level</div><div class="vuln-info-value">{{ vuln.skill_level }}</div></div>
    </div>
    <div class="remediation-box">
        <h4>Remediation</h4>
        <p><strong>Action:</strong> {{ vuln.remediation }}</p>
        <p class="remediation-meta">Cost: {{ vuln.remediation_cost }} &nbsp;|&nbsp; Time: {{ vuln.remediation_time }}</p>
    </div>
    {% if report_type == 'full' and vuln.networks %}
    <div class="affected-networks mt-10">
        <strong class="text-small">Affected Networks:</strong>
        <table class="affected-networks">
            <thead><tr><th>SSID</th><th>MAC Address</th><th>Channel</th><th>Signal</th></tr></thead>
            {% for net in vuln.networks[:20] %}
            <tr><td>{{ net.ssid or '[Hidden]' }}</td><td>{{ net.mac }}</td><td>{{ net.channel }}</td><td>{{ net.rssi }} dBm</td></tr>
            {% endfor %}
            {% if vuln.networks|length > 20 %}
            <tr><td colspan="4" class="text-muted text-small">... and {{ vuln.networks|length - 20 }} more</td></tr>
            {% endif %}
        </table>
    </div>
    {% endif %}
</div>
{% endif %}
{% endfor %}
{% endif %}

<!-- REMEDIATION ROADMAP (summary + full) -->
{% if report_type != 'executive' %}
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">6.</span>Remediation Roadmap</h1>
<p class="text-muted mb-10">Prioritized action plan ordered by risk reduction impact.</p>

{% for item in remediation_roadmap %}
<div class="roadmap-item no-break">
    <span class="roadmap-priority">{{ item.priority }}</span>
    <span class="roadmap-action">{{ item.action }}</span>
    <p class="roadmap-description">{{ item.description }}</p>
    <div class="roadmap-meta">
        <div class="roadmap-meta-item"><strong>Risk Reduction:</strong> {{ item.risk_reduction }}</div>
        <div class="roadmap-meta-item"><strong>Est. Cost:</strong> {{ item.cost }}</div>
        <div class="roadmap-meta-item"><strong>Est. Time:</strong> {{ item.time }}</div>
        <div class="roadmap-meta-item"><strong>Networks:</strong> {{ item.affected_count }}</div>
    </div>
    {% if item.compliance %}
    <div class="compliance-ref">Compliance: {{ item.compliance }}</div>
    {% endif %}
</div>
{% endfor %}
<p style="font-size: 11pt; color: #666; margin-top: 16px; line-height: 1.7; font-style: italic;"><strong>Note:</strong> Time estimates reflect configuration changes per access point only. Additional time is required to reconnect client devices (phones, POS systems, printers, cameras). For a typical small business with 2&ndash;3 access points and 15&ndash;25 connected devices, total remediation time is approximately 3&ndash;6 hours on-site.</p>
{% endif %}

<!-- TAGGED TARGETS (full only) -->
{% if report_type == 'full' and tagged_primary %}
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">7.</span>Tagged Targets &mdash; Primary</h1>
<p class="text-muted mb-10">Networks flagged as primary targets during assessment.</p>
<table>
    <thead><tr><th style="width: 22%;">SSID</th><th style="width: 16%;">MAC Address</th><th style="width: 18%;">Security</th><th style="width: 8%;">Ch.</th><th style="width: 10%;">Signal</th><th style="width: 14%;">Risk</th><th style="width: 12%;">Obs.</th></tr></thead>
    {% for net in tagged_primary %}
    <tr>
        <td><strong>{{ net.ssid or '[Hidden]' }}</strong></td>
        <td class="text-small">{{ net.mac }}</td>
        <td><span class="badge badge-{{ net.risk_level }}">{{ net.auth_mode }}</span></td>
        <td>{{ net.channel }}</td>
        <td>{{ net.rssi }} dBm</td>
        <td><span class="badge badge-{{ net.risk_level }}">{{ net.risk_level|upper }}</span></td>
        <td>{{ net.observation_count }}</td>
    </tr>
    {% endfor %}
</table>
{% endif %}

{% if report_type == 'full' and tagged_secondary %}
<h2>Tagged Targets &mdash; Secondary</h2>
<table>
    <thead><tr><th>SSID</th><th>MAC Address</th><th>Security</th><th>Channel</th><th>Signal</th><th>Risk</th></tr></thead>
    {% for net in tagged_secondary %}
    <tr>
        <td>{{ net.ssid or '[Hidden]' }}</td>
        <td class="text-small">{{ net.mac }}</td>
        <td>{{ net.auth_mode }}</td>
        <td>{{ net.channel }}</td>
        <td>{{ net.rssi }} dBm</td>
        <td><span class="badge badge-{{ net.risk_level }}">{{ net.risk_level|upper }}</span></td>
    </tr>
    {% endfor %}
</table>
{% endif %}

<!-- NETWORK INVENTORY (full only) -->
{% if report_type == 'full' %}
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">8.</span>Complete Network Inventory</h1>
<p class="text-muted mb-10">
    {% if networks|length > 100 %}Showing the first 100 of {{ stats.total_networks }} networks.{% endif %}
</p>
<table>
    <thead><tr>
        <th style="width: 22%;">SSID</th><th style="width: 16%;">MAC Address</th>
        <th style="width: 12%;">Security</th><th style="width: 8%;">Ch.</th>
        <th style="width: 10%;">Signal</th><th style="width: 10%;">Risk</th>
        <th style="width: 8%;">Obs.</th><th style="width: 14%;">First Seen</th>
    </tr></thead>
    {% for net in networks[:100] %}
    <tr>
        <td>{{ net.ssid or '[Hidden Network]' }}</td>
        <td class="text-small">{{ net.mac }}</td>
        <td><span class="badge badge-{{ net.risk_level }}">{{ net.auth_mode }}</span></td>
        <td>{{ net.channel }}</td>
        <td>{{ net.rssi }} dBm</td>
        <td><span class="badge badge-{{ net.risk_level }}">{{ net.risk_level|upper }}</span></td>
        <td>{{ net.observation_count }}</td>
        <td class="text-small">{{ net.first_seen or 'N/A' }}</td>
    </tr>
    {% endfor %}
</table>
{% if networks|length > 100 %}
<p class="text-muted text-small text-center mt-10">Showing 100 of {{ stats.total_networks }} networks. Complete data available upon request.</p>
{% endif %}
{% endif %}

<!-- RISK OF INACTION -->
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">{{ '4' if report_type == 'executive' else '9' if report_type == 'full' else '7' }}.</span>Risk of Inaction</h1>
<p style="margin-bottom: 16px;">Wireless vulnerabilities do not resolve themselves. If the findings in this report are not addressed, your business faces the following risks:</p>

<div class="vuln-card vuln-card-critical" style="margin-bottom: 14px;">
    <div class="vuln-header"><span class="vuln-title">Data Breach Liability</span></div>
    <p class="vuln-description">Texas Business &amp; Commerce Code Chapter 521 requires businesses to implement reasonable security measures to protect sensitive data. Failure to do so after being notified of vulnerabilities may constitute negligence. The average cost of a data breach for small businesses is <strong>$120,000</strong> in direct costs and lost customers.</p>
</div>

{% if stats.auth_counts.get('OPEN', 0) > 0 or stats.auth_counts.get('WEP', 0) > 0 %}
<div class="vuln-card vuln-card-critical" style="margin-bottom: 14px;">
    <div class="vuln-header"><span class="vuln-title">PCI-DSS Non-Compliance</span></div>
    <p class="vuln-description">If your business accepts credit cards over an unencrypted or weakly encrypted wireless network, you may be in violation of Payment Card Industry Data Security Standards. <strong>Fines range from $5,000 to $100,000 per month</strong> until compliance is achieved, and your merchant account may be suspended.</p>
</div>
{% endif %}

<div class="vuln-card vuln-card-high" style="margin-bottom: 14px;">
    <div class="vuln-header"><span class="vuln-title">Regulatory Exposure</span></div>
    <p class="vuln-description">Healthcare providers transmitting patient data over insecure WiFi face HIPAA fines of <strong>$100 to $50,000 per violation</strong>, with annual maximums of $1.5 million per category. Financial services firms face similar exposure under GLBA and state regulations.</p>
</div>

<div class="vuln-card vuln-card-medium" style="margin-bottom: 14px;">
    <div class="vuln-header"><span class="vuln-title">Reputational Damage</span></div>
    <p class="vuln-description">A publicly reported data breach permanently damages customer trust. 60% of small businesses that suffer a significant data breach close within 6 months. Even businesses that survive face years of rebuilding customer confidence.</p>
</div>

<div class="vuln-card vuln-card-medium">
    <div class="vuln-header"><span class="vuln-title">Competitive Disadvantage</span></div>
    <p class="vuln-description">Increasingly, business partners, vendors, and insurance providers require proof of cybersecurity due diligence before entering contracts or providing coverage. Documented wireless vulnerabilities can disqualify your business from opportunities.</p>
</div>

<!-- NEXT STEPS -->
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">{{ '5' if report_type == 'executive' else '10' if report_type == 'full' else '8' }}.</span>What Should You Do Now?</h1>
<p style="margin-bottom: 16px; font-size: 12pt;">The vulnerabilities documented in this report are real, and they are visible to anyone with a laptop and basic WiFi tools. Here is what we recommend:</p>

<div class="cta-section">
    <ol class="cta-steps">
        <li>
            <span class="cta-step-num">1</span>
            <strong>Call Us for a Free 15-Minute Consultation</strong><br>
            We will walk you through the findings in this report, answer any questions,
            and help you understand exactly what needs to be fixed. No obligation, no pressure.
        </li>
        <li>
            <span class="cta-step-num">2</span>
            <strong>Schedule Your On-Site Security Audit</strong><br>
            We come to your location, verify the findings, test your network passwords,
            and either provide a detailed fix-it plan or fix everything on the spot.
        </li>
        <li>
            <span class="cta-step-num">3</span>
            <strong>Sleep Better</strong><br>
            Once remediation is complete, we provide a follow-up scan to confirm
            your networks are secured. You get documentation proving due diligence.
        </li>
    </ol>
</div>

<div class="contact-block">
    <div class="contact-brand">S.P.A.R.K. Initiative Labs</div>
    <div class="contact-tagline">Professional WiFi Security Auditing</div>
    <div style="margin: 12px 0;">
        <div style="font-size: 13pt; font-weight: 700; color: #293241; margin-bottom: 4px;">Call or Text: (979) 966-3499</div>
        <div style="font-size: 12pt; color: #555;">Email: security@sparkinitiative.io</div>
    </div>
    <div class="contact-url">sparkinitiative.io</div>
    <div style="font-size: 11pt; color: #888; margin-top: 8px; font-style: italic;">Serving the Highway 71 corridor &mdash; Columbus, La Grange, Bastrop, and surrounding areas</div>
</div>

<h2>Service Tiers</h2>
<div class="tiers-container clearfix">
    <div class="tier-card">
        <div class="tier-name">Basic Audit</div>
        <div class="tier-price">$299</div>
        <div class="tier-desc">
            <div style="text-align: left; line-height: 1.7;">
            &#10003; External wireless reconnaissance<br>
            &#10003; All networks identified &amp; classified<br>
            &#10003; Risk scoring per network<br>
            &#10003; Executive summary PDF report<br>
            &#10003; Delivered within 48 hours
            </div>
            <div style="margin-top: 8px; font-size: 11pt; color: #888; font-style: italic;">Best for: Understanding your wireless exposure</div>
        </div>
    </div>
    <div class="tier-card tier-card-featured">
        <div class="tier-featured-label">Most Popular</div>
        <div class="tier-name">Standard Audit</div>
        <div class="tier-price">$499</div>
        <div class="tier-desc">
            <div style="text-align: left; line-height: 1.7;">
            &#10003; Everything in Basic, plus:<br>
            &#10003; On-site assessment (2&ndash;3 hours)<br>
            &#10003; Password strength testing<br>
            &#10003; Detailed vulnerability analysis<br>
            &#10003; Prioritized remediation roadmap<br>
            &#10003; Full technical report<br>
            &#10003; 30-min phone consultation
            </div>
            <div style="margin-top: 8px; font-size: 11pt; color: #888; font-style: italic;">Best for: Businesses handling customer data or payments</div>
        </div>
    </div>
    <div class="tier-card">
        <div class="tier-name">Premium Audit</div>
        <div class="tier-price">$699</div>
        <div class="tier-desc">
            <div style="text-align: left; line-height: 1.7;">
            &#10003; Everything in Standard, plus:<br>
            &#10003; Hands-on remediation (up to 4 hrs)<br>
            &#10003; Staff security awareness briefing<br>
            &#10003; Secure WiFi configuration docs<br>
            &#10003; 30-day follow-up verification scan<br>
            &#10003; 90-day priority support
            </div>
            <div style="margin-top: 8px; font-size: 11pt; color: #888; font-style: italic;">Best for: Businesses that want problems found AND fixed</div>
        </div>
    </div>
</div>

<p style="text-align: center; font-size: 12pt; font-weight: 700; color: #293241; margin-top: 20px;">
    Schedule your free consultation today. The vulnerabilities in this report are not going away on their own.
</p>

<h2>About S.P.A.R.K. Initiative Labs</h2>
<div class="summary-box">
    <p>S.P.A.R.K. Initiative Labs is a Central Texas cybersecurity firm specializing in wireless network security assessments for small and medium businesses. We help business owners understand their wireless attack surface and implement practical, cost-effective defenses against unauthorized access.</p>
    <p>Our assessments use the same tools and techniques employed by real-world attackers, giving you an honest picture of your security posture &mdash; before someone with malicious intent finds the same vulnerabilities.</p>
    <p style="margin-bottom: 0;"><strong>Frameworks &amp; Standards:</strong> NIST SP 800-153, CIS Controls v8, PCI-DSS, OWASP Wireless Testing Guide</p>
</div>

<div style="margin-top: 30px; padding-top: 16px; border-top: 1px solid #e8e8e8; font-size: 11pt; color: #999; line-height: 1.8;">
    <strong style="color: #777;">Disclaimer and Limitation of Liability</strong><br>
    This report is provided for informational purposes only and represents the wireless security posture observed at the time of assessment. S.P.A.R.K. Initiative Labs makes no warranties, express or implied, regarding the completeness or accuracy of the findings. This assessment was conducted entirely through passive observation of publicly broadcast wireless signals from publicly accessible locations. No unauthorized access to any network, system, or device was performed or attempted. Risk ratings are based on industry-standard frameworks and professional judgment. Actual exploitability may vary depending on factors not observable through passive assessment. S.P.A.R.K. Initiative Labs shall not be held liable for any damages arising from the use or misuse of information contained in this report. This report does not constitute legal, regulatory, or compliance advice.
</div>

<div style="margin-top: 12px; font-size: 11pt; color: #999; font-style: italic;">
    <strong style="color: #777;">Report Validity:</strong> This assessment reflects conditions observed during {{ assessment_period }}. Wireless environments change frequently. Reassessment is recommended every 6&ndash;12 months or after significant changes to network infrastructure.
</div>

{% if report_type != 'executive' %}
<div class="page-break"></div>
<h1><span style="color: #27ae60; margin-right: 8px;">{{ '11' if report_type == 'full' else '9' }}.</span>Glossary of Terms</h1>
<table>
    <thead><tr><th style="width: 25%;">Term</th><th>Definition</th></tr></thead>
    <tr><td><strong>Access Point (AP)</strong></td><td>A wireless router or device that creates a WiFi network</td></tr>
    <tr><td><strong>SSID</strong></td><td>The name of a WiFi network &mdash; what you see when you search for WiFi on your phone</td></tr>
    <tr><td><strong>MAC Address</strong></td><td>A unique hardware identifier for each wireless device, like a serial number</td></tr>
    <tr><td><strong>Encryption</strong></td><td>Scrambling of data so only authorized devices can read it</td></tr>
    <tr><td><strong>WEP</strong></td><td>An obsolete encryption standard from 1999 that can be cracked in minutes</td></tr>
    <tr><td><strong>WPA / WPA2 / WPA3</strong></td><td>Progressively stronger WiFi encryption standards. WPA3 is the current best practice.</td></tr>
    <tr><td><strong>PSK (Pre-Shared Key)</strong></td><td>A WiFi password shared among all users of a network</td></tr>
    <tr><td><strong>Open Network</strong></td><td>A WiFi network with no password &mdash; anyone can connect and see all traffic</td></tr>
    <tr><td><strong>WPS</strong></td><td>WiFi Protected Setup &mdash; a convenience feature with a known flaw that lets attackers bypass your password</td></tr>
    <tr><td><strong>Brute Force Attack</strong></td><td>Trying every possible password combination until the correct one is found</td></tr>
    <tr><td><strong>Signal Strength (dBm)</strong></td><td>A measure of wireless signal power. Higher values (closer to 0) mean the network can be attacked from farther away.</td></tr>
</table>
{% endif %}

<!-- FOOTER -->
<div class="report-footer">
    <p><strong>This report was generated by WiFi Arsenal</strong> &mdash; S.P.A.R.K. Initiative Labs</p>
    <p>Assessment data collected during the period {{ assessment_period }}.</p>
    <p><strong>CONFIDENTIAL</strong> &mdash; Distribution restricted to {{ client_name }} authorized personnel only.</p>
</div>

</body>
</html>'''

    # ------------------------------------------------------------------
    # PDF generation
    # ------------------------------------------------------------------

    def html_to_pdf(self, html_content):
        """Convert HTML string to PDF bytes using WeasyPrint."""
        from weasyprint import HTML
        return HTML(string=html_content).write_pdf()

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_preview(self, report_type='summary', client_name='Security Assessment',
                         geofence_id=None, vuln_threshold='all', include_map=True):
        """Assemble all data and render the Jinja2 template to HTML."""
        networks = self.get_networks_for_report(geofence_id, vuln_threshold)
        stats = self._get_report_statistics(networks)
        overall_risk, overall_risk_level = self._calculate_overall_risk_score(networks)

        # SVG needle position (center 120,120 radius 95)
        angle = math.radians(180 - (overall_risk / 100.0) * 180)
        needle_x = 120 + 95 * math.cos(angle)
        needle_y = 120 - 95 * math.sin(angle)

        tagged_primary = [n for n in networks if n.get('target_tag') == 'primary']
        tagged_secondary = [n for n in networks if n.get('target_tag') == 'secondary']
        tagged_out_of_scope = [n for n in networks if n.get('target_tag') == 'out_of_scope']

        # Load logo as base64
        logo_base64 = ''
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spark-logo.png')
        if os.path.exists(logo_path):
            import base64
            with open(logo_path, 'rb') as f:
                logo_base64 = base64.b64encode(f.read()).decode('ascii')

        context = {
            'title': f'Wireless Security Assessment Report - {client_name}',
            'client_name': client_name,
            'assessment_period': self._get_assessment_period(networks),
            'generated_date': datetime.now().strftime('%m/%d/%Y %H:%M:%S'),
            'report_type': report_type,
            'networks': networks,
            'stats': stats,
            'include_map': include_map,
            'overall_risk': overall_risk,
            'overall_risk_level': overall_risk_level,
            'priority_targets': self._get_priority_targets(networks),
            'vulnerability_analysis': self._get_vulnerability_analysis(networks),
            'remediation_roadmap': self._get_remediation_roadmap(networks),
            'needle_x': round(needle_x, 1),
            'needle_y': round(needle_y, 1),
            'tagged_primary': tagged_primary,
            'tagged_secondary': tagged_secondary,
            'tagged_out_of_scope': tagged_out_of_scope,
            'logo_base64': logo_base64,
            'report_id': datetime.now().strftime('%Y%m%d') + '-001',
        }

        import jinja2
        template_str = self._get_inline_template(report_type)
        template = jinja2.Template(template_str)
        return template.render(**context)

    def generate_report(self, report_type='summary', client_name='Security Assessment',
                        geofence_id=None, vuln_threshold='all', include_map=True):
        """Generate a complete PDF report."""
        html = self.generate_preview(report_type, client_name, geofence_id,
                                     vuln_threshold, include_map)
        return self.html_to_pdf(html)


# ==============================================================================
# Module-level convenience functions (called by server.py)
# ==============================================================================

_instance = None


def _get_instance():
    global _instance
    if _instance is None:
        _instance = ReportGenerator()
    return _instance


def generate_report(report_type='summary', client_name='Security Assessment',
                    geofence_id=None, vuln_threshold='all', include_map=True):
    return _get_instance().generate_report(report_type, client_name, geofence_id,
                                           vuln_threshold, include_map)


def generate_preview(report_type='summary', client_name='Security Assessment',
                     geofence_id=None, vuln_threshold='all', include_map=True):
    return _get_instance().generate_preview(report_type, client_name, geofence_id,
                                            vuln_threshold, include_map)


def get_networks_for_report(geofence_id=None, vuln_threshold='all'):
    return _get_instance().get_networks_for_report(geofence_id, vuln_threshold)


def categorize_risk(network):
    return _get_instance().categorize_risk(network)


def html_to_pdf(html_content):
    return _get_instance().html_to_pdf(html_content)


# ==============================================================================
# Test block
# ==============================================================================

if __name__ == '__main__':
    rg = ReportGenerator()
    networks = rg.get_networks_for_report()
    print(f"Total networks: {len(networks)}")
    stats = rg._get_report_statistics(networks)
    print(f"Risk counts: {stats['risk_counts']}")
    score, level = rg._calculate_overall_risk_score(networks)
    print(f"Overall risk: {score}/100 ({level})")

    html = rg.generate_preview(report_type='summary', client_name='Test Client')
    with open('/tmp/test_report.html', 'w') as f:
        f.write(html)
    print(f"HTML preview: /tmp/test_report.html ({len(html)} bytes)")

    try:
        pdf = rg.generate_report(report_type='summary', client_name='Test Client')
        with open('/tmp/test_report.pdf', 'wb') as f:
            f.write(pdf)
        print(f"PDF report: /tmp/test_report.pdf ({len(pdf)} bytes)")
    except Exception as e:
        print(f"PDF generation failed: {e}")
