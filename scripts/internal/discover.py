#!/usr/bin/env python3
"""
Passive Network Discovery - WiFi Arsenal
Silently monitors network traffic to identify vulnerabilities
"""

import json
import os
import sys
import time
import signal
import threading
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("Error: scapy not installed")
    sys.exit(1)

# Output file
OUTPUT_FILE = "/home/ov3rr1d3/wifi_arsenal/captures/discovery_results.json"
RUNNING_FLAG = "/tmp/discovery_running"

# Track discovered items
discoveries = {
    "hosts": {},           # IP -> {mac, hostname, first_seen, last_seen}
    "llmnr": [],           # LLMNR queries (poisonable)
    "nbns": [],            # NetBIOS queries (poisonable)
    "wpad": [],            # WPAD requests (poisonable)
    "mdns": [],            # mDNS broadcasts
    "ssdp": [],            # UPnP devices
    "smb": {},             # SMB hosts with version info
    "cleartext": [],       # Cleartext credentials found
    "http_hosts": [],      # HTTP (non-HTTPS) servers
    "vulnerabilities": []  # Actionable findings
}

seen_queries = set()  # Dedupe
lock = threading.Lock()

def save_results():
    """Save discoveries to JSON file"""
    with lock:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(discoveries, f, indent=2, default=str)

def add_host(ip, mac=None, hostname=None):
    """Track discovered hosts"""
    with lock:
        now = datetime.now().isoformat()
        if ip not in discoveries["hosts"]:
            discoveries["hosts"][ip] = {
                "mac": mac,
                "hostname": hostname,
                "first_seen": now,
                "last_seen": now
            }
        else:
            discoveries["hosts"][ip]["last_seen"] = now
            if mac:
                discoveries["hosts"][ip]["mac"] = mac
            if hostname:
                discoveries["hosts"][ip]["hostname"] = hostname

def add_vulnerability(vuln_type, target, details, severity="medium", attack=None):
    """Add actionable vulnerability"""
    with lock:
        vuln = {
            "type": vuln_type,
            "target": target,
            "details": details,
            "severity": severity,
            "attack": attack,
            "timestamp": datetime.now().isoformat()
        }
        # Dedupe
        for v in discoveries["vulnerabilities"]:
            if v["type"] == vuln_type and v["target"] == target:
                return
        discoveries["vulnerabilities"].append(vuln)
        print(f"[!] VULN: {vuln_type} - {target} - {details}")

def process_packet(pkt):
    """Analyze each packet for interesting data"""
    
    # ARP - host discovery
    if ARP in pkt:
        if pkt[ARP].op == 2:  # ARP reply
            add_host(pkt[ARP].psrc, pkt[ARP].hwsrc)
        elif pkt[ARP].op == 1:  # ARP request
            add_host(pkt[ARP].psrc, pkt[ARP].hwsrc)
    
    # Skip if no IP layer
    if IP not in pkt:
        return
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    # LLMNR (UDP 5355) - Poisonable
    if UDP in pkt and pkt[UDP].dport == 5355:
        if Raw in pkt:
            try:
                raw = pkt[Raw].load
                # Extract query name (simplified parsing)
                if len(raw) > 13:
                    name_len = raw[12]
                    if name_len > 0 and name_len < 64:
                        name = raw[13:13+name_len].decode('utf-8', errors='ignore')
                        query_key = f"llmnr:{src_ip}:{name}"
                        if query_key not in seen_queries:
                            seen_queries.add(query_key)
                            with lock:
                                discoveries["llmnr"].append({
                                    "source": src_ip,
                                    "query": name,
                                    "timestamp": datetime.now().isoformat()
                                })
                            add_vulnerability(
                                "LLMNR", 
                                src_ip, 
                                f"Host querying for '{name}'",
                                "high",
                                "responder"
                            )
            except:
                pass
    
    # NetBIOS Name Service (UDP 137) - Poisonable
    if UDP in pkt and pkt[UDP].dport == 137:
        query_key = f"nbns:{src_ip}"
        if query_key not in seen_queries:
            seen_queries.add(query_key)
            with lock:
                discoveries["nbns"].append({
                    "source": src_ip,
                    "timestamp": datetime.now().isoformat()
                })
            add_vulnerability(
                "NBT-NS",
                src_ip,
                "NetBIOS name query detected",
                "high",
                "responder"
            )
    
    # mDNS (UDP 5353)
    if UDP in pkt and pkt[UDP].dport == 5353:
        if DNS in pkt and pkt[DNS].qr == 0:  # Query
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode() if pkt[DNSQR].qname else ""
                query_key = f"mdns:{src_ip}:{qname}"
                if query_key not in seen_queries:
                    seen_queries.add(query_key)
                    with lock:
                        discoveries["mdns"].append({
                            "source": src_ip,
                            "query": qname,
                            "timestamp": datetime.now().isoformat()
                        })
    
    # SSDP/UPnP (UDP 1900)
    if UDP in pkt and (pkt[UDP].dport == 1900 or pkt[UDP].sport == 1900):
        if Raw in pkt:
            try:
                data = pkt[Raw].load.decode('utf-8', errors='ignore')
                if "SERVER:" in data.upper() or "USN:" in data.upper():
                    query_key = f"ssdp:{src_ip}"
                    if query_key not in seen_queries:
                        seen_queries.add(query_key)
                        # Extract device info
                        server = ""
                        for line in data.split('\r\n'):
                            if line.upper().startswith("SERVER:"):
                                server = line.split(":", 1)[1].strip()
                        with lock:
                            discoveries["ssdp"].append({
                                "source": src_ip,
                                "server": server,
                                "timestamp": datetime.now().isoformat()
                            })
                        if server:
                            add_vulnerability(
                                "UPnP",
                                src_ip,
                                f"UPnP device: {server}",
                                "low",
                                "info"
                            )
            except:
                pass
    
    # SMB (TCP 445) - Check for SMBv1 / signing
    if TCP in pkt and (pkt[TCP].dport == 445 or pkt[TCP].sport == 445):
        if Raw in pkt:
            raw = bytes(pkt[Raw].load)
            # SMB1 signature: \xffSMB
            if b'\xffSMB' in raw:
                query_key = f"smbv1:{src_ip if pkt[TCP].sport == 445 else dst_ip}"
                if query_key not in seen_queries:
                    seen_queries.add(query_key)
                    target = src_ip if pkt[TCP].sport == 445 else dst_ip
                    with lock:
                        discoveries["smb"][target] = {
                            "version": "SMBv1",
                            "signing": "unknown",
                            "timestamp": datetime.now().isoformat()
                        }
                    add_vulnerability(
                        "SMBv1",
                        target,
                        "SMBv1 protocol detected - EternalBlue potential",
                        "critical",
                        "eternalblue"
                    )
            # SMB2/3 signature: \xfeSMB
            elif b'\xfeSMB' in raw:
                target = src_ip if pkt[TCP].sport == 445 else dst_ip
                query_key = f"smb2:{target}"
                if query_key not in seen_queries:
                    seen_queries.add(query_key)
                    # Check for signing (simplified - byte 70 in header)
                    # This is rough - would need proper parsing for accuracy
                    with lock:
                        if target not in discoveries["smb"]:
                            discoveries["smb"][target] = {
                                "version": "SMBv2/3",
                                "signing": "unknown",
                                "timestamp": datetime.now().isoformat()
                            }
    
    # HTTP Basic Auth (cleartext)
    if TCP in pkt and pkt[TCP].dport == 80:
        if Raw in pkt:
            try:
                data = pkt[Raw].load.decode('utf-8', errors='ignore')
                if "Authorization: Basic" in data:
                    import base64
                    for line in data.split('\r\n'):
                        if line.startswith("Authorization: Basic"):
                            b64 = line.split(" ")[2]
                            try:
                                creds = base64.b64decode(b64).decode()
                                query_key = f"httpauth:{src_ip}:{creds}"
                                if query_key not in seen_queries:
                                    seen_queries.add(query_key)
                                    with lock:
                                        discoveries["cleartext"].append({
                                            "type": "HTTP Basic Auth",
                                            "source": src_ip,
                                            "destination": dst_ip,
                                            "credentials": creds,
                                            "timestamp": datetime.now().isoformat()
                                        })
                                    add_vulnerability(
                                        "Cleartext Creds",
                                        src_ip,
                                        f"HTTP Basic Auth: {creds}",
                                        "critical",
                                        "captured"
                                    )
                            except:
                                pass
            except:
                pass
    
    # FTP credentials (port 21)
    if TCP in pkt and pkt[TCP].dport == 21:
        if Raw in pkt:
            try:
                data = pkt[Raw].load.decode('utf-8', errors='ignore')
                if data.startswith("USER ") or data.startswith("PASS "):
                    query_key = f"ftp:{src_ip}:{data[:20]}"
                    if query_key not in seen_queries:
                        seen_queries.add(query_key)
                        with lock:
                            discoveries["cleartext"].append({
                                "type": "FTP",
                                "source": src_ip,
                                "destination": dst_ip,
                                "data": data.strip(),
                                "timestamp": datetime.now().isoformat()
                            })
                        add_vulnerability(
                            "Cleartext Creds",
                            src_ip,
                            f"FTP: {data.strip()[:50]}",
                            "critical",
                            "captured"
                        )
            except:
                pass
    
    # Telnet (port 23)
    if TCP in pkt and (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
        query_key = f"telnet:{src_ip}:{dst_ip}"
        if query_key not in seen_queries:
            seen_queries.add(query_key)
            target = dst_ip if pkt[TCP].dport == 23 else src_ip
            add_vulnerability(
                "Telnet",
                target,
                "Telnet service in use - cleartext protocol",
                "high",
                "sniff"
            )
    
    # WPAD (looking for wpad in HTTP or DNS)
    if DNS in pkt and DNSQR in pkt:
        qname = pkt[DNSQR].qname.decode() if pkt[DNSQR].qname else ""
        if "wpad" in qname.lower():
            query_key = f"wpad:{src_ip}"
            if query_key not in seen_queries:
                seen_queries.add(query_key)
                with lock:
                    discoveries["wpad"].append({
                        "source": src_ip,
                        "query": qname,
                        "timestamp": datetime.now().isoformat()
                    })
                add_vulnerability(
                    "WPAD",
                    src_ip,
                    f"WPAD proxy request: {qname}",
                    "high",
                    "responder"
                )

def save_periodically():
    """Save results every 5 seconds"""
    while os.path.exists(RUNNING_FLAG):
        save_results()
        time.sleep(5)

def signal_handler(sig, frame):
    """Handle shutdown"""
    print("\n[*] Stopping discovery...")
    if os.path.exists(RUNNING_FLAG):
        os.remove(RUNNING_FLAG)
    save_results()
    sys.exit(0)

def main():
    if len(sys.argv) < 2:
        print("Usage: discover.py <interface>")
        sys.exit(1)
    
    interface = sys.argv[1]
    
    print(f"[*] Starting passive discovery on {interface}")
    print(f"[*] Results: {OUTPUT_FILE}")
    print("[*] Press Ctrl+C to stop\n")
    
    # Create running flag
    with open(RUNNING_FLAG, 'w') as f:
        f.write(str(os.getpid()))
    
    # Signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start save thread
    save_thread = threading.Thread(target=save_periodically, daemon=True)
    save_thread.start()
    
    # Sniff filter - common interesting traffic
    bpf_filter = "arp or udp port 5355 or udp port 137 or udp port 5353 or udp port 1900 or tcp port 445 or tcp port 80 or tcp port 21 or tcp port 23 or udp port 53"
    
    try:
        sniff(iface=interface, filter=bpf_filter, prn=process_packet, store=0)
    except PermissionError:
        print("Error: Need root privileges")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
