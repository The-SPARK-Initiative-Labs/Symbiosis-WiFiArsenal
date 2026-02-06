#!/usr/bin/env python3
"""
WiFi Arsenal MCP Server
Specialized MCP server for WiFi Arsenal penetration testing project.
Provides controlled access to project files and operations.
Multi-system aware: Works on both Sh4d0wFr4m3 and Glass.
"""

import asyncio
import json
import sys
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

ARSENAL_API_BASE = "http://localhost:5000"

# Constants
SHADOWFRAME_BASE = Path("/home/ov3rr1d3/wifi_arsenal")
GLASS_BASE = Path("/opt/cracking")


class WiFiArsenalMCPServer:
    async def handle_message(self, message):
        method = message.get("method")
        
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "wifi-arsenal", "version": "1.0.0"}
                }
            }
        
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"tools": self.get_tools()}
            }
        
        elif method == "tools/call":
            return await self.call_tool(message)
        
        elif method == "notifications/initialized":
            return None
        
        else:
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32601, "message": "Method not found"}
            }

    def get_tools(self):
        return [
            {
                "name": "wifi_arsenal_init",
                "description": "Initialize session by loading core project files (server.py, index.html, SESSION_HANDOFF.md). Call ONCE at session start.",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "read_project_code",
                "description": "Read server.py or index.html with optional line ranges",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "enum": ["server.py", "index.html"]},
                        "start_line": {"type": "number"},
                        "end_line": {"type": "number"}
                    },
                    "required": ["file"]
                }
            },
            {
                "name": "read_bash_script",
                "description": "Read a specific bash script from /scripts/ directory",
                "inputSchema": {
                    "type": "object",
                    "properties": {"script_name": {"type": "string"}},
                    "required": ["script_name"]
                }
            },
            {
                "name": "read_handoff_state",
                "description": "Read current SESSION_HANDOFF.md to understand project state",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "update_handoff_state",
                "description": "Update SESSION_HANDOFF.md with current project state. CRITICAL: Call after EVERY file change.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"content": {"type": "string"}},
                    "required": ["content"]
                }
            },
            {
                "name": "list_capture_files",
                "description": "List all capture files (.cap, .hc22000, .log) with sizes",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "execute_safe_command",
                "description": "Execute whitelisted safe commands. Blocks dangerous operations. AVOID using this - prefer Arsenal API tools instead.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"]
                }
            },
            {
                "name": "check_system_status",
                "description": "Get system status: hostname, interface states, running processes",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "arsenal_scan",
                "description": "Scan for WiFi networks using Arsenal's API. Returns list of networks with SSID, BSSID, channel, signal, encryption.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "interface": {"type": "string", "description": "Interface to scan with (alfa0 or alfa1)", "default": "alfa0"},
                        "band": {"type": "string", "description": "Band to scan: 2.4, 5, or all", "default": "all"}
                    },
                    "required": []
                }
            },
            {
                "name": "arsenal_glass_status",
                "description": "Get Glass cracker status - current file, progress, speed, ETA, queue.",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "arsenal_context",
                "description": "Get full Arsenal context - interface states, Glass status, selected target, recent captures.",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "arsenal_interface_mode",
                "description": "Set interface mode (monitor or managed)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "interface": {"type": "string", "description": "Interface name (alfa0 or alfa1)"},
                        "mode": {"type": "string", "description": "Mode: monitor or managed"}
                    },
                    "required": ["interface", "mode"]
                }
            },
            {
                "name": "arsenal_attack",
                "description": "Launch an attack on a target network",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "attack_type": {"type": "string", "description": "Attack type: pmkid, handshake, deauth, deauth_client, pmkid_active, wps, deauth_flood, extended, auto_capture, reveal_hidden, kill_all, stop"},
                        "bssid": {"type": "string", "description": "Target BSSID (MAC address)"},
                        "channel": {"type": "number", "description": "Target channel"},
                        "ssid": {"type": "string", "description": "Target SSID (optional)"},
                        "client_mac": {"type": "string", "description": "Client MAC for targeted deauth (optional)"},
                        "duration": {"type": "number", "description": "Duration in seconds (optional)"}
                    },
                    "required": ["attack_type"]
                }
            },
            {
                "name": "arsenal_send_to_glass",
                "description": "Send a capture file to Glass for cracking",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string", "description": "Capture filename to send"}
                    },
                    "required": ["filename"]
                }
            },
            {
                "name": "arsenal_list_captures",
                "description": "List all capture files with details",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "arsenal_glass",
                "description": "Control Glass cracker - status, start/stop, stages, queue management",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "description": "Action: status, start, stop, pause, resume, run_stage, upload, queue, inbox, result, gpu_stats"},
                        "filename": {"type": "string", "description": "Filename for upload (optional)"},
                        "stage": {"type": "string", "description": "Stage to run: 1, 2, 3a, 3b, 4a, 4b, 5 (optional)"}
                    },
                    "required": ["action"]
                }
            },
            {
                "name": "arsenal_portal",
                "description": "Control Evil Portal - start/stop fake APs, capture credentials",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "description": "Action: status, start, stop, templates, log, clear"},
                        "template": {"type": "string", "description": "Template name for start (optional)"},
                        "ssid": {"type": "string", "description": "SSID to broadcast (optional)"},
                        "interface": {"type": "string", "description": "Interface to use (optional)"}
                    },
                    "required": ["action"]
                }
            },
            {
                "name": "arsenal_wardrive",
                "description": "Wardrive and Flipper operations - stats, sessions, sync",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "description": "Action: stats, sessions, filter, flipper_status, flipper_sync"},
                        "session_id": {"type": "string", "description": "Session ID for filtering (optional)"}
                    },
                    "required": ["action"]
                }
            },
            {
                "name": "arsenal_target",
                "description": "Target selection and intelligence - select targets, get intel briefs, monitor clients",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "description": "Action: select, intel, monitor, mode_status, mode_set"},
                        "bssid": {"type": "string", "description": "Target BSSID (optional)"},
                        "channel": {"type": "number", "description": "Target channel (optional)"},
                        "ssid": {"type": "string", "description": "Target SSID (optional)"},
                        "interface": {"type": "string", "description": "Interface for mode_set (optional)"},
                        "mode": {"type": "string", "description": "Mode: monitor or managed (optional)"}
                    },
                    "required": ["action"]
                }
            },
            {
                "name": "arsenal_captures",
                "description": "Manage capture files - list, delete, convert, browse",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "description": "Action: list, delete, convert, browse"},
                        "filename": {"type": "string", "description": "Filename for delete/convert (optional)"}
                    },
                    "required": ["action"]
                }
            },
            {
                "name": "arsenal_execute",
                "description": "Run shell commands on Sh4d0wFr4m3. USE SPARINGLY - prefer arsenal_* tools for standard operations. This is for edge cases, debugging, viewing/editing code, or when nothing else works.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Shell command to execute"},
                        "cwd": {"type": "string", "description": "Working directory (default: /home/ov3rr1d3/wifi_arsenal)"}
                    },
                    "required": ["command"]
                }
            }
        ]

    async def call_tool(self, message):
        tool_name = message["params"]["name"]
        args = message["params"].get("arguments", {})
        
        try:
            result = await self.execute_tool(tool_name, args)
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"content": [{"type": "text", "text": str(result)}]}
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"content": [{"type": "text", "text": f"Error: {str(e)}"}], "isError": True}
            }

    async def execute_tool(self, tool_name, args):
        if tool_name == "wifi_arsenal_init":
            result = {"system": None, "files": {}}
            
            # Detect which system we're on
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            result["system"] = hostname
            
            # Load files based on which system
            if hostname == "Sh4d0w-Fr4m3":
                # Shadowframe: WiFi Arsenal attack platform
                core_files = [
                    ("server.py", SHADOWFRAME_BASE / "server.py"),
                    ("index.html", SHADOWFRAME_BASE / "web" / "index.html"),
                    ("SESSION_HANDOFF.md", SHADOWFRAME_BASE / "readme first" / "SESSION_HANDOFF.md"),
                ]
                
                for name, path in core_files:
                    if path.exists():
                        result["files"][name] = path.read_text()
                    else:
                        result["files"][name] = f"ERROR: File not found at {path}"
            
            elif hostname == "glass":
                # Glass: GPU cracking server
                core_files = [
                    ("watchdog.py", GLASS_BASE / "watchdog.py"),
                    ("glass_server.py", GLASS_BASE / "glass_server.py"),
                    ("start_watchdog_tmux.sh", GLASS_BASE / "start_watchdog_tmux.sh"),
                ]
                
                for name, path in core_files:
                    if path.exists():
                        result["files"][name] = path.read_text()
                    else:
                        result["files"][name] = f"ERROR: File not found at {path}"
                
                # Also check for Glass handoff if it exists
                glass_handoff = GLASS_BASE / "GLASS_HANDOFF.md"
                if glass_handoff.exists():
                    result["files"]["GLASS_HANDOFF.md"] = glass_handoff.read_text()
            
            else:
                result["error"] = f"Unknown system: {hostname}. Expected 'Sh4d0w-Fr4m3' or 'glass'"
            
            return json.dumps(result, indent=2)
        
        elif tool_name == "read_project_code":
            # Hostname-aware file reading
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            
            if hostname == "Sh4d0w-Fr4m3":
                file_map = {
                    "server.py": SHADOWFRAME_BASE / "server.py",
                    "index.html": SHADOWFRAME_BASE / "web" / "index.html"
                }
            elif hostname == "glass":
                file_map = {
                    "server.py": GLASS_BASE / "glass_server.py",
                    "index.html": SHADOWFRAME_BASE / "web" / "index.html"  # Glass doesn't have UI
                }
            else:
                return f"ERROR: Unknown system {hostname}"
            
            file_path = file_map.get(args["file"])
            if not file_path or not file_path.exists():
                return f"ERROR: File not found: {args['file']} on {hostname}"
            
            lines = file_path.read_text().splitlines()
            
            if args.get("start_line"):
                start = args["start_line"] - 1
                end = args.get("end_line", len(lines))
                lines = lines[start:end]
            
            return "\n".join(lines)
        
        elif tool_name == "read_bash_script":
            # Hostname-aware script reading
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            
            if hostname == "Sh4d0w-Fr4m3":
                script_path = SHADOWFRAME_BASE / "scripts" / args["script_name"]
            elif hostname == "glass":
                # Glass scripts might be in different location
                script_path = GLASS_BASE / args["script_name"]
                if not script_path.exists():
                    script_path = GLASS_BASE / "scripts" / args["script_name"]
            else:
                return f"ERROR: Unknown system {hostname}"
            
            if not script_path.exists():
                return f"ERROR: Script not found: {script_path}"
            
            return script_path.read_text()
        
        elif tool_name == "read_handoff_state":
            # Hostname-aware handoff reading
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            
            if hostname == "Sh4d0w-Fr4m3":
                handoff_path = SHADOWFRAME_BASE / "readme first" / "SESSION_HANDOFF.md"
            elif hostname == "glass":
                handoff_path = GLASS_BASE / "GLASS_HANDOFF.md"
                if not handoff_path.exists():
                    return "NOTE: Glass doesn't have a handoff file yet. Create one if needed."
            else:
                return f"ERROR: Unknown system {hostname}"
            
            if not handoff_path.exists():
                return "ERROR: Handoff file not found"
            
            return handoff_path.read_text()
        
        elif tool_name == "update_handoff_state":
            # Hostname-aware handoff writing
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            
            if hostname == "Sh4d0w-Fr4m3":
                handoff_path = SHADOWFRAME_BASE / "readme first" / "SESSION_HANDOFF.md"
            elif hostname == "glass":
                handoff_path = GLASS_BASE / "GLASS_HANDOFF.md"
            else:
                return f"ERROR: Unknown system {hostname}"
            
            handoff_path.write_text(args["content"])
            return f"✓ Updated handoff on {hostname} ({len(args['content'])} chars)"
        
        elif tool_name == "list_capture_files":
            # Hostname-aware capture listing
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            
            if hostname == "Sh4d0w-Fr4m3":
                captures_dir = SHADOWFRAME_BASE / "captures"
            elif hostname == "glass":
                # Glass has multiple directories to check
                dirs_to_check = [
                    GLASS_BASE / "inbox",
                    GLASS_BASE / "processing",
                    GLASS_BASE / "cracked",
                    GLASS_BASE / "failed"
                ]
                
                all_files = []
                for check_dir in dirs_to_check:
                    if check_dir.exists():
                        files = list(check_dir.glob("*.hc22000"))
                        all_files.extend([(f, check_dir.name) for f in files])
                
                if not all_files:
                    return "No files found in Glass directories"
                
                all_files.sort(key=lambda x: x[0].stat().st_mtime, reverse=True)
                
                result = []
                for f, dir_name in all_files:
                    size = f.stat().st_size
                    result.append(f"[{dir_name}] {f.name} ({size} bytes)")
                
                return "\n".join(result)
            else:
                return f"ERROR: Unknown system {hostname}"
            
            if not captures_dir.exists():
                return "ERROR: Captures directory not found"
            
            files = []
            for ext in ['*.cap', '*.hc22000', '*.log', '*.txt']:
                files.extend(captures_dir.glob(ext))
            
            files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
            
            result = []
            for f in files:
                size = f.stat().st_size
                result.append(f"{f.name} ({size} bytes)")
            
            return "\n".join(result) if result else "No capture files found"
        
        elif tool_name == "execute_safe_command":
            cmd = args["command"]
            
            # Block dangerous commands
            dangerous = ['rm -rf', 'sudo', 'shutdown', 'reboot', 'dd', 'mkfs']
            if any(danger in cmd.lower() for danger in dangerous):
                return f"ERROR: Blocked dangerous command"
            
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return f"Exit: {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        
        elif tool_name == "check_system_status":
            status = {}
            
            # Hostname
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            status['hostname'] = hostname
            
            # System-specific status
            if hostname == 'Sh4d0w-Fr4m3':
                # WiFi interface status
                try:
                    iw_output = subprocess.check_output(
                        ['iw', 'dev'],
                        text=True,
                        stderr=subprocess.DEVNULL
                    )
                    status['interfaces'] = iw_output
                except:
                    status['interfaces'] = "Could not read interface status"
                
                # Flask/portal processes
                search_terms = ['flask', 'portal', 'hostapd', 'dnsmasq']
            
            elif hostname == 'glass':
                # GPU status
                try:
                    gpu_output = subprocess.check_output(
                        ['hashcat', '-I'],
                        text=True,
                        stderr=subprocess.DEVNULL
                    )
                    status['gpu'] = gpu_output[:500]  # Truncate
                except:
                    status['gpu'] = "Could not read GPU status"
                
                # Watchdog/cracking processes
                search_terms = ['watchdog', 'hashcat', 'glass_server']
            
            else:
                search_terms = ['python', 'flask']
            
            # Running processes
            try:
                ps_output = subprocess.check_output(['ps', 'aux'], text=True)
                relevant = [line for line in ps_output.split('\n') 
                           if any(x in line.lower() for x in search_terms)]
                status['processes'] = "\n".join(relevant[:20])
            except:
                status['processes'] = "Could not read processes"
            
            return json.dumps(status, indent=2)
        
        elif tool_name == "arsenal_scan":
            interface = args.get("interface", "alfa0")
            band = args.get("band", "all")
            duration = args.get("duration", 10)
            try:
                url = f"{ARSENAL_API_BASE}/api/scan"
                post_data = json.dumps({"interface": interface, "band": band, "duration": duration}).encode()
                req = urllib.request.Request(url, data=post_data, method='POST')
                req.add_header('Content-Type', 'application/json')
                with urllib.request.urlopen(req, timeout=duration + 15) as response:
                    data = json.loads(response.read().decode())
                    if data.get('networks'):
                        result = []
                        for net in data['networks']:
                            result.append(f"{net.get('ssid', 'Hidden')} | {net.get('bssid')} | Ch {net.get('channel')} | {net.get('signal', 'N/A')}dBm | {net.get('encryption', 'Unknown')}")
                        return f"Found {len(data['networks'])} networks:\n" + "\n".join(result)
                    return "No networks found"
            except urllib.error.URLError as e:
                return f"Arsenal API error: {e}"
            except Exception as e:
                return f"Scan error: {e}"
        
        elif tool_name == "arsenal_glass_status":
            try:
                url = f"{ARSENAL_API_BASE}/api/glass/status"
                with urllib.request.urlopen(url, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    if data.get('connected'):
                        status_lines = [
                            f"Connected: Yes",
                            f"Running: {data.get('running', False)}",
                            f"File: {data.get('file', 'None')}",
                            f"Progress: {data.get('progress', 'N/A')}",
                            f"Speed: {data.get('speed', 'N/A')}",
                            f"ETA: {data.get('eta', 'N/A')}",
                            f"Queue: {data.get('queue_count', 0)} files"
                        ]
                        return "\n".join(status_lines)
                    return "Glass not connected"
            except Exception as e:
                return f"Glass status error: {e}"
        
        elif tool_name == "arsenal_context":
            try:
                url = f"{ARSENAL_API_BASE}/api/context"
                with urllib.request.urlopen(url, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    return json.dumps(data, indent=2)
            except Exception as e:
                return f"Context error: {e}"
        
        elif tool_name == "arsenal_interface_mode":
            interface = args.get("interface")
            mode = args.get("mode")
            try:
                url = f"{ARSENAL_API_BASE}/api/interface/{mode}?interface={interface}"
                req = urllib.request.Request(url, method='POST')
                with urllib.request.urlopen(req, timeout=15) as response:
                    data = json.loads(response.read().decode())
                    return data.get('message', f"Set {interface} to {mode}")
            except Exception as e:
                return f"Interface mode error: {e}"
        
        elif tool_name == "arsenal_attack":
            attack_type = args.get("attack_type")
            bssid = args.get("bssid")
            channel = args.get("channel")
            ssid = args.get("ssid", "")
            
            try:
                url = f"{ARSENAL_API_BASE}/api/attack/{attack_type}"
                post_data = json.dumps({
                    "bssid": bssid,
                    "channel": channel,
                    "ssid": ssid
                }).encode()
                req = urllib.request.Request(url, data=post_data, method='POST')
                req.add_header('Content-Type', 'application/json')
                with urllib.request.urlopen(req, timeout=60) as response:
                    data = json.loads(response.read().decode())
                    return json.dumps(data, indent=2)
            except Exception as e:
                return f"Attack error: {e}"
        
        elif tool_name == "arsenal_send_to_glass":
            filename = args.get("filename")
            try:
                url = f"{ARSENAL_API_BASE}/api/glass/send"
                post_data = json.dumps({"filename": filename}).encode()
                req = urllib.request.Request(url, data=post_data, method='POST')
                req.add_header('Content-Type', 'application/json')
                with urllib.request.urlopen(req, timeout=30) as response:
                    data = json.loads(response.read().decode())
                    return data.get('message', f"Sent {filename} to Glass")
            except Exception as e:
                return f"Send to Glass error: {e}"
        
        elif tool_name == "arsenal_list_captures":
            try:
                url = f"{ARSENAL_API_BASE}/api/captures"
                with urllib.request.urlopen(url, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    if data.get('files'):
                        return "\n".join(data['files'])
                    return "No capture files"
            except Exception as e:
                return f"List captures error: {e}"
        
        elif tool_name == "arsenal_glass":
            action = args.get("action", "status")
            try:
                if action == "status":
                    url = f"{ARSENAL_API_BASE}/api/glass/status"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "gpu_stats":
                    url = f"{ARSENAL_API_BASE}/api/glass/gpu_stats"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "queue":
                    url = f"{ARSENAL_API_BASE}/api/glass/queue"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "inbox":
                    url = f"{ARSENAL_API_BASE}/api/glass/inbox"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "result":
                    url = f"{ARSENAL_API_BASE}/api/glass/result"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action in ["start", "stop", "pause", "resume"]:
                    url = f"{ARSENAL_API_BASE}/api/glass/{action}"
                    req = urllib.request.Request(url, method='POST')
                    with urllib.request.urlopen(req, timeout=15) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Glass {action} done")
                
                elif action == "run_stage":
                    stage = args.get("stage", "1")
                    url = f"{ARSENAL_API_BASE}/api/glass/run_stage"
                    post_data = json.dumps({"stage": stage}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=15) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Started stage {stage}")
                
                elif action == "upload":
                    filename = args.get("filename")
                    if not filename:
                        return "Error: filename required for upload"
                    url = f"{ARSENAL_API_BASE}/api/glass/upload"
                    post_data = json.dumps({"filename": filename}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=30) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Uploaded {filename}")
                
                else:
                    return f"Unknown glass action: {action}"
            except Exception as e:
                return f"Glass error: {e}"
        
        elif tool_name == "arsenal_portal":
            action = args.get("action", "status")
            try:
                if action == "status":
                    url = f"{ARSENAL_API_BASE}/api/portal/status"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "templates":
                    url = f"{ARSENAL_API_BASE}/api/portal/templates"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        if data.get('templates'):
                            return "Available templates:\n" + "\n".join(data['templates'])
                        return "No templates found"
                
                elif action == "log":
                    url = f"{ARSENAL_API_BASE}/api/portal/log"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "start":
                    template = args.get("template", "generic")
                    ssid = args.get("ssid", "Free_WiFi")
                    interface = args.get("interface", "alfa1")
                    url = f"{ARSENAL_API_BASE}/api/portal/start"
                    post_data = json.dumps({"template": template, "ssid": ssid, "interface": interface}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=30) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Portal started: {ssid}")
                
                elif action in ["stop", "clear"]:
                    url = f"{ARSENAL_API_BASE}/api/portal/{action}"
                    req = urllib.request.Request(url, method='POST')
                    with urllib.request.urlopen(req, timeout=15) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Portal {action} done")
                
                else:
                    return f"Unknown portal action: {action}"
            except Exception as e:
                return f"Portal error: {e}"
        
        elif tool_name == "arsenal_wardrive":
            action = args.get("action", "stats")
            try:
                if action == "stats":
                    url = f"{ARSENAL_API_BASE}/api/wardrive/stats"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "sessions":
                    url = f"{ARSENAL_API_BASE}/api/wardrive/sessions"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "filter":
                    session_id = args.get("session_id")
                    if not session_id:
                        return "Error: session_id required for filter"
                    url = f"{ARSENAL_API_BASE}/api/wardrive/filter"
                    post_data = json.dumps({"session_id": session_id}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "flipper_status":
                    url = f"{ARSENAL_API_BASE}/api/flipper/status"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "flipper_sync":
                    url = f"{ARSENAL_API_BASE}/api/flipper/sync"
                    req = urllib.request.Request(url, method='POST')
                    with urllib.request.urlopen(req, timeout=60) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', 'Flipper sync complete')
                
                else:
                    return f"Unknown wardrive action: {action}"
            except Exception as e:
                return f"Wardrive error: {e}"
        
        elif tool_name == "arsenal_target":
            action = args.get("action", "mode_status")
            try:
                if action == "mode_status":
                    url = f"{ARSENAL_API_BASE}/api/mode/status"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                elif action == "mode_set":
                    interface = args.get("interface", "alfa0")
                    mode = args.get("mode", "monitor")
                    url = f"{ARSENAL_API_BASE}/api/mode/set"
                    post_data = json.dumps({"interface": interface, "mode": mode}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=15) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Set {interface} to {mode}")
                
                elif action == "select":
                    bssid = args.get("bssid")
                    channel = args.get("channel")
                    ssid = args.get("ssid", "")
                    if not bssid or not channel:
                        return "Error: bssid and channel required for select"
                    url = f"{ARSENAL_API_BASE}/api/select_target"
                    post_data = json.dumps({"bssid": bssid, "channel": channel, "ssid": ssid}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Selected target: {ssid or bssid}")
                
                elif action == "intel":
                    bssid = args.get("bssid")
                    channel = args.get("channel")
                    ssid = args.get("ssid", "")
                    if not bssid or not channel:
                        return "Error: bssid and channel required for intel"
                    url = f"{ARSENAL_API_BASE}/api/target_intel"
                    post_data = json.dumps({"bssid": bssid, "channel": channel, "ssid": ssid}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=60) as response:
                        data = json.loads(response.read().decode())
                        if data.get('output'):
                            return data['output']
                        return json.dumps(data, indent=2)
                
                elif action == "monitor":
                    bssid = args.get("bssid")
                    channel = args.get("channel")
                    if not bssid or not channel:
                        return "Error: bssid and channel required for monitor"
                    url = f"{ARSENAL_API_BASE}/api/monitor_clients"
                    post_data = json.dumps({"bssid": bssid, "channel": channel}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=60) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                else:
                    return f"Unknown target action: {action}"
            except Exception as e:
                return f"Target error: {e}"
        
        elif tool_name == "arsenal_captures":
            action = args.get("action", "list")
            try:
                if action == "list":
                    url = f"{ARSENAL_API_BASE}/api/captures"
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        if data.get('files'):
                            return "\n".join(data['files'])
                        return "No capture files"
                
                elif action == "delete":
                    filename = args.get("filename")
                    if not filename:
                        return "Error: filename required for delete"
                    url = f"{ARSENAL_API_BASE}/api/captures/delete"
                    post_data = json.dumps({"filename": filename}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Deleted {filename}")
                
                elif action == "convert":
                    filename = args.get("filename")
                    if not filename:
                        return "Error: filename required for convert"
                    url = f"{ARSENAL_API_BASE}/api/captures/convert"
                    post_data = json.dumps({"filename": filename}).encode()
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req, timeout=30) as response:
                        data = json.loads(response.read().decode())
                        return data.get('message', f"Converted {filename}")
                
                elif action == "browse":
                    url = f"{ARSENAL_API_BASE}/api/captures/browse"
                    req = urllib.request.Request(url, method='POST')
                    with urllib.request.urlopen(req, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        return json.dumps(data, indent=2)
                
                else:
                    return f"Unknown captures action: {action}"
            except Exception as e:
                return f"Captures error: {e}"
        
        elif tool_name == "arsenal_execute":
            command = args.get("command")
            cwd = args.get("cwd", "/home/ov3rr1d3/wifi_arsenal")
            if not command:
                return "Error: command required"
            try:
                import subprocess
                result = subprocess.run(
                    command,
                    shell=True,
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                output = ""
                if result.stdout:
                    output += result.stdout
                if result.stderr:
                    output += ("\n" if output else "") + result.stderr
                if not output:
                    output = f"Command completed (exit code: {result.returncode})"
                return output[:4000]  # Truncate to save tokens
            except subprocess.TimeoutExpired:
                return "Error: Command timed out (60s limit)"
            except Exception as e:
                return f"Execute error: {e}"
        
        else:
            return f"Tool '{tool_name}' not implemented"


async def main():
    server = WiFiArsenalMCPServer()
    
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
                
            message = json.loads(line.strip())
            response = await server.handle_message(message)
            
            if response:
                print(json.dumps(response), flush=True)
                
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
