# Issue #7 — Internal Network Page: Full Implementation Plan

## Context

The Internal Network page (Page 6 in the UI, `showPage('internal')`) needs to become a full post-exploitation audit platform. This is the "deliver" step in Ben's business pipeline: wardrive → find vulnerable businesses → sell audit → **deliver internal assessment using this page**.

**Current state:** The page already has a working foundation — 25 backend endpoints, 18 shell scripts, 22 frontend functions. All tested live against the running server (13/14 pass, 1 expected timeout on sync nmap). This is NOT a ground-up build — it's enhancements on top of working code.

**Goal:** Walk Ben through a complete internal assessment with one-click tools — discovery, credential harvesting, lateral movement, proof of access, and professional reporting.

**All tools needed are installed on this Kali box** (Impacket 0.13, CrackMapExec 5.4, NetExec 1.4, Metasploit 6.4, Nmap 7.98, Responder 3.1.7, Hydra 9.6, xfreerdp3, smbclient, enum4linux, snmpwalk, rpcclient, WeasyPrint 68.1). Only `scrot` is missing (ImageMagick `import` is the fallback).

---

## What Already Works (Verified by Testing)

| Feature | Backend | Scripts | Frontend | Live Test |
|---------|---------|---------|----------|-----------|
| Passive Discovery (Scapy) | 5 endpoints | discover.py + start/stop scripts | start/stop/clear/results + 3s polling | PASS |
| Nmap Scan | 1 endpoint | nmap_scan.sh | **NO UI BUTTON** | PASS (sync, blocks) |
| Intelligence Aggregation | 1 endpoint | — | — (not called from UI) | PASS |
| Responder | 3 endpoints | start/stop + monitor_hashes.sh | start/stop + 5s hash polling | PASS |
| Hash Display & Management | 2 endpoints | — | full credential list UI | PASS |
| Send to Glass (NTLM) | 1 endpoint | — | sendHashToGlass() | **SAVES FILE ONLY — no Glass upload** |
| PsExec Shell | 1 endpoint | psexec_shell.sh | button + validation | PASS (terminal only) |
| WMIExec Shell | 1 endpoint | wmiexec_shell.sh | button + validation | PASS (terminal only) |
| SecretsD dump | 1 endpoint | secretsdump.sh | button + output display | PASS |
| EternalBlue | 1 endpoint | start_eternalblue.sh + msf RC | button + confirm dialog | PASS |
| NTLM Relay | 2 endpoints | ntlmrelay.sh | start button only — **NO STOP BUTTON** | PASS |
| Metasploit Listener | 2 endpoints | start_listener.sh + msf RC | start/stop + status | PASS |
| SMB Share Listing | 1 endpoint | smb_list.sh | button + raw output | PASS |
| SMB File Download | 1 endpoint | smb_download.sh | **NO UI** | (not tested) |
| RDP Screenshot | — | rdp_screenshot.sh | **NO UI** | (not tested) |
| Evidence Locker | 3 endpoints | — | list + download + ZIP export | PASS |

---

## Build Order

This is a multi-session build. Each step is a working increment.

### STEP 0: Quick Fixes — DONE (2026-02-14)

All 6 fixes implemented, reviewed by security + frontend agents, committed and pushed.

**Files to modify:** `server.py`, `web/index.html`

1. **Add Nmap Scan button to UI** — The backend endpoint and script exist. Frontend just needs a button that calls `POST /api/internal/scan` with a subnet input. Add to the Discovery panel.
   - Add subnet input field (default: 192.168.1.0/24) to the Discovery panel
   - Add "Scan" button calling new `nmapScan()` JS function
   - Make it async: show "Scanning..." state, disable button during scan, display results when done
   - Display nmap results in the Discovery Results panel (host table with IPs, ports, services)

2. **Add Relay Stop button** — Backend `POST /api/internal/exploit/relay/stop` exists. Add a "Stop Relay" button next to the NTLM Relay button in Attack Modules.
   - Add `stopRelay()` JS function calling the existing endpoint
   - Add button to the Exploitation button group

3. **Fix Send-to-Glass for NTLM hashes** — The endpoint saves the hash file but never uploads to Glass. Add the `try_glass_request` upload call.
   - In `internal_send_hash_to_glass()` (server.py ~line 6393): after saving the hash file, call `try_glass_request('post', '/upload', files=...)` using the same pattern as `glass_upload()` (server.py ~line 2034)
   - Glass needs to know this is NTLMv2 (hashcat mode 5600), not WiFi (mode 22000). Add hash_type field or filename convention so Glass can pick the right mode.
   - **OPEN QUESTION:** Glass server is WiFi-specific (stages are WiFi wordlists). NTLM cracking needs different wordlists. This may require Glass server changes which are on a different machine. For now, just get the upload working — manual hashcat mode selection on Glass side.

4. **Fix path traversal in ALL file-handling endpoints** — Not just evidence download (line ~6676). Audit ALL endpoints that handle user-supplied file paths:
   - `internal_evidence_download(target, filename)` — both `target` AND `filename` are URL params from user
   - `internal_smb_download()` — output file path derived from user input
   - `internal_evidence_export()` — walks directories, verify it can't escape evidence dir
   - Fix: `os.path.realpath()` check on every resolved path, ensure it stays within the expected directory. Reject with 403 if it escapes.

5. **Add input sanitization to exploitation endpoints** — PsExec, WMIExec, secretsdump, EternalBlue, relay all pass user input directly as shell script arguments. Use `shlex.quote()` in Python for all values passed to shell scripts — NOT regex whitelisting (passwords can contain any character). Only use regex validation for IP/subnet targets (`^[0-9./]+$`).

6. **Wire up Intel endpoint to UI** — `GET /api/internal/intel` exists and returns rich data (targets, recommendations, attack_ready status) but nothing in the frontend calls it. Add an "Intel" panel or integrate into Discovery Results to show actionable intelligence after discovery runs.

---

### STEP 1: Discovery Enhancements (1-2 sessions)

Enhance Phase 1 from Issue #7. Build on existing passive discovery + nmap scan.

**Files to modify:** `server.py`, `web/index.html`, `scripts/internal/nmap_scan.sh`
**Files to create:** `scripts/internal/enum_smb.sh`, `scripts/internal/enum_snmp.sh`, `scripts/internal/banner_grab.sh`

0. **Adapter Mode Control on Internal Network Page** — The Network Ops page (Page 1) has mode switching for alfa0/alfa1 (monitor/managed). The Internal Network page needs this too so you don't have to leave the page to set up your connection. Add a compact adapter status + mode toggle to the top of the page (or the top bar in the 5-panel layout). Look at the Network Ops page for the existing pattern — same endpoints, just a simpler UI since internal pentesting mostly needs managed mode on one adapter. The discovery interface dropdown (alfa0/eth0/wlan0 etc.) should reflect which adapter is actually connected to the target network.

1. **Enhanced Nmap Scan** — Upgrade nmap_scan.sh from quick top-20 scan to full service + OS detection
   - Add `-sV` (version detection) and `-O` (OS fingerprinting) flags
   - Add `--script=smb-os-discovery,smb-security-mode` for SMB hosts
   - Parse results into structured JSON: IP, MAC, hostname, OS, device_type, open ports with service name + version
   - Make the scan endpoint async: `POST /api/internal/scan` starts scan and returns immediately, `GET /api/internal/scan/status` polls completion, `GET /api/internal/scan/results` returns results. Same pattern as discovery start/status/results.

2. **Device Type Classification** — Auto-categorize discovered hosts
   - Add classification logic to the intel endpoint or a new processing step
   - Categories: Workstation, Server, Printer, IP Camera, IoT, Router/Switch, NAS, Phone, Unknown
   - Based on: OS fingerprint, open ports/services, MAC OUI prefix, hostname patterns
   - Add a `device_type` field to the discovery results JSON

3. **SMB Share Enumeration** — New script `enum_smb.sh`
   - For each host with port 445 open, run `smbclient -L -N` (anonymous) and `enum4linux -a`
   - Identify accessible shares, permissions, interesting files
   - Store results in `captures/smb_enum_results.json`
   - New endpoint: `POST /api/internal/discover/smb-enum` with `{ targets: [...] }`

4. **SNMP Enumeration** — New script `enum_snmp.sh`
   - For each host with port 161 open, try default community strings (public, private, community)
   - Run `snmpwalk -c <community> -v2c <target> 1.3.6.1.2.1.1` for system info
   - Store results in `captures/snmp_enum_results.json`
   - New endpoint: `POST /api/internal/discover/snmp-enum`

5. **Interactive Host Table** — Replace raw output with a proper table
   - Sortable/filterable table showing: IP, Hostname, OS, Type, Ports, Risk Level, Actions
   - Click a host to expand details (full port list, services, SMB shares, available attacks)
   - "Attack" dropdown per host with context-appropriate options
   - Color-coded risk indicators (red for critical vulns, yellow for medium, green for low)

6. **Network Topology Visualization** — Optional, could defer to later
   - Simple network diagram showing discovered hosts grouped by subnet
   - Can use SVG or canvas — rendered server-side or client-side
   - Shows connections/relationships between hosts
   - **This is nice-to-have. Can ship without it and add later.**

---

### STEP 2: Credential Harvesting Enhancements (1-2 sessions)

Enhance Phase 2 from Issue #7. Build on existing Responder + hash pipeline.

**Files to modify:** `server.py`, `web/index.html`, `scripts/internal/monitor_hashes.sh`
**Files to create:** `scripts/internal/default_cred_check.sh`, `scripts/internal/cred_spray.sh`

1. **Real-time Hash Display** — Currently polls every 5s. Upgrade to SSE (Server-Sent Events) for instant updates.
   - New endpoint: `GET /api/internal/hashes/stream` — SSE stream that watches hashes.json for changes
   - Frontend: `EventSource` listener that appends new hashes to the credential list immediately
   - Show toast/notification when new hash captured
   - **Alternative:** Keep polling but reduce interval to 2s. SSE is better UX but more work. Polling works fine.

2. **Default Credential Checking** — New script `default_cred_check.sh`
   - Take a list of discovered hosts + their services
   - For each service, try common default credentials:
     - SSH/Telnet: admin/admin, admin/password, root/root, root/toor
     - HTTP admin panels: admin/admin, admin/password
     - Printers: no auth, admin/admin
     - IP cameras: admin/admin, admin/12345, root/root
     - Routers: admin/admin, admin/password, cisco/cisco
   - Use Hydra for the actual credential testing: `hydra -l <user> -p <pass> <target> <service>`
   - Store results in `captures/default_creds_results.json`
   - New endpoint: `POST /api/internal/creds/default-check` with `{ targets: [...] }`
   - Display results in the Captured Credentials panel with source "Default Credentials"

3. **Credential Spray** — New script `cred_spray.sh`
   - Take a cracked password and test it against all discovered hosts
   - Use CrackMapExec: `crackmapexec smb <targets> -u <user> -p <pass>`
   - Or NetExec: `netexec smb <targets> -u <user> -p <pass>`
   - Store results showing which hosts the credential works on
   - New endpoint: `POST /api/internal/creds/spray` with `{ user, password, targets: [...] }`
   - Display results: green checkmarks for successful logins, red X for failed

4. **LLMNR/NBT-NS/WPAD Status Panel** — Show what Responder is actively poisoning
   - The discovery results already capture LLMNR/NBT-NS/WPAD queries
   - Add a real-time panel showing: queries being poisoned, responses sent, hashes captured
   - Pull from `captures/discovery_results.json` (already has llmnr, nbns, wpad arrays)

---

### STEP 3: Lateral Movement Enhancements (1-2 sessions)

Enhance Phase 3 from Issue #7. Build on existing PsExec/WMI/SecretsDump.

**Files to modify:** `server.py`, `web/index.html`
**Files to create:** `scripts/internal/crackmapexec_scan.sh`, `scripts/internal/pass_the_hash.sh`, `scripts/internal/ssh_exec.sh`

1. **Pass-the-Hash** — Use captured NTLM hashes without cracking
   - New script `pass_the_hash.sh` using `impacket-psexec -hashes :<ntlm_hash> <target>`
   - Also works with `impacket-wmiexec` and `impacket-smbexec`
   - New endpoint: `POST /api/internal/exploit/pth` with `{ target, user, hash, method: 'psexec'|'wmiexec'|'smbexec' }`
   - Add "Pass-the-Hash" button to Attack Modules (separate from credential-based buttons)
   - Hash field auto-populated from captured hashes via "Use Hash" button

2. **CrackMapExec Integration** — Swiss army knife for network pentesting
   - New script `crackmapexec_scan.sh`
   - Functions: enumerate shares, spray creds, execute commands across multiple hosts
   - New endpoint: `POST /api/internal/exploit/cme` with `{ targets, user, password, action: 'enum'|'spray'|'exec', command }`
   - Display results in the Output panel

3. **SMBExec, DcomExec & AtExec** — Additional lateral movement methods
   - Add buttons for `impacket-smbexec`, `impacket-dcomexec`, and `impacket-atexec` (all installed)
   - New scripts: `smbexec_shell.sh`, `dcomexec_shell.sh`, `atexec_shell.sh` (same pattern as psexec_shell.sh)
   - New endpoints following existing pattern

4. **RDP Access with Screenshot** — Wire up the existing rdp_screenshot.sh
   - Add "RDP" button to Attack Modules
   - New endpoint: `POST /api/internal/exploit/rdp` with `{ target, user, password }`
   - Calls rdp_screenshot.sh, captures screenshot
   - Display screenshot in the Evidence Locker when done

5. **SSH Access** — Remote command execution via SSH
   - New script `ssh_exec.sh` using `sshpass -p <pass> ssh <user>@<target> <command>`
   - New endpoint: `POST /api/internal/exploit/ssh` with `{ target, user, password, command }`
   - Display output in the Output panel

6. **Attack Path Tracking** — Log every action as a step in the attack chain
   - Create an `attack_log.json` file tracking: timestamp, source_host, target_host, method, result, credentials_used
   - Every exploitation endpoint appends to this log
   - New endpoint: `GET /api/internal/attack-path` returning the full chain
   - New endpoint: `POST /api/internal/attack-path/clear` to reset for new engagement
   - **UI:** Timeline visualization at bottom of page showing the attack progression
   - This feeds directly into Phase 5 reporting

7. **Process Manager** — Track and clean up background processes
   - Server-side registry of all spawned internal processes (discovery, responder, relay, listener, nmap, exploit shells)
   - New endpoint: `GET /api/internal/processes` — list all running internal processes with PIDs
   - New endpoint: `POST /api/internal/processes/kill-all` — stop all running internal processes (cleanup between engagements)
   - UI: "Kill All" button in a status bar showing active process count
   - On server restart: auto-cleanup any orphaned PID files in /tmp/

---

### STEP 4: Proof of Access (1-2 sessions)

Build Phase 4 from Issue #7. The scare tactics — this is what sells ongoing security services.

**Files to modify:** `server.py`, `web/index.html`
**Files to create:** `scripts/internal/webcam_capture.sh`, `scripts/internal/screenshot_capture.sh`, `scripts/internal/browser_dump.sh`, `scripts/internal/printer_test.sh`

1. **Screenshot Capture** — Take a screenshot of compromised machine's desktop
   - rdp_screenshot.sh already exists and works
   - Also add PowerShell-based screenshot via PsExec: `psexec ... powershell -c "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen | ..."`
   - New endpoint: `POST /api/internal/proof/screenshot` with `{ target, user, password, method: 'rdp'|'psexec' }`
   - Save to `captures/evidence/<target>/screenshot_<timestamp>.png`
   - Display immediately in Evidence Locker with thumbnail

2. **Webcam Capture** — Activate webcam on compromised workstation
   - Requires Meterpreter session (via EternalBlue or payload delivery)
   - New script `webcam_capture.sh` that connects to existing Meterpreter session and runs `webcam_snap`
   - Alternative: PowerShell script delivered via PsExec that uses DirectShow/MediaFoundation
   - New endpoint: `POST /api/internal/proof/webcam` with `{ session_id }` or `{ target, user, password }`
   - Save to `captures/evidence/<target>/webcam_<timestamp>.jpg`
   - **NOTE:** This is the centerpiece finding. The photo of the client at their desk.

3. **File Access Proof** — List sensitive files on compromised shares
   - Script that searches SMB shares for: *.xlsx, *.docx, *password*, *confidential*, *payroll*, *hr*, *financial*
   - Just list filenames and paths — don't exfiltrate content (unless client authorizes)
   - New endpoint: `POST /api/internal/proof/file-access` with `{ target, user, password, share }`
   - Display file listing in Evidence Locker with icons by type

4. **Printer Test Page** — Send a test page to network printer
   - New script `printer_test.sh` using `lp -d <printer> <test_file>` or `smbclient` print command
   - New endpoint: `POST /api/internal/proof/printer` with `{ target }`
   - Simple proof of network access — visible, harmless

5. **Router/Switch Admin Access** — Screenshot admin panels
   - Use `curl` or `wget` to fetch the admin page HTML/screenshot
   - Many routers have default credentials (covered in Step 2)
   - New endpoint: `POST /api/internal/proof/admin-panel` with `{ target, user, password }`
   - Save screenshot/HTML to evidence

6. **Browser Saved Passwords Proof** — Show that browser credential stores are accessible
   - New script `browser_dump.sh` — executes PowerShell via PsExec to query browser credential stores
   - Targets Chrome (`Login Data` SQLite), Firefox (`logins.json`), Edge (same as Chrome)
   - Just prove access is possible (list count of saved passwords, show domains) — don't dump actual passwords unless client authorizes
   - New endpoint: `POST /api/internal/proof/browser-creds` with `{ target, user, password }`
   - Save report to `captures/evidence/<target>/browser_creds_<timestamp>.txt`

7. **Email Access Proof** — If Exchange/O365 credentials captured, prove inbox access
   - Read-only: screenshot the inbox, show unread count, prove access
   - For on-prem Exchange: use `curl` against OWA (Outlook Web Access) with captured creds
   - For O365: use captured creds against `https://outlook.office365.com/api/v2.0/me/messages` (if no MFA)
   - New endpoint: `POST /api/internal/proof/email` with `{ target, user, password, type: 'owa'|'o365' }`
   - **NOTE:** This is sensitive — discuss with client before attempting. Ben decides per engagement.
   - Save screenshot/response to evidence

All proof actions automatically save to `captures/evidence/<target>/` and append to `attack_log.json`.

---

### STEP 5: Evidence & Reporting (1-2 sessions)

Build Phase 5 from Issue #7. Professional report generator for internal assessments.

**Files to create:** `wardrive_system/internal_report_generator.py` (~1500-2000 lines)
**Files to modify:** `server.py`, `web/index.html`

**Architecture:** Clone the wardrive `report_generator.py` pattern exactly:
- Single class `InternalReportGenerator`
- Inline Jinja2 template
- WeasyPrint PDF output (floats only, no flex/grid, 11pt+ fonts)
- Module-level singleton with convenience functions
- Three report tiers: executive, summary, full

**Data Sources (different from wardrive):**
- `captures/discovery_results.json` — discovered hosts + vulnerabilities
- `captures/nmap_results.json` — port/service scan results
- `captures/hashes/hashes.json` — captured credentials
- `captures/default_creds_results.json` — default credential findings
- `captures/evidence/` — all proof-of-access files
- `attack_log.json` — the full attack path timeline

**Report Sections:**
1. **Cover Page** — Client name, assessment type, date, S.P.A.R.K. branding
2. **Executive Summary** — Plain English: "We gained full access to X systems in Y minutes using Z methods"
3. **Assessment Timeline** — Chronological attack path from attack_log.json
4. **Risk Score** — SVG gauge (same pattern as wardrive), based on: hosts compromised, credentials captured, access level achieved
5. **Findings** — Each finding with:
   - Description + severity
   - Proof (embedded screenshot/webcam capture as base64 image)
   - Impact explanation in plain English
   - Remediation recommendation
6. **Attack Path Visualization** — Diagram showing: entry point → pivot → compromise chain
7. **Credential Summary** — Table of all captured/cracked credentials (redacted in executive tier)
8. **Network Inventory** — All discovered hosts with risk levels
9. **Remediation Roadmap** — Prioritized action items with cost/time estimates
10. **Next Steps** — S.P.A.R.K. service tiers for ongoing security

**API Endpoints:**
- `POST /api/internal/report/generate` — returns PDF
- `POST /api/internal/report/preview` — returns HTML for browser preview
- `GET /api/internal/report/stats` — returns finding counts by severity

**Report Templates (from Issue #7):**
- **WiFi-only** — already exists (wardrive report)
- **Internal network** — this new report
- **Full assessment** — combined WiFi + internal (future, pulls from both data sources)

---

### STEP 6: UI Redesign (alongside Steps 1-5, not separate)

The UI should evolve incrementally with each step, not be redesigned all at once.

**Current layout:** 3-row flexbox (Discovery+Responder | Credentials+Attack | Output+Evidence)

**Target layout (from Issue #7):**
- **Top bar:** Target network info, engagement status, authorization confirmation, timer
- **Left panel:** Discovered hosts (interactive list/tree, click to see details + attack options)
- **Center:** Main workspace (context-dependent: host details, attack execution, evidence viewer)
- **Right panel:** Live feed (captured credentials, active attacks, attack log)
- **Bottom:** Attack path timeline visualization

**Incremental approach:**
1. **Step 0:** Keep current layout, just add missing buttons and wire up intel
2. **Step 1:** Replace Discovery Results div with the interactive host table. Add host click-to-expand.
3. **Step 2:** Upgrade Credentials panel with real-time indicators, spray results
4. **Step 3:** Add attack path timeline at the bottom
5. **Step 4:** Add proof-of-access buttons per host, evidence thumbnails
6. **Step 5:** Add report generation panel (similar to wardrive sidebar report section)
7. **Final pass:** Restructure into the target layout if the incremental changes haven't already gotten us there

**Authorization Gate:** Before any tools can be used, require a confirmation dialog:
> "This tool is for authorized penetration testing only. Ensure you have written permission from the network owner before proceeding."
- One-time per session confirmation
- Store in sessionStorage so it persists across page switches but not browser restarts
- Show engagement info bar after confirmation (client name, start time, authorization reference)

---

## File Manifest

### Files to Modify
| File | What Changes |
|------|-------------|
| `server.py` | New endpoints for each step, fix Glass upload, fix path traversal, add input sanitization, attack path logging |
| `web/index.html` | New UI elements for each step, host table, attack path timeline, report panel, authorization gate |
| `scripts/internal/nmap_scan.sh` | Add -sV -O flags, async support |

### Files to Create
| File | Purpose | Step |
|------|---------|------|
| `scripts/internal/enum_smb.sh` | SMB share enumeration | 1 |
| `scripts/internal/enum_snmp.sh` | SNMP enumeration | 1 |
| `scripts/internal/banner_grab.sh` | Service banner grabbing | 1 |
| `scripts/internal/default_cred_check.sh` | Default credential testing via Hydra | 2 |
| `scripts/internal/cred_spray.sh` | Credential spray via CrackMapExec/NetExec | 2 |
| `scripts/internal/pass_the_hash.sh` | Pass-the-hash via Impacket | 3 |
| `scripts/internal/crackmapexec_scan.sh` | CrackMapExec multi-function wrapper | 3 |
| `scripts/internal/smbexec_shell.sh` | SMBExec shell (same pattern as psexec) | 3 |
| `scripts/internal/dcomexec_shell.sh` | DcomExec shell | 3 |
| `scripts/internal/atexec_shell.sh` | AtExec shell (scheduled task execution) | 3 |
| `scripts/internal/ssh_exec.sh` | SSH command execution | 3 |
| `scripts/internal/webcam_capture.sh` | Webcam capture via Meterpreter | 4 |
| `scripts/internal/screenshot_capture.sh` | Desktop screenshot via PowerShell/PSExec | 4 |
| `scripts/internal/browser_dump.sh` | Browser saved password proof | 4 |
| `scripts/internal/printer_test.sh` | Printer test page | 4 |
| `scripts/internal/email_access.sh` | Email access proof (OWA/O365) | 4 |
| `wardrive_system/internal_report_generator.py` | Internal assessment PDF report generator | 5 |

---

## Session Planning

| Session | Steps | Focus |
|---------|-------|-------|
| **Session 1** | Step 0 | Quick fixes — nmap button, relay stop, Glass upload, security fixes, intel wiring |
| **Session 2** | Step 1 | Discovery enhancements — enhanced nmap, device classification, SMB/SNMP enum, host table |
| **Session 3** | Step 2 | Credential harvesting — default cred check, credential spray, real-time hash display |
| **Session 4** | Step 3 | Lateral movement — pass-the-hash, CrackMapExec, RDP, SSH, attack path tracking |
| **Session 5** | Step 4 | Proof of access — screenshot, webcam, file access, printer |
| **Session 6** | Step 5 | Report generator — clone wardrive pattern, all sections, PDF output |
| **Session 7** | Step 6 | UI final pass — restructure layout if needed, polish, authorization gate |

Each session produces a working increment. Every step is independently useful.

---

## Verification Plan

After each step:
1. **Restart server:** `pkill -f server.py && cd /home/ov3rr1d3/wifi_arsenal && sudo python3 server.py`
2. **Test every new endpoint with curl** — verify responses
3. **Test in browser** — Ctrl+Shift+R, navigate to Internal page, click every new button
4. **TeamCreate a review team** — have adversarial reviewers check the code for bugs, security issues, edge cases
5. **Commit and push** — plain English commit message

For the final build:
- Run a simulated assessment against Glass (it's a Windows machine on the LAN)
- Generate a test report and review the PDF output
- Have Ben walk through the full flow and confirm it matches his workflow

---

## Open Questions

1. **Glass NTLM support:** Glass server's cracking stages are WiFi-specific (WiFi wordlists). The Glass `/upload` endpoint auto-queues files for WiFi cracking stages — uploading an NTLM hash file will either fail or get cracked with wrong wordlists. Options: (a) add a `hash_type` parameter to Glass's `/upload` endpoint so it picks NTLM wordlists/mode 5600 instead of WiFi mode 22000, (b) add a separate staging endpoint on Glass that accepts hashes without auto-queuing, (c) for now in Step 0, just save the hash file locally and note that Glass upload needs Glass-side changes. **Glass server code is on a different machine** — this needs a separate session working on Glass.

2. **Network topology visualization:** Issue #7 asks for a visual network map. Deferred to a future session — the interactive host table in Step 1 gives 90% of the value with 10% of the complexity. Can revisit after all 5 phases work.

3. **Meterpreter payload delivery:** Webcam/screenshot capture via Meterpreter requires a payload on the target machine. EternalBlue gives a Meterpreter session automatically for SMBv1 hosts. For modern systems, need a different delivery method (macro, HTA, PowerShell download cradle). This is engagement-specific — the tool should support it but Ben decides the delivery method per engagement.

4. **server.py and index.html file size:** server.py is already 6727 lines, index.html is 7898 lines. Adding ~30+ new endpoints and UI across all steps will push both past 9000+ lines. Consider splitting server.py into Flask Blueprints (e.g., `routes/internal.py`) in a future refactoring session. Not a blocker for now but will become painful by Step 3-4.

5. **Credential spray overlap:** Step 2 creates `cred_spray.sh` and Step 3 creates `crackmapexec_scan.sh` which also does spraying. Resolution: `cred_spray.sh` in Step 2 uses CrackMapExec/NetExec directly. In Step 3, `crackmapexec_scan.sh` becomes a multi-function wrapper that includes spray as one action. Step 2's spray script is the simple version; Step 3 supersedes it.
