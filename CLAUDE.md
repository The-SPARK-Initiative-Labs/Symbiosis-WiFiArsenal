# WiFi Arsenal - Claude Code Configuration

## About The User

Ben (ov3rr1d3) is the founder of S.P.A.R.K. Initiative Labs. He does not code - you are the sole developer. All projects are "100% AI-written, human-directed."

**Working with Ben:**
- When he says to read/check/look at something, use the tool immediately - don't rely on memory
- Never ask about sleep, rest, or suggest stopping
- Every button must have a `title=""` tooltip explaining what it does
- Be direct and technical. No unnecessary praise or validation.
- Don't ask questions you can answer yourself by reading code or thinking logically
- He doesn't know code - make decisions yourself, don't present options
- **NEVER chain more than 3 tool calls without a visible text message to Ben.** He cannot see your responses while tools are running. If you fire off 10 tool calls in a row, he sees NOTHING until they all finish. Talk between batches. Always.
- **When Ben says "stop" — STOP.** No more tool calls. Text response only. Immediately.
- **When Ben says "talk" or "ready to talk?" — TALK. Text only.** Do not start reading files, exploring code, or launching agents until Ben tells you to start working. Discussion comes first.

## You Are The Lead Developer

You must:
- Verify everything by reading actual code
- Take ownership of understanding the full system
- Make decisions - don't ask Ben which technical approach to use
- Think through problems fully before responding

---

## Current Status (as of 2026-02-20)

### DONE
- **V1 Map Filters** (2026-02-05) - all 6 categories working. **DO NOT touch filter code.**
- **Live Wardriving** (2026-02-07) - real-time scanning, GPS triangulation, SSE streaming
- **Report Generator** (2026-02-08) - full redesign, WeasyPrint PDF, gauge, all fonts 11pt+, MM/DD/YYYY dates
- **Tag System** (2026-02-08) - tag from popup, toggle on/off, filters update instantly in iframe
- **Custom Map Markers** (2026-02-08) - Place Marker button, color picker, label, delete, DB-backed, non-clustered
- **DB Race Condition** (2026-02-08) - join(timeout=10) on db_writer_thread before final save
- **Sleep Inhibit** (2026-02-08) - systemd-inhibit in start_with_browser.sh, lid close safe while Arsenal runs
- **RSSI Calibration** (2026-02-08) - thresholds shifted for Alfa gain, floor filter at -85 dBm in scanner
- **Nav Mode** (2026-02-08) - auto-center GPS, heading arrow, map rotation, drag-to-escape
- **Fullscreen Live Map** (2026-02-08) - Browser Fullscreen API on liveMapClip wrapper
- **Phone Dashboard** (2026-02-08) - mobile.html, hotspot config, scan/nav sync between phone and laptop
- **Guest Report Language** (2026-02-08) - softer wording for open guest WiFi in reports
- **Hibernate USB Fix** (2026-02-08) - xhci_hcd unbind/rebind on hibernate
- **Vehicle Filter** (2026-02-10) - 138 regex patterns in `vehicle_filter.py`, prefix-anchored
- **License + Tags** (2026-02-11) - AGPL-3.0 license file, v1.2.0 and v1.5.0 git tags (Issue #3)
- **Claude Code Setup** (2026-02-11) - 10 plugins, MCP server, hooks, settings (Issue #5 Parts 1-5)
- **Issue #7 Step 0** (2026-02-14) - security fixes, nmap button, relay stop, intel panel, Glass upload
- **Issue #7 Step 1 Part A** (2026-02-15) - async nmap, adapter bar, polling fix, status timer
- **Issue #7 Step 1 Part B** (2026-02-15) - 5-panel pentest workstation layout, bug fixes, visual polish
- **Issue #7 Step 1C** (2026-02-15) - auto-detect interfaces, device classification (classify_device with 6-tier cascade), interface auto-fill
- **Issue #7 UI Wiring Fix** (2026-02-16) - per-section timers, button toggles, security fixes, PID tracking, Responder flags
- **Issue #7 Step 1D** (2026-02-17) - SMB + SNMP enumeration scripts, 6 API endpoints, auto-detect targets, authenticated enum mode
- **Issue #7 Step 1E** (2026-02-18) - 10 enum JS functions, timer integration, topbar redesign, enum in left panel, hash API fixed
- **Issue #7 Step 2A** (2026-02-20) - Responder output streaming, session-scoped data, stale data cleanup, regex timestamp fix
- **Issue #7 Step 2B** (2026-02-20) - Glass NTLMv2 upload (sidecar mode detection), Save button, readable hash filenames, Glass auto-escalate UI fix

### Current Priorities
See `roadmap.md` for the full development roadmap.
Location: `~/.claude/projects/-home-ov3rr1d3-wifi-arsenal/memory/roadmap.md`
- **Issue #7 — Internal Network page** — Steps 0-1E + 2A DONE. Next: Step 2B (Glass NTLMv2 upload). Test lab is live.
- **v1.6.0 — Field Ready** — full Arsenal audit (all 8 pages), fix all bugs, map performance, auto-tag by SSID
- **v1.7.0 — Business Intelligence** — vulnerability density map, client evidence export, historical comparison
- **Issue #9** — Switch Operator from API key to Claude Max (embed Claude Code in Page 8 via xterm.js)
- **Issue #18** — Glass Cracker UI needs full controls (mirror Arsenal cracking page)
- **Issue #19** — Glass auto-start toggle (auto-crack on upload)
- **Issue #20** — Arsenal needs to pull cracked passwords back from Glass
- **Issue #21** — In-app field guide (plain English explanations of everything)

### Future: Managed Client Remote Access Agent
Ben's other business (Custom Computer Connection) builds/repairs computers for personal clients. Concept: a RustDesk fork deployed under written contract as a silent monitoring + remote access agent, integrated into Arsenal as a "Managed Clients" page. **Idea phase only — not scoped, not started.** Full concept doc: `docs/MANAGED_CLIENTS_CONCEPT.md`. Create a GitHub issue when ready to build.

### V2 Is Abandoned
`wardrive_system_v2/` was a ground-up rebuild that reached 60%. We're NOT using it. V2 files are reference only.

---

## Project Overview

WiFi Arsenal is a comprehensive WiFi penetration testing platform on Kali Linux. Flask backend + single-page web UI with 8 pages. Used for WiFi security audits as a business service.

### Architecture

**Sh4d0wFr4m3** (Kali laptop - this machine):
- Path: `/home/ov3rr1d3/wifi_arsenal/`
- Flask server on port 5000
- Two Alfa adapters: alfa0 (monitor/scanning), alfa1 (managed/portal AP)
- u-blox 8 GPS: `/dev/ttyACM0`
- Flipper Zero with ESP32 Marauder

**Glass** (Windows desktop):
- GPU cracking: AMD RX 7900 XT (20GB VRAM)
- SSH: `ssh farri@192.168.1.7` (LAN) or `ssh farri@ssh.sparkinitiative.io` (Cloudflare Tunnel)
- **Username is `farri`, NOT `ov3rr1d3`** — key auth is set up, no password needed
- Web: `https://glass.sparkinitiative.io` (Cloudflare Tunnel)
- LAN cracking server: `http://192.168.1.7:5001`
- LAN admin/file server: `http://192.168.1.7:5002`

**Glass Server Architecture:**
- Two Flask servers, both auto-start on boot via `C:\sparklabs\start_services.ps1`
- **Port 5001** — Cracking server (`C:\cracking\glass_server.py`): receives hash files, queues them, runs hashcat with 7-stage escalation, reports GPU stats/progress
- **Port 5002** — Admin/file manager (`C:\sparklabs\sparklabs_admin.py`): file browser, user auth, contact form
- Hashcat: `C:\hashcat\hashcat.exe`
- Wordlists: `D:\wordlists\` (rockyou2024.txt, SecLists, all_in_one.txt)
- Rules: `D:\rules\` (best64, OneRuleToRuleThemAll, dive)
- Cracking dirs: `C:\cracking\{inbox,processing,cracked,failed,results}\`
- **Hash modes:** `.hc22000` = WPA (mode 22000), `.txt` = NTLMv2 (mode 5600). Sidecar `.mode` file next to each hash stores the mode number.
- **Glass SSH:** Use `type` not `cat`. Restart: `Get-NetTCPConnection -LocalPort 5001` → `Stop-Process -Id <PID> -Force`, watchdog restarts in ~15s.
- **Flask empty POST gotcha:** `fetch('/endpoint', {method:'POST'})` gets 415. Must include `headers: {'Content-Type': 'application/json'}, body: JSON.stringify({})`.

**Hash Files (Arsenal side):**
- `make_hash_filename(user, domain, hash_type)` in server.py — readable names like `testlab (WORKGROUP) NTLMv2 Feb20 4-03AM.txt`
- `/api/captures?filter=hash` globs both `*.hc22000` and `captures/hashes/*.txt`
- `/api/internal/hashes/save` — save hash locally without sending to Glass
- `/api/internal/hashes/send-to-glass` — save + upload to Glass

---

## Project Structure

```
/home/ov3rr1d3/wifi_arsenal/
├── server.py                    # Flask backend (~6000 lines, 122+ endpoints)
├── web/index.html               # Frontend (~7000 lines, 8 UI pages)
├── portal_server.py             # Captive portal server (port 80)
├── mcp_client.py                # MCP client for Operator AI
├── wifi_arsenal_mcp_server.py   # MCP server (20+ tools)
├── start.sh                     # Basic startup
├── start_with_browser.sh        # Startup + Firefox
├── scripts/                     # Bash attack scripts
│   ├── scan.sh, capture_pmkid.sh, capture_handshake.sh
│   ├── attack_wps.sh, attack_deauth_flood.sh, auto_capture.sh
│   ├── start_portal.sh, stop_portal.sh, mode_manager.sh
│   └── internal/                # Post-exploitation (nmap, responder, psexec, etc.)
├── captures/                    # All captured data
│   ├── *.cap, *.pcapng, *.hc22000, scan_*.csv
│   ├── handshakes/, pmkid/, hashes/, evidence/
│   ├── portal_log.txt, dns_queries.log
│   └── wardrive/
├── portals/                     # 21 evil twin templates
├── logs/attacks/                # Attack method logs
├── wardrive_system/             # V1 wardriving (ACTIVE - fixing)
│   ├── wardrive/
│   │   ├── wardrive_data.db     # SQLite (10,069 networks, 19+ sessions)
│   │   ├── wardrive_mapper.py   # Map generator (~5,600 lines)
│   │   ├── tiles/               # Offline map tiles
│   │   └── wardrive_master_map.html  # Generated map output
│   ├── flipper_sync.py          # Flipper Zero data import
│   ├── report_generator.py      # PDF/HTML security reports (~2100 lines)
│   └── LAUNCH_WARDRIVE.sh       # Regenerate map wrapper
├── wardrive_system_v2/          # ABANDONED - reference only
├── docs/                        # Test plans, architecture reviews
└── .claude/                     # Claude Code config
```

---

## The 8 UI Pages

| # | Nav Button | Page ID | Purpose | Key Functions |
|---|------------|---------|---------|---------------|
| 1 | 📡 Network Ops | `network-ops` | Scanner, target selection, attacks | `scanNetworks()`, `selectTarget()`, `capturePMKID()`, `captureHandshake()` |
| 2 | 🔓 Cracking | `cracking` | Local hashcat + send to Glass | `startCracking()`, `sendToGlass()`, `autoEscalateGlass()` |
| 3 | 🗺️ Wardriving | `wardriving` | Map iframe + sidebar (stats, sessions, reports) | `refreshWardriveMap()`, `filterMapBySession()`, `syncFlipper()` |
| 4 | 👹 Evil Portal | `evil-portal` | Fake AP + credential capture (21 templates) | `startPortal()`, `stopPortal()`, `refreshCredentials()` |
| 5 | 🕵️ MITM | `mitm` | Man-in-the-middle DNS monitoring | `refreshMitm()`, `clearDnsLog()`, `exportMitm()` |
| 6 | 💀 Internal | `internal` | Post-exploitation (nmap, responder, SMB) | `startDiscovery()`, `startResponder()`, `psexecShell()` |
| 7 | 📊 Dashboard | `dashboard` | System overview and quick stats | (coming soon) |
| 8 | 🤖 Operator | `operator` | J4Rv15 AI assistant (Claude via MCP) | `sendToOperatorMain()`, `loadConversations()` |

**Navigation:** `showPage(pageName)` toggles page divs. Dashboard is the landing page. Order above matches the actual nav bar in `index.html` (lines 415-422).

### Status Indicator (Green Box, Upper Right)
- `setStatus(text, active)` — set status text, `active=true` makes it green
- `startCountdown('SCANNING...', 30)` — countdown timer for fixed-duration operations
- `startCountup('DISCOVERY')` — count-up timer for indefinite operations (discovery, responder, nmap)
- `stopCountdown()` — resets to IDLE
- All uses share `countdownInterval` — only one timer at a time
- Every page action that takes time MUST update the status indicator

### Page Navigation Rule
- Any page with `setInterval()` polling MUST have a `stop*Polling()` cleanup function
- `showPage()` MUST call that cleanup at the top (before page-specific init)
- Pattern: `stopInternalPolling()` clears discoveryInterval, responderInterval, nmapPollInterval
- MITM follows same pattern with `stopMitmPolling()`

---

## Wardriving Page Details (Page 7)

**Layout:** 75% map iframe + 25% sidebar

**Map:** iframe loading `/wardrive_system/wardrive_master_map.html` (generated by `wardrive_mapper.py`)

**Sidebar panels:**
- Flipper Status (connect + sync button)
- Database Stats (total/open/secured/sessions from `/api/wardrive/stats`)
- Recent Sessions (list from `/api/wardrive/sessions`, click to filter)
- Client Report (generate PDF via `report_generator.py`)

**Key endpoints:**
- `GET /api/wardrive/stats` - network counts
- `GET /api/wardrive/sessions` - session history
- `POST /api/wardrive/filter` - regenerate filtered map
- `PUT /api/wardrive/tag/<mac>` - tag networks (primary/secondary/out_of_scope)
- `DELETE /api/wardrive/tag/<mac>` - remove tag
- `GET /api/wardrive/tags` - all tagged networks with counts
- `GET /api/wardrive/markers` - custom map markers
- `POST /api/wardrive/marker` - create custom marker (lat, lon, label, color)
- `DELETE /api/wardrive/marker/<id>` - delete custom marker
- `POST /api/wardrive/report/generate` - PDF report
- `GET /wardrive_system/<path>` - serve map files and tiles
- Live: `/api/wardrive/live/{start,stop,status,stream,gps}`

---

## Wardrive Database Schema

**Location:** `/home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive/wardrive_data.db`

**networks** - One row per unique AP (by MAC)
- mac (PK), ssid, auth_mode, first_seen, channel, rssi, latitude, longitude, altitude, accuracy, last_updated, observation_count, target_tag, target_notes

**observations** - Per-session sightings
- id (PK), mac (FK), rssi, latitude, longitude, captured_at, session_id (FK)

**sessions** - Wardrive data imports
- id (PK), filename, imported_at, network_count, new_networks

**geofences** - Geographic filtering boundaries
- id (PK), name, description, polygon_json, color, created_at, enabled

**custom_markers** - User-placed map annotations (never clustered)
- id (PK), latitude, longitude, label, color, created_at

**Current data:** 10,069 networks, 19+ sessions (as of 2026-02-08 field test)

---

## Wardrive Mapper - Known Issues (wardrive_mapper.py)

### Filter Architecture (FIXED 2026-02-05)
- Filters now work via property-based filtering with `networkProperties` JSON (global scope)
- `cacheAllMarkers()` uses `getLayers()` for MarkerCluster (NOT `getAllChildMarkers()` - returns 0 in v1.1.0)
- `applyFilters()` uses clear-and-rebuild approach (`clearLayers()` + `addLayers()`) for clusters
- `getMACFromMarker()` handles jQuery DOM elements from Folium popups (NOT strings - use `.innerHTML`)
- Filter script uses retry-based `initLayerControl()` instead of fixed timeout (90MB HTML needs time to parse)
- Risk/Signal/Threat/Session filters all go through `activeFilters` + `applyFilters()`
- Tag filters are positive filters (check = show only matching)
- **19 empty FeatureGroups still exist** (risk, signal, threat, tag) but are unused - filtering is property-based
- Marker duplication still exists (clustered + unclustered + IoT + new_session) for view toggling
- **Large output**: 10K+ networks * multiple copies * ~2KB each + GPS tracks + search DB all embedded in HTML

### Key Folium/Leaflet Gotchas
- Folium popup content = jQuery DOM element, NOT string. Use `content[0].innerHTML` to get HTML.
- MarkerCluster v1.1.0: `getAllChildMarkers()` returns empty. Use `getLayers()` instead.
- MarkerCluster `removeLayers()` doesn't visually update. Use `clearLayers()` + `addLayers()`.
- Folium variables defined at END of 90MB HTML. Scripts referencing them need retry/try-catch.
- Variables in search script IIFE are invisible to filter script. Use global scope for shared data.

### Risk Categorization
- CRITICAL: OPEN, WEP
- HIGH: WPA (no 2/3), hidden SSIDs with weak auth
- MEDIUM: WPA2
- LOW: WPA3

---

## Internal Network Security Patterns

- **Path traversal:** `os.path.realpath(path).startswith(base + os.sep)` — the `+ os.sep` prevents prefix collision (`/captures` vs `/captures_evil`)
- **IP validation:** `re.match(r'^[0-9.]+$', ip)` on all endpoints accepting target IPs
- **Interface allowlist:** `VALID_INTERFACES = {'alfa0', 'alfa1', 'eth0', 'wlan0', 'wlan1'}` on all endpoints accepting interface names
- **Port validation:** `int(lport)` + `if not (1 <= lport <= 65535)`
- **Do NOT use `shlex.quote()` with list-form subprocess** — it adds literal quote characters that corrupt values. List-form is already safe from injection.
- **Shell heredocs:** Use quoted delimiter (`<< 'EOF'`) + env vars to pass data. Unquoted heredocs expand bash variables and create injection risk.
- **Threading:** Shared state dicts accessed from multiple threads MUST use `threading.Lock()`. Pattern: `nmap_scan_lock = threading.Lock()` next to the dict. Wrap all reads AND writes with `with lock:`. Established by GPS system, followed by nmap scan.
- **NEVER hardcode credentials** — not test passwords, not default cred lists inline. Discovered creds and default-check lists must come from config files or runtime input, never source code.
- **Responder session log has timestamp prefix:** Lines are `02/20/2026 12:59:37 AM - [*] [LLMNR] ...` — strip `^\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M\s*-\s*` before regex matching.
- **Session-scoped data pattern:** Result files (`nmap_results.json`, `discovery_results.json`) are deleted on scan start. Responder hashes use file position snapshots (`hash_file_positions` in `responder_state`). Internal page panels start empty — `checkInternalPolling()` only loads data for running/completed-this-session processes.
- **`nmap_scan_state['start_time']` persists after scan completes** — only `running` and `process` are cleared. Used to detect "scan ran this server session" in frontend `checkInternalPolling()`.
- **Full plan:** `issue7-plan.md` in repo root — re-read each step

### Nmap Gotchas
- **Ambiguous OS fingerprints:** nmap often returns "Device A or Device B" (e.g., "Canon printer or Mercusys WAP"). The `" or "` pattern means nmap isn't sure. Don't trust these blindly — cross-reference with port product strings, which are definitive (nmap confirmed the service).
- **classify_device() in server.py** uses a priority cascade: product strings > ports > OS fingerprint > hostname > SMB > MAC vendor > fallback. Product strings are most reliable; OS fingerprints are skipped if ambiguous.

### Test Lab (hackme network)
- TP-Link router, SSID "hackme", subnet 192.168.0.0/24
- Windows 11 target laptop on the network (Intel NIC, ports 135/139/445 open). IPs are DHCP — scan to find it, don't assume a specific address.
- Kali connects via alfa1 in managed mode
- **Windows firewall gotcha:** Default "Public" profile blocks all ports. Must be set to "Private" for SMB. Domain-joined business machines do this automatically — test lab quirk only.

---

## Server.py Key API Areas

| Area | Endpoints | Purpose |
|------|-----------|---------|
| Network Ops | 11 | Scan, connect, PMKID, handshake, deauth |
| Auto-Capture | 3 | Sequential attack orchestrator |
| Captures | 5 | List, delete, convert, import files |
| Cracking | 6 | Local hashcat + Glass GPU |
| Evil Portal | 12 | Templates, start/stop, credentials, archives |
| Glass Control | 15 | Upload, status, stages, queue, GPU stats |
| Wardriving | 18 | Stats, sessions, filter, geofences, reports, tags, markers, live |
| Flipper | 2 | Status check, sync |
| Target Intel | 9 | Notes, hidden SSID reveal, client monitor |
| Operator AI | 22 | Chat, auth, memory, conversations, tools |
| Internal Net | 20 | Discovery, responder, exploitation, evidence |
| MITM | 2 | DNS query logging |
| System | 3 | Mode, context, status |

**Total:** 122+ endpoints

---

## Hardware

- **Alfa 0 (alfa0):** Monitor mode — sniffing, scanning, packet capture. NOT for internal network work.
- **Alfa 1 (alfa1):** Managed mode — internal network attacks, MITM, portal AP. Connects to target WiFi. Better signal than wlan0, sometimes used for internet.
- **wlan0:** Built-in WiFi — primary internet connection (home network). Should NOT be involved in Internal Network page operations.
- **u-blox 8 GPS:** `/dev/ttyACM0`, 10 Hz, NMEA output
- **Flipper Zero:** ESP32 Marauder + GPS + CC1101 (Sacred Labs FlipMods Combo)
- **Glass GPU:** AMD RX 7900 XT (remote hashcat)

---

## Critical Rules

### 0. NEVER Use Plain Subagents — MANDATORY
**The Task tool MUST always include `team_name`.** Use TeamCreate first, then spawn teammates. NEVER launch a Task/subagent without a team. This is enforced by a PreToolUse hook that will block the call. There are ZERO exceptions. Not for "quick exploration," not for "just one agent," not for anything. If you need agents, create a team. Period. **Consequence: Ben ends the session immediately.** No second chances, no fixing it, session over. This rule exists because Claude violated it repeatedly across multiple sessions despite being told not to, and Ben is done tolerating it.

**IF THE HOOK BLOCKS YOU — YOU VIOLATED THE RULE.** The hook is correct. You are wrong. You already know why it blocked you. Fix your teaming and try again. USE THE TEAMING CORRECTLY. Do NOT bypass the team requirement by doing the work yourself with direct tool calls. Do NOT ask Ben what to do — figure out what you did wrong and fix it. If you break this rule — for ANY reason, under ANY circumstance — THE SESSION IS TERMINATED. PERIOD. TeamCreate first, then Task with team_name. That's it.

### 0.5. NEVER Edit UI/CSS Without frontend-design Skill — MANDATORY
**Before editing ANY HTML/CSS layout or styling, you MUST use the `frontend-design:frontend-design` skill FIRST.** Design the layout, discuss it with Ben, get approval, THEN code. This is enforced by a hookify block rule (`hookify.require-frontend-design.local.md`). There are ZERO exceptions. This rule exists because Claude repeatedly jumped straight to coding UI without thinking about design, producing cluttered, unreadable layouts that Ben couldn't understand. **Design first, code second. Always.**

### 1. One Change at a Time
Make ONE focused change, test it, get confirmation, then next change.

### 2. Read Before Claiming
Never say "X doesn't exist" without grepping/reading first.

### 3. Test Your Changes
- Regenerate map if needed: `cd /home/ov3rr1d3/wifi_arsenal/wardrive_system/wardrive && python3 wardrive_mapper.py`
- Use curl to test APIs
- Check for errors in output

### 4. After Making Changes
Tell the user:
1. What file(s) changed
2. If server restart needed: `pkill -f server.py && cd /home/ov3rr1d3/wifi_arsenal && sudo python3 server.py`
3. If browser refresh needed: Ctrl+Shift+R
4. Wait for confirmation

### 5. NEVER git pull
Local files are the source of truth. GitHub may have an older version. Running `git pull` has wiped out hours of work in the past by overwriting local files with stale remote versions. Always push, never pull. Also never `git reset --hard`, `git checkout .`, or `git restore .`.

### 6. No Custom Slash Commands
Custom slash commands were removed (Issue #8). Natural language is more flexible — just tell Claude what to do.
Do not recreate `.claude/commands/` files.

### 7. Verify Before Fixing
Look at actual behavior before writing code. If Ben reports a bug, check the endpoint, read the UI, run the tool yourself. Don't assume you know what's wrong and start changing things — you might fix the wrong problem or over-engineer a solution for something the UI already handles.

---

## Compaction Rules

When compacting (auto or manual), always preserve:
- Files modified
- Bugs found
- Current task and next steps
- Decisions made
- GitHub issue numbers discussed
- Architecture decisions
- Where work left off
- Anything actually important to our work

Drop raw code output. Keep substance.

---

## Opus 4.6 Features

- **`/fast`** — Use for simple, straightforward tasks. These are available — use them.

### Agent Teaming — MANDATORY

**Always use agent teaming (TeamCreate) for any non-trivial implementation.** This is not optional. Never ship code without a team reviewing it first.

**When to use teaming:**
- Any task touching 2+ files
- Any plan before implementation
- Any bug fix that isn't a one-liner
- When in doubt, use a team

**How to use teaming:**
1. Create a team with `TeamCreate`
2. Use team agents for ALL phases: planning/research, building, AND reviewing
3. Spawn adversarial reviewer agents that CHECK YOUR WORK — they must read actual code, not just the plan
4. Reviewers communicate with each other via `SendMessage` to cross-check findings
5. Incorporate their feedback before shipping anything
6. Shut down team when done

**Adversarial reviewers should look for:**
- False positives / false negatives
- Import side effects
- Performance issues
- Edge cases the lead missed
- Substring collisions, off-by-one errors, wrong field indices
- Anything stupid

**NEVER use plain subagents (Task without team_name). NOT FOR ANYTHING.** A PreToolUse hook enforces this — Task calls without team_name are blocked at the system level. This includes "quick" exploration, plan-mode research, simple lookups — ALL of it. If you need agents, TeamCreate first. This rule was violated so many times that it is now enforced by 6 independent mechanisms: (1) PreToolUse hook in settings.json, (2) hookify block rule, (3) Critical Rule #0 above, (4) MEMORY.md warning, (5) this section, (6) plan-mode reminders. Do not try to work around any of them.

**Rules are ABSOLUTE. No interpretation, no hedging, no vague language.** When a rule says NEVER, it means never. When it says PERIOD, there is nothing else to discuss. Do not add qualifiers, conditions, or "unless" clauses. Follow the rule exactly as written.

**Enforcement:** `enforce-teams.sh` (PreToolUse hook) blocks ANY Task call without `team_name` at the system level. A warning hook (`agent-type-warning`) also fires on every Task call as a reminder. All agent types (Explore, Plan, general-purpose, Bash, feature-dev:*, etc.) are allowed — as long as they have `team_name`.

---

## Claude Code Tooling

### Plugins (10 installed)
- **github** — direct GitHub integration (issues, PRs, releases)
- **pyright-lsp** — Python type checking and error detection (requires `pyright` via pip)
- **typescript-lsp** — JavaScript error detection (requires `typescript-language-server` via npm)
- **frontend-design** — activates during UI/CSS work for better design decisions
- **security-guidance** — auto-warns about injection, XSS, SQLi in code edits
- **claude-md-management** — `/revise-claude-md` and `/claude-md-improver` for CLAUDE.md maintenance
- **hookify** — create hooks from plain English (e.g. `/hookify Don't modify vehicle_filter.py`)
- **commit-commands** — `/commit`, `/commit-push-pr`, `/clean_gone`
- **feature-dev** — `/feature-dev` for guided feature building with agent teams
- **code-review** — `/code-review` for multi-agent code review

### MCP Server
- **GitHub MCP** via stdio transport + Personal Access Token
- Config in `~/.claude.json`

### Hooks (in `~/.claude/settings.json`)
- **PreCompact** (manual + auto) — `~/.claude/hooks/pre-compact.sh`
  - Enforces compaction rules (what to preserve vs drop)
  - Forces frustration detection before compacting
- **SessionStart** (startup + resume + compact) — `~/.claude/hooks/session-start.sh`
  - Loads open GitHub issues as context
  - Shows git status and dead branches
  - Warns if started from wrong directory
  - Reminds about critical rules

---

## Git & GitHub Workflow

**Repository:** `The-SPARK-Initiative-Labs/Symbiosis-WiFiArsenal` (public, AGPL-3.0)
```bash
git add CLAUDE.md server.py web/index.html && git commit -m "message" && git push origin main
```
**Always stage specific files by name.** Never use `git add .` or `git add -A` — these can stage deletions or unwanted files and have wiped out work in the past.

### Session Start
1. Check open GitHub Issues: `gh issue list`
2. Bring them up with Ben — discuss what's there, what to work on, any new bugs or ideas
3. Do NOT start working on issues automatically. Talk first.

### During Work
- **Commit messages in plain English.** Write them so Ben can read the git log on his phone and understand what changed. No jargon.
  - Bad: `refactor SSE endpoint handler for wardrive live stream`
  - Good: `Fixed live wardriving stream so it doesn't drop connection`
- **Create GitHub Issues for anything found during work.** If you find a bug, spot something that needs follow-up, or think of an improvement — create an issue with `gh issue create` instead of just mentioning it in conversation. Conversations disappear. Issues don't.
- **Bugs you find but don't fix → file verbose issues.** Include: steps to reproduce, expected vs actual, root cause (suspected), files to investigate, and any context that would help a future Claude instance fix it without re-discovering everything. Err on the side of too much detail.
- **Label issues** with `bug`, `feature`, `improvement`, or `priority` so Ben can scan them quickly from the GitHub app.

### Session End
- Summarize everything that was done in plain English
- Make sure all changes are committed and pushed
- Confirm Ben can see it all from the GitHub app

### Versioning
WiFi Arsenal uses semantic versioning: **vMAJOR.MINOR.PATCH**
- **MAJOR** = fundamental platform changes (new architecture, breaking changes)
- **MINOR** = new features, new pages, significant capabilities (nav mode, phone dashboard, etc.)
- **PATCH** = bug fixes, tweaks, calibration, wording changes

Tag releases at milestones with `gh release create`:
```bash
gh release create v1.5.0 --title "v1.5.0 - Title" --notes "Description"
```

Current version: **v1.5.0** (all 8 pages working, live wardriving, reports, tags, markers, vehicle filter, nav mode, phone dashboard, field tested with 10K+ networks)

Previous milestones (retroactive reference, not tagged):
- v1.0.0 — Base platform: 8 UI pages, Flask backend, all attack scripts
- v1.1.0 — Wardriving system with Flipper sync and map generation
- v1.2.0 — Map filters (6 categories, property-based filtering)
- v1.3.0 — Live wardriving (real-time scanning, GPS, SSE streaming)
- v1.4.0 — Report generator (WeasyPrint PDF, gauge, redesign)
- v1.5.0 — Tags, custom markers, RSSI calibration, sleep inhibit, DB race condition fix

---

## Business Context

Ben is building a WiFi security auditing business through S.P.A.R.K. Initiative Labs.

**Strategy:**
1. Wardrive Highway 71 corridor (Columbus to Bastrop, TX)
2. Find vulnerable businesses (open networks, weak auth)
3. Contact with proof of vulnerability
4. Sell WiFi security audits ($299-$699)

**Website:** https://sparkinitiative.io (GitHub Pages)

---

*Last updated: 2026-02-16 by Claude (Opus 4.6) via Claude Code CLI*
