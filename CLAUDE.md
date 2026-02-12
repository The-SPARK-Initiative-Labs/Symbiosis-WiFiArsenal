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

## You Are The Lead Developer

You must:
- Verify everything by reading actual code
- Take ownership of understanding the full system
- Make decisions - don't ask Ben which technical approach to use
- Think through problems fully before responding

---

## Current Status (as of 2026-02-11)

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

### Current Priorities
See `roadmap.md` for the full development roadmap.
Location: `~/.claude/projects/-home-ov3rr1d3-wifi-arsenal/memory/roadmap.md`
- **v1.6.0 — Field Ready** — full Arsenal audit (all 8 pages), fix all bugs, map performance, auto-tag by SSID
- **v1.7.0 — Business Intelligence** — vulnerability density map, client evidence export, historical comparison
- **v2.0.0 — Full Audit Platform** — Internal Network page, 5-phase post-exploitation (Issue #7)
- **Issue #9** — Switch Operator from API key to Claude Max (embed Claude Code in Page 8 via xterm.js)

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
- GPU cracking: AMD RX 7900 XT
- SSH: `ssh ov3rr1d3@192.168.1.7` or `ssh ov3rr1d3@ssh.sparkinitiative.io`
- Web: `https://glass.sparkinitiative.io` (Cloudflare Tunnel)
- LAN: `http://192.168.1.7:5001`

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

| # | Page | Purpose | Key Functions |
|---|------|---------|---------------|
| 1 | **Network Ops** | Scanner, target selection, attacks | `scanNetworks()`, `selectTarget()`, `capturePMKID()`, `captureHandshake()` |
| 2 | **Evil Portal** | Fake AP + credential capture (21 templates) | `startPortal()`, `stopPortal()`, `refreshCredentials()` |
| 3 | **MITM** | Man-in-the-middle DNS monitoring | `refreshMitm()`, `clearDnsLog()`, `exportMitm()` |
| 4 | **Internal Network** | Post-exploitation (nmap, responder, SMB) | `startDiscovery()`, `startResponder()`, `psexecShell()` |
| 5 | **Captures** | View/manage handshakes, convert formats | `loadCaptures()`, `convertSelected()`, `importCapture()` |
| 6 | **Cracking** | Local hashcat + send to Glass | `startCracking()`, `sendToGlass()`, `autoEscalateGlass()` |
| 7 | **Wardriving** | Map iframe + sidebar (stats, sessions, reports) | `refreshWardriveMap()`, `filterMapBySession()`, `syncFlipper()` |
| 8 | **Operator** | J4Rv15 AI assistant (Claude via MCP) | `sendToOperatorMain()`, `loadConversations()` |

**Navigation:** `showPage(pageName)` toggles page divs. Dashboard is the landing page.

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
| Internal Net | 19 | Discovery, responder, exploitation, evidence |
| MITM | 2 | DNS query logging |
| System | 3 | Mode, context, status |

**Total:** 122+ endpoints

---

## Hardware

- **Alfa 0 (alfa0):** Monitor mode scanning, attacks
- **Alfa 1 (alfa1):** Managed mode, portal AP creation
- **u-blox 8 GPS:** `/dev/ttyACM0`, 10 Hz, NMEA output
- **Flipper Zero:** ESP32 Marauder + GPS + CC1101 (Sacred Labs FlipMods Combo)
- **Glass GPU:** AMD RX 7900 XT (remote hashcat)

---

## Critical Rules

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
2. Spawn adversarial reviewer agents that CHECK YOUR WORK
3. Reviewers must read the actual code, not just the plan
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

**Do NOT use plain subagents (Task without team_name) for non-trivial work.** Subagents can't talk to each other. Use real teams.

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

*Last updated: 2026-02-11 by Claude (Opus 4.6) via Claude Code CLI*
