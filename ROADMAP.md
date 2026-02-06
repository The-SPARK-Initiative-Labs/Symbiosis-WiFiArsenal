# WiFi Arsenal - Roadmap

**Last Updated:** 2025-12-30
**Reality-based plan. No theory. Only what's built and what's next.**

---

## What Actually Works Today

### Scanning & Capture (Sh4d0wFr4m3)
- ✅ 2.4GHz / 5GHz network scanning
- ✅ PMKID capture
- ✅ Handshake capture with deauth
- ✅ Basic local cracking (RTX 3050)

### Distributed Cracking (Glass)
- ✅ Flask API receiving hashes
- ✅ 7-stage auto-escalation cracking (1, 2, 3a, 3b, 4a, 4b, 5)
- ✅ RX 7900 XT GPU @ 1.29 MH/s
- ✅ Web UI with live status (http://localhost:5001)
- ✅ Cloudflare Tunnel for remote access (replaced ngrok)
- ✅ Wordlists on SSD (fast loading)
- ✅ Stage 3b: OneRuleToRuleThemAll (~2 hours)
- ✅ Stage 4a: RockYou 2024 straight (~30 hours)
- ✅ Stage 4b: RockYou 2024 + best64 (~7 days)
- ✅ Status shows current file being cracked

### Wardriving (Flipper + Sh4d0wFr4m3)
- ✅ Flipper captures GPS-tagged networks
- ✅ Auto-sync when plugged in
- ✅ SQLite database (cumulative)
- ✅ Interactive map with heat map, layers, stats
- ✅ Session tracking (derived from first_seen dates)
- ✅ Session filtering - click session to filter map
- ✅ Show All button to reset filter

### Evil Portal
- ✅ 21 templates exist
- ⚠️ Untested - needs verification

---

## The Layers

### Layer 1: Multi-Page UI
Turn working features into a proper interface.

### Layer 2: Professional Tools
Client work, evidence, reporting.

### Layer 3: Intelligence
AI analysis, network relationships, smart cracking.

### Layer 4: Automation
Auto-everything, notifications, scheduling.

---

## Page Designs

### Page: Cracking / Glass
Mirror of Glass Cracker UI + file management

**Layout:** Status panel (left ~60%), controls (right ~40%)

**Features:**
- Live status: progress bar, speed, ETA, current attack
- Stage buttons (1-5), Auto-Escalate, Stop
- File picker: local .hc22000 captures
- "Send to Glass" button
- Queue: files on Glass waiting
- Activity log
- Crack history (what's been cracked, passwords found)

---

### Page: Wardriving
Map as main focus, sidebar for controls

**Layout:** Map (~75%), sidebar (~25%)

**Map Section:**
- Embedded wardrive_master_map.html
- Full interactive (layers, heat map, markers)
- Click session to filter map to just those networks

**Sidebar:**
- Flipper status (🟢/🔴)
- "Sync Now" button + last sync time
- Database stats (total, open, secured, by channel)
- Recent sessions list:
  - "Dec 27 afternoon - 45 networks" (clickable)
  - "Dec 26 downtown - 112 networks"

**Database Changes:**
- Add "sessions" table
- Link networks to sessions
- Track: name, timestamp, network count, notes

---

### Page: Network Ops
Current scanning/attack stuff, cleaned up

**Features:**
- Scan controls (interface, channel, duration)
- Target list with filters (open, WPS, signal strength)
- Attack launcher (PMKID, Handshake, Deauth)
- Live capture status
- One-click "Send to Glass" for captures

---

### Page: Evil Portal
Manage and deploy fake access points

**Features:**
- Template gallery (21 templates with previews)
- SSID configuration
- Interface selector
- Start/Stop controls
- Live credential viewer
- Connected clients list
- Deauth coordination toggle

---

### Page: Dashboard
Overview of everything at a glance

**Features:**
- System status (interfaces up/down, Glass connected)
- Active operations (what's scanning, cracking, etc.)
- Recent captures
- Quick stats (networks today, passwords cracked)
- Alerts/notifications
- Quick launch buttons

---

### Page: Intel / Analysis
Network intelligence and patterns

**Features:**
- Network database browser (all discovered networks)
- Device tracking (MACs seen across networks)
- Vendor lookup (Ubiquiti? Cisco? Consumer?)
- Network relationships (same org detection)
- Vulnerability flags (WPS enabled, open, weak)
- Tag networks: in-scope, out-of-scope, interesting, cracked
- Notes per network
- Timeline (when networks/devices were seen)

---

### Page: Reports
Professional output for clients

**Features:**
- Engagement/client selector
- Auto-generate report from data
- Executive summary + technical findings
- Risk ratings with remediation
- Evidence attachments
- Export: PDF, HTML, JSON
- Compliance mapping (PCI DSS, etc.)

---

### Page: Config
System settings and preferences

**Features:**
- Interface management (alfa0, alfa1, wlan0)
- Glass connection settings
- Flipper settings
- Wordlist management
- Alert preferences
- Theme/display options

---

## Feature Ideas (Beyond Scan/Crack)

### Before Engagement
- Client/engagement profiles
- Scope documentation
- Pre-engagement checklist
- Rules of engagement templates

### Network Intelligence
- MAC vendor lookup
- Detect network relationships (sequential MACs = same org)
- Honeypot/decoy detection
- WPS vulnerability flagging
- Client probe requests (devices looking for SSIDs)
- "Who's here" - see clients without cracking

### Post-Crack
- One-click connect to cracked network
- Quick internal scan (what's on this network?)
- Service discovery
- Gateway/DNS info grab
- Screenshot capture for evidence

### Organization
- Tag/categorize networks
- Notes per network
- Timeline of all actions (audit trail)
- Evidence locker (screenshots, captures, logs)
- Multi-engagement separation

### Reporting
- Auto-generate professional PDF
- Executive summary for non-technical
- CVSS scoring
- Remediation recommendations
- Evidence compilation

### Flipper Integration
- Control Marauder from Arsenal UI
- See Flipper status/battery
- Deploy scripts remotely
- Real-time wardrive view

### Automation
- Auto-send captures to Glass
- Crack notifications (push/email when done)
- Scheduled scans
- File watchers (auto-process new captures)
- Rule-based auto-attacks

### Defensive Monitoring
- Monitor YOUR networks for attacks
- Detect deauth attempts against you
- Rogue AP / evil twin detection
- Alert on suspicious activity

---

## AI Integration (The Operator)

### Core Vision: Teaching Partner
The Operator isn't just automation - it's how you learn the craft.

**The Loop:**
1. You run a scan or monitor
2. Arsenal gathers rich data (clients, signals, WPS status, PMF, probes, etc.)
3. Claude sees it automatically (context injection)
4. Claude explains what you're seeing and why it matters
5. Claude recommends an attack and explains the reasoning
6. You ask questions - "What's Pixie Dust?" "Why that client?"
7. Claude teaches you while you work
8. You say "Try it" - Claude executes
9. Claude narrates what's happening so you understand
10. Win or fail, you learned something

**Not doing it FOR you. Doing it WITH you.**

Every engagement builds your knowledge. In six months you won't need the explanations - you'll know what PMF means, why signal strength matters, when to use what attack. Real skills, not tool dependency.

### Overview
AI assistant embedded in Arsenal with full operational context. Uses Claude API from Sh4d0wFr4m3 (no GPU needed, works while Glass is cracking). Can observe, advise, execute, and most importantly - teach.

### UI Location
- **Floating chat panel** - collapsible corner widget for quick questions during ops
- **AI Ops tab** - full-screen mode for planning sessions and detailed analysis
- Both share same context and conversation history

### Capability Graduation

**Phase A: Observer (Read-Only)**
- Sees all current state (scans, targets, captures, crack status)
- Answers questions about what's happening
- Explains status: "Glass is 40% through stage 4b, ETA 4 days"
- Suggests next moves: "Based on SSID pattern, try coffee shop wordlist"
- Cannot execute anything

**Phase B: Advisor (Approval Mode)**
- Everything from Phase A
- Can propose actions: "I recommend deauth on client X to force handshake"
- Shows Execute/Cancel buttons
- You approve or reject each action
- Logs all proposals and decisions

**Phase C: Autonomous (Rule-Bounded)**
- Can execute within defined rules
- Example rules:
  - "Auto-scan new networks on 5GHz"
  - "Send captures to Glass automatically"
  - "Alert me when crack completes"
- Still asks for approval on attacks
- Full audit trail

### Context Injection (Auto)
Every message automatically includes:
- Active interfaces and modes (monitor/managed)
- Current scan results and target list
- Running attacks and their status
- Glass status (file, stage, progress, speed, ETA, GPU stats)
- Recent captures (last 10)
- Crack results (passwords found)
- Wardrive stats

AI just *knows* without you explaining.

### Memory
- Remembers previous sessions
- Knows your preferences ("you usually target WPA2, ignore open networks")
- Tracks engagement history
- Recalls past decisions and outcomes

### Smart Analysis
- Network grouping: "These 3 APs are same business - sequential MACs"
- Vulnerability flags: "WPS enabled - try PIN attack first"
- Pattern recognition: "SSID suggests home network vs business"
- Client analysis: "This client probes for 'CorpNet' - employee device?"

### Intelligent Cracking
- Analyze target before cracking:
  - Coffee shop? → coffee-related words first
  - Spanish SSID? → Spanish wordlists
  - Business name? → Company + year patterns
- Generate custom wordlists from intel gathered
- Suggest masks: [Company][Year], [Season][Year]!
- Recommend stage based on target type

### Report Writer
- Feed engagement data
- Auto-generate professional pentest report
- Executive summary + technical findings
- Risk ratings with remediation
- Client-ready PDF export

### OSINT Integration
- Cross-reference GPS coords with business data
- Pull business info from location
- Identify network owners
- Track AP movement over time (mobile vs fixed)

### Infrastructure
- **Brain:** Claude API (anthropic) from Sh4d0wFr4m3
- **Fallback:** Local LLM on Glass (LMStudio) when Glass not cracking
- **Frontend:** Custom chat in Arsenal OR OpenWebUI integration
- **Memory:** Local SQLite or JSON for session persistence

### Build Order for AI
1. ✅ Basic chat panel UI (floating + tab) - DONE
2. ✅ Context injection (read current state) - DONE
3. ✅ Phase A: Observer mode - DONE (J4Rv15 can see state, answer, suggest)
4. ✅ Memory system (persist between sessions) - DONE (.operator_memory.json)
5. ⏳ Phase B: Approval mode with action buttons - IN PROGRESS (tools work, UI needs Execute/Cancel)
6. ⏳ Smart analysis features - PARTIAL (context injection works)
7. Phase C: Autonomous rules
8. Report generation
9. OSINT integration

### Operator Status (Dec 30, 2025)
**LIVE AND WORKING:**
- J4Rv15 (Jarvis) persona with sarcastic hacker mentor style
- Streaming chat via SSE
- 148 MCP tools (filesystem, infrastructure, sysadmin, development, wifi_arsenal)
- Passcode authentication (0346) with snarky lockout mode
- Persistent memory (conversations + facts)
- Floating chat panel synced with full Operator page
- Arsenal API tools (scan, glass_status, context, interface_mode, attack, send_to_glass)

**NEEDS WORK:**
- Extended thinking (expandable reasoning dropdown)
- Real-time tool visibility during streaming
- Phase B approval buttons (Execute/Cancel on proposed actions)
- Glass connectivity debugging

---

---

## Business Features

### One-Click Reports
The money feature. Cuts report writing from hours to minutes.
- Click "Generate Report" → professional PDF
- Executive summary (non-technical) + technical findings
- Pre-written templates for common findings:
  - Weak WPA2 password
  - WPS enabled
  - Open networks
  - Default credentials
  - Rogue APs detected
- Risk ratings (Critical/High/Medium/Low)
- Remediation steps for each finding
- Evidence auto-attached (screenshots, captures)
- Client logo/branding options
- Export: PDF, HTML, JSON

### Engagement Manager
Track clients and jobs separately. Professional organization.
- Each engagement = isolated workspace
  - Scope documentation (what's authorized)
  - All captures and results stay in engagement
  - Notes and timeline
- Never mix client A's data with client B's
- Built-in timer tracks hours spent per engagement
- Export hours → invoicing
- Know your actual hourly rate per job
- Rules of engagement templates
- Pre-engagement checklist

### Evidence Locker
CYA for disputes. Prove everything.
- Auto-timestamp everything
- Screenshots captured during assessment
- All .cap and .hc22000 files
- Crack results with timestamps
- Connected clients log
- All actions logged with time
- Hash verification (prove files not tampered)
- Export evidence package for client
- Searchable by engagement/date/type

### Client Portal (Future)
Professional touch. Reduce status emails.
- Give clients a login
- See progress: "Assessment: 3/5 networks tested"
- View findings as they're added
- Real-time status updates
- Download final report when ready
- Recurring clients see history
- White-label option (your branding)

---

## Operational Features

### Live Dashboard
Command center. Glance and know everything.
- System status panel:
  - Interface states (up/down, monitor/managed)
  - Glass connection and GPU stats
  - Flipper status
- Active operations:
  - Current scan (target, duration, networks found)
  - Running attacks (deauth, handshake capture)
  - Glass crack progress
- Recent activity feed:
  - Captures in last hour
  - Passwords cracked
  - Alerts/warnings
- Quick stats:
  - Networks found today
  - Handshakes captured
  - Crack success rate
- Quick launch buttons for common tasks

### Notifications
Walk away, stay informed.
- Push to phone when:
  - Password cracked
  - Handshake captured
  - Scan complete
  - Glass stage complete
  - Error/failure
- Methods:
  - Pushover (phone notifications)
  - Email
  - Telegram bot
  - Desktop notification (always)
- Configurable per event type
- Quiet hours option

### Quick Connect
Seamless pivot to internal assessment.
- Password cracked → one click → connect to network
- Auto-grab on connect:
  - Gateway IP
  - DNS servers
  - DHCP info
  - Subnet/CIDR
- Quick nmap scan options:
  - Fast host discovery
  - Service scan
  - Full port scan
- Save results to engagement
- Perfect for demonstrating impact

### Defensive Monitoring Mode
Flip Arsenal to defense. Recurring revenue service.
- Monitor mode watches for:
  - Deauth attacks against your client's network
  - Rogue APs (evil twin detection)
  - Unauthorized clients connecting
  - PMKID/EAPOL capture attempts
  - Suspicious probe requests
- Alert on detection (push/email)
- Log all events with timestamps
- Generate monthly security report
- Offer as service: "WiFi Security Monitoring - $X/month"
- Passive - doesn't interfere with network

### Auto-Actions
Set rules, Arsenal handles the rest.
- "When handshake captured → send to Glass"
- "When scan complete → export results"
- "When capture sits idle 10 min → start local crack"
- "When Glass finds password → notify + log"
- Configurable triggers and actions
- Enable/disable per rule
- Audit log of all auto-actions

---

## Build Order

**Phase 1: UI Foundation**
1. ✅ Navigation system (multi-page) - 5 tabs working
2. ✅ Cracking page (Glass mirror) - live status, 7 stage buttons, file management
3. ✅ Wardriving page (map + sessions) - auto-load stats, session filtering, Show All
4. ⏳ Network Ops page rebuild - two-column layout done, needs testing
5. Target Intelligence Brief - rich monitoring output (see below)

**Phase 2: Core Pages**
5. Evil Portal page
6. Dashboard (command center)
7. Intel/Analysis page
8. Config page

**Phase 3: Business (Revenue Impact)**
9. One-Click Reports
10. Engagement Manager
11. Evidence Locker
12. Export tools

**Phase 4: Efficiency**
13. Notifications (Pushover/Telegram)
14. Quick Connect (post-crack pivot)
15. Auto-Actions (rules engine)

**Phase 5: Intelligence**
16. Vendor lookup
17. Network relationship detection
18. Device tracking
19. ✅ AI integration (The Operator) - J4Rv15 LIVE with streaming, auth, memory, 148 tools

**Phase 6: Advanced**
20. Defensive Monitoring Mode
21. Client Portal
22. Full AI operator with autonomy

---

## Intel/Analysis Page

### Network Database Browser
- All discovered networks in searchable table
- Sort by any column
- Advanced filters (encryption, vendor, signal, date range)
- Bulk actions (tag, delete, export)

### Device Tracking
- All client MACs seen across all networks
- Device fingerprinting (Apple, Samsung, Intel, etc.)
- "This device connects to these networks"
- Movement patterns (seen at location A then B)
- Probe request history per device

### Network Relationships
- Same vendor/sequential MACs = same organization
- Mesh network detection
- SSID pattern analysis ("Corp-Floor1", "Corp-Floor2" = same company)
- Shared clients between networks

### Vulnerability Flags
- WPS enabled (high priority)
- Open networks
- WEP (rare but instant win)
- Weak signal + clients = easy deauth
- No PMF = PMKID viable
- Default SSID patterns (ISP router, likely default creds)

### Tagging System
- In-scope / out-of-scope
- Tested / not tested
- Cracked / not cracked
- Priority levels
- Custom tags
- Notes per network

### Timeline View
- When was each network first/last seen
- Activity history
- Attack history per network
- Visual timeline

### OSINT Integration (Future)
- Business lookup from GPS
- Wigle.net integration
- Public data correlation

---

## Config Page

### Interface Management
- All detected WiFi interfaces
- Current mode display
- One-click mode switching
- Custom interface naming
- Interface health/diagnostics

### Glass Connection
- IP address / hostname
- Port configuration
- Connection test button
- Auto-reconnect toggle
- Credentials storage (if needed)

### Flipper Settings
- Serial port configuration
- Auto-sync on connect toggle
- Sync folder location
- Delete after sync option

### Wordlist Management
- See all available wordlists
- Sizes and locations
- Add new wordlists
- Organize by category
- Download recommended lists

### Rule Management
- Available hashcat rules
- Enable/disable per stage
- Custom rule creation

### Notification Settings
- Enable/disable notifications
- Pushover API key
- Telegram bot token
- Email SMTP settings
- Which events trigger notifications

### Display Preferences
- Theme (dark default, darker, light?)
- Font size
- Refresh intervals
- Default scan duration
- Default attack timeouts

### Data Management
- Clear captures folder
- Clear database
- Export all data
- Import data
- Backup/restore

### About
- Version info
- System info
- Update check (future)
- Credits / license

---

## Reports Page

### Engagement Selection
- List all engagements
- Create new engagement
- Archive old engagements

### Report Builder
- Select engagement
- Choose findings to include
- Add executive summary
- Add custom notes
- Include/exclude evidence

### Auto-Generated Sections
- Scope and methodology
- Tools used
- Timeline of activities
- Networks discovered
- Vulnerabilities found
- Successful compromises
- Evidence (screenshots, captures)

### Finding Templates
- Weak WPA2 password
- WPS enabled
- Open network
- Rogue AP detected
- Default credentials
- Each with: description, risk rating, remediation

### Risk Ratings
- Critical / High / Medium / Low / Info
- CVSS scoring option
- Custom severity

### Remediation Recommendations
- Pre-written for common findings
- Customizable per finding
- Priority order

### Output Formats
- PDF (professional, client-ready)
- HTML (interactive)
- JSON (data export)
- Markdown

### Branding
- Client logo upload
- Your company logo
- Custom header/footer
- Color scheme per client

---

## Dashboard Page (Command Center)

### System Status Cards
- Interface cards (alfa0, alfa1) - mode, up/down, activity LED
- Glass card - connected, current job, progress bar, GPU temp, ETA
- Flipper card - connected, battery %, last sync time
- Disk space (captures folder size, free space warning)
- Network connectivity (internet, LAN status)

### Active Operations Panel
- Current scan (target, duration, progress)
- Current attack (type, target, status)
- Current crack (file, stage, progress)
- Active portal (SSID, connected clients)
- Cancel/stop button for each

### Live Activity Feed
- Real-time scrolling log of all events
- Color coded: green=success, red=fail, yellow=warning, gray=info
- Clickable entries (jump to relevant page)
- Filter by type (scans, attacks, cracks, all)
- Export log

### Quick Stats
- Networks discovered (today / all time)
- Handshakes captured (today / all time)
- Passwords cracked (today / all time)
- Open networks found
- WPS-enabled networks found
- Success rate percentage

### Alerts Panel
- Glass disconnected
- Crack complete!
- Capture success!
- Attack failed
- Low disk space
- Flipper disconnected
- Dismissable with history

### Quick Launch
- Big action buttons: Scan, Monitor, Attack, Crack
- Recent targets list (one-click resume)
- Favorite networks
- Last used attack type

### Engagement Context (if active)
- Current engagement/client name
- Timer - time elapsed this session
- Scope summary (X networks in scope)
- Progress indicators (3/5 networks captured)
- Quick notes

---

## Evil Portal Page (New Build)

### Template Management
- Visual gallery of all 21 templates with thumbnails
- Live preview in iframe before deploying
- Edit templates (built-in HTML editor)
- Create new templates from scratch
- Import/export templates
- Categorize (coffee shop, hotel, airport, corporate, telecom)
- Clone real login pages (with legal warnings)

### Deployment
- SSID configuration (clone nearby network or custom)
- Interface selector (alfa0/alfa1)
- Channel selection (match legitimate AP)
- Start/Stop with clear status indicator
- Captive portal auto-redirect settings
- Band selection (2.4GHz vs 5GHz)
- Hidden SSID option
- MAC spoofing (clone legitimate AP's MAC)

### Credential Capture
- Live credential viewer (real-time feed)
- Credential log with timestamps
- Export credentials (CSV, JSON)
- Duplicate detection
- Device fingerprint info
- Geo-tag captures (if GPS available)

### Connected Clients
- List of connected victims
- MAC address, vendor, signal strength
- Connection duration
- Pages/requests made
- Kick individual clients
- Block reconnection option

### Deauth Coordination
- Deauth legitimate AP toggle
- Deauth intensity slider (gentle → aggressive)
- Target specific clients only
- Whitelist own devices
- Scheduled deauth waves

### Business/Evidence
- Auto-screenshot portal interactions
- Timestamp all events
- Session recording for report
- Legal disclaimer system ("authorized test only")
- Evidence package export

---

## Wardriving Page Enhancements

### Map Features
- Click network → full details panel (not just popup)
- Draw route taken (GPS trail line)
- Time slider - animate the drive, watch networks appear
- Export KML/KMZ for Google Earth
- Distance traveled stat
- Speed overlay (walking vs driving detection)
- Bearing/direction indicators

### Network Intelligence
- Click network → show capture/crack status
- Open networks highlighted more prominently  
- "High value targets" filter (open, WPS enabled, weak encryption)
- Vendor clustering ("this area is all Spectrum routers")
- Business name lookup from GPS coordinates
- Duplicate detection (same network, multiple locations = mesh?)

### Session Management
- Name sessions ("Downtown walk", "Client ABC survey")
- Notes per session
- Compare sessions - what's new since last time?
- Merge sessions
- Delete session
- Session statistics (duration, distance, networks/hour)

### Flipper Integration
- Battery status display
- Storage space remaining
- Live sync indicator
- Auto-sync when plugged in option
- Sync history log
- Multiple Flipper support (future)

### Business Features
- Coverage map visualization for clients
- Export session as PDF report with embedded map
- Mark networks as in-scope/out-of-scope directly on map
- Client/engagement assignment per session
- Before/after comparison for remediation verification

---

## Cracking Page Enhancements

### Crack History/Results
- Password vault - all cracked passwords, SSID, date, which stage found it
- What wordlist/rule cracked it (learning data)
- Success rate per stage over time
- Export for reports

### Before Cracking
- Hash quality indicator ("Good: 2 handshakes + PMKID" vs "Weak: 1 partial")
- Time estimate before sending
- Target context - show SSID, capture date, signal, not just filename
- Recommended stage based on SSID pattern

### Queue Management
- Priority reorder (drag to change order)
- Multi-hash dashboard (see all queued progress)
- Pause/resume capability
- Cancel and move to next

### Glass Health
- Temperature history graph
- Throttling detection
- Power draw estimate
- Uptime display
- Critical temp alert

### Auto-Actions
- On crack: notify, test password, save to vault, add to report
- On exhausted: notify, suggest next steps
- On Glass disconnect: alert

### Integration
- Network Ops shows password if cracked
- Crack complete → Quick Connect available
- Feed results to The Operator

### Raw Access (Advanced)
- Hashcat output viewer (learning/debugging)
- Potfile browser
- Wordlist manager (see available, sizes, add new)

---

## Network Ops Enhancements

### Network List Improvements
- Sort buttons (by signal strength, channel, encryption type)
- Filter options (only open, only WPA2, only WPA3, only 5GHz, hide weak signals)
- Color coding - green for strong signal, yellow medium, red weak
- WPS indicator icon in list (🔘 = WPS enabled)
- Vendor name next to BSSID (TP-Link, Netgear, Ubiquiti, etc.)
- Search/filter box to find specific SSID
- Client count preview if detectable during scan

### Visual Improvements
- Signal strength bars instead of just dBm numbers
- Channel utilization graph (which channels are crowded)
- Live refresh toggle (auto-rescan every X seconds)
- Network cards instead of plain list rows
- Encryption badge (WPA2/WPA3/WEP/OPEN)

### Workflow Improvements
- Attack history panel - log of what you tried and results
- Capture indicator - checkmark when handshake obtained
- Auto-send to Glass toggle (capture → auto upload)
- "Recommend Attack" button - picks best attack for target
- Progress bar during attacks with countdown timer
- Cancel attack button
- Queue multiple attacks

### Intel Features
- Notes per network - mark as "in scope", "tested", "skip", "interesting"
- Tags/labels system
- Last seen timestamp (stale network detection)
- Network persistence - is this always here or transient?
- First discovered date
- Historical signal strength (getting closer or farther?)

### Business/Evidence Features
- Timestamp log of ALL actions taken
- Screenshot/export current state for reports
- Scope warning system - "Network not marked in-scope"
- Evidence auto-capture on successful attack
- Session recording - everything you did in this engagement

### Quick Actions
- Right-click context menu on networks
- Keyboard shortcuts (S = scan, M = monitor, D = deauth)
- One-click "Full Auto" - scan → best target → best attack → capture → send to Glass
- Favorites - pin frequently tested networks

---

## Target Intelligence Brief

The "Monitor for Clients" feature becomes a full pre-attack briefing:

### Per Client Data:
- MAC address
- Vendor (Apple, Samsung, Intel, Espressif/IoT, etc.)
- Signal strength (dBm + Excellent/Good/Fair/Weak)
- Packets seen (activity level)
- First seen / Last seen timestamps
- Associated or just probing?
- Probed SSIDs (evil twin intel - networks this device wants)

### Per AP Data:
- Encryption details (WPA2-CCMP, WPA3-SAE, etc.)
- WPS enabled? Locked?
- PMF/802.11w status (affects PMKID success)
- Band (2.4GHz vs 5GHz)
- Hidden network?
- Traffic volume (active vs dead)

### Environmental:
- Other APs on same channel (interference)
- Noise level
- Deauth frames detected? (someone else attacking?)

### Smart Analysis:
- Best target recommendation (strongest active client)
- Attack recommendation ("WPS enabled, try Pixie Dust first")
- Success probability estimate
- Warnings ("PMF detected, PMKID may fail")

### Display Format:
```
═══ TARGET BRIEF: hackme ════════════════════════════
Channel: 6 | Signal: -42 dBm (Excellent) | WPA2-CCMP
WPS: Enabled (not locked) | PMF: No
Traffic: 847 packets/30s (Active)

═══ CLIENTS (2) ═════════════════════════════════════
▶ AC:37:43:12:8F:9A | Apple iPhone | -51 dBm (Good)
  Packets: 234 | Last: 2s ago | ACTIVE
  Probing: "HomeNet", "Starbucks WiFi"
  
▶ 7C:9E:BD:44:21:FF | Intel Laptop | -68 dBm (Fair)  
  Packets: 45 | Last: 12s ago | IDLE
  Probing: "CorpNet-5G"

═══ RECOMMENDATION ══════════════════════════════════
✓ WPS Enabled - Try Pixie Dust first (30% success)
✓ 2 active clients - Handshake capture viable
★ Best target: Apple iPhone (strongest signal)
⚠ If WPS fails, deauth iPhone for handshake
```

This feeds directly to The Operator for explanations and execution.

---

## UI Rules

- **Every button must have a title="" tooltip** explaining what it does - no exceptions, all pages

---

## Hardware

- **Sh4d0wFr4m3:** Kali laptop, alfa0 + alfa1, RTX 3050
- **Glass:** Windows/Kali desktop, RX 7900 XT, 3 SSDs
- **Dr1v3r:** Flipper Zero (wardriving only)

---

## Key Files

**Sh4d0wFr4m3:**
- `/home/ov3rr1d3/wifi_arsenal/server.py` - Flask backend
- `/home/ov3rr1d3/wifi_arsenal/web/index.html` - Current UI
- `/home/ov3rr1d3/wifi_arsenal/wardrive_system/` - Wardrive code

**Glass:**
- `/opt/cracking/glass_server.py` - Flask API
- `/opt/cracking/web/index.html` - Glass Cracker UI
- `/opt/cracking/run_stage.sh` - Stage runner
- `/opt/cracking/auto_escalate.sh` - All stages
- `/mnt/sdd1/wordlists/` - Wordlists (SSD)

---

## Status File
`/mnt/user-data/outputs/wifi-arsenal-status.md` - Running session notes
