# WiFi Arsenal - Full Platform Audit & Improvement Plan

**Audit Date:** 2026-01-03  
**Status:** COMPLETE  
**Total Features Identified:** 81

---

## CRITICAL ISSUES (Fix First)

| # | Issue | Page | Status |
|---|-------|------|--------|
| 1 | Duplicate IDs `alfa0Status`/`alfa1Status` | Network Ops | ⬜ BUG |
| 2 | Deauth Companion - UI exists, NEVER BUILT | Evil Portal | ⬜ UNBUILT |
| 3 | Clone SSID from Scan - unknown if works | Evil Portal | ⬜ UNVERIFIED |

---

# NETWORK OPS PAGE

## 🔴 Must Have (6)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 1 | Fix duplicate IDs | Bug - breaks JavaScript | 5 min | ⬜ |
| 2 | Stop/Cancel attack button | Can't abort running attack | 30 min | ⬜ |
| 3 | Filter by encryption | Quick find WPA2 vs WPA3 vs Open | 30 min | ⬜ |
| 4 | Search/filter by SSID | Find specific target in long list | 20 min | ⬜ |
| 5 | Signal strength bars | Visual beats reading "-67 dBm" | 20 min | ⬜ |
| 6 | Sort network list | By signal, name, channel, encryption | 30 min | ⬜ |

## 🟡 Nice to Have (6)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 7 | "Crackability" indicator | WPA3/PMF = 🔴, WPA2 = 🟢, Open = ⚪ | 30 min | ⬜ |
| 8 | Export network list (CSV) | Documentation, client reports | 20 min | ⬜ |
| 9 | Mark as tested / status | Track progress during engagement | 45 min | ⬜ |
| 10 | View captures for target | See all .hc22000/.pcap for a network | 30 min | ⬜ |
| 11 | Probe request monitor | See what devices are looking for | 1 hr | ⬜ |
| 12 | Consolidate attack outputs | Two output areas is confusing | 20 min | ⬜ |

## 🟢 Future (6)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 13 | Queue multiple targets | Batch attack mode | 2 hr | ⬜ |
| 14 | Attack success stats | Learn what methods work best | 1 hr | ⬜ |
| 15 | Client history tracking | "Seen this device before?" | 1 hr | ⬜ |
| 16 | IoT/Camera detection | Flag high-value targets by vendor | 30 min | ⬜ |
| 17 | Export intel to PDF | Client deliverables | 2 hr | ⬜ |
| 18 | Filter by signal strength | Focus on attackable range | 20 min | ⬜ |

---

# EVIL PORTAL PAGE

## What Currently Works
- ✅ Portal start/stop through Arsenal UI
- ✅ Template selection + preview (23 templates)
- ✅ Credential capture (GET and POST)
- ✅ Credential panel with archive system
- ✅ Auto-archive on portal start
- ✅ UFW firewall rules
- ✅ Kick All Clients

## 🔴 Must Have (5)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 1 | **Build Deauth Companion** | UI exists, never built - forces victims to your AP | 1-2 hr | ⬜ |
| 2 | **Verify/fix Clone SSID** | Button exists, unknown if works | 30 min | ⬜ |
| 3 | Interface selector | Choose alfa0 or alfa1 for portal | 20 min | ⬜ |
| 4 | Post-capture redirect URL | Redirect to awareness page | 30 min | ⬜ |
| 5 | Connected clients list | See who's on your portal | 45 min | ⬜ |

## 🟡 Nice to Have (7)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 6 | More channel options | All 14 2.4GHz + more 5GHz | 15 min | ⬜ |
| 7 | Passthrough mode toggle | Internet after capture + monitor | 2 hr | ⬜ |
| 8 | Upload custom template | User's own portal designs | 1 hr | ⬜ |
| 9 | Categorize templates | Groups: corporate, hotel, carrier | 30 min | ⬜ |
| 10 | Preview in new tab button | Larger template view | 10 min | ⬜ |
| 11 | Victim MAC/device info | Show device type connected | 30 min | ⬜ |
| 12 | Portal uptime display | How long portal running | 15 min | ⬜ |

## 🟢 Future (4)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 13 | Bandwidth/traffic stats | Monitor activity | 1 hr | ⬜ |
| 14 | Session report export | Creds + timeline for clients | 2 hr | ⬜ |
| 15 | Template editor in UI | Modify templates in browser | 3 hr | ⬜ |
| 16 | Auto-suggest SSID | Based on scan results | 30 min | ⬜ |

---

# CRACKING PAGE

## What Currently Works
- ✅ Glass SSH connection + status
- ✅ 5-stage cracking system
- ✅ Auto-escalate through stages
- ✅ Local cracking on Sh4d0wFr4m3
- ✅ Send captures to Glass
- ✅ Queue management (pause/resume)
- ✅ GPU stats (%, temp, VRAM)
- ✅ Live progress bar
- ✅ Cracked password display

## 🔴 Must Have (5)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 1 | Copy password button | One-click copy when cracked | 10 min | ⬜ |
| 2 | Cracked password history | View ALL cracked passwords (potfile) | 45 min | ⬜ |
| 3 | Link password to target | Show which network password belongs to | 30 min | ⬜ |
| 4 | Multiple file selection | Queue multiple .hc22000 at once | 30 min | ⬜ |
| 5 | Clear queue button | Remove all waiting items | 15 min | ⬜ |

## 🟡 Nice to Have (7)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 6 | Estimated time per stage | Show expected duration before running | 20 min | ⬜ |
| 7 | Filter captures (cracked/uncracked) | Focus on what needs work | 30 min | ⬜ |
| 8 | File info on hover | Tooltip: network name, capture date | 20 min | ⬜ |
| 9 | Re-order queue | Move items up/down priority | 45 min | ⬜ |
| 10 | Desktop notification on crack | Don't have to watch screen | 30 min | ⬜ |
| 11 | Success rate stats | Which stages crack passwords | 1 hr | ⬜ |
| 12 | Benchmark button | Test GPU speed | 30 min | ⬜ |

## 🟢 Future (4)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 13 | Custom wordlist upload | Your own wordlists | 1 hr | ⬜ |
| 14 | Rule selector | Choose different rule sets | 45 min | ⬜ |
| 15 | Email/webhook on crack | Remote notification | 1 hr | ⬜ |
| 16 | Mask attack builder | Custom brute force patterns | 2 hr | ⬜ |

---

# WARDRIVING PAGE

## What Currently Works
- ✅ Embedded map
- ✅ Flipper Zero sync
- ✅ Database stats (Total/Open/Secured/Sessions)
- ✅ Session filtering
- ✅ Fullscreen map view

## 🔴 Must Have (5)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 1 | Export to KML/CSV | Use data in Google Earth/spreadsheets | 45 min | ⬜ |
| 2 | Delete session | Remove unwanted sessions | 30 min | ⬜ |
| 3 | Merge sessions | Combine multiple wardrive runs | 1 hr | ⬜ |
| 4 | Live wardrive mode | Real-time updates while driving | 2 hr | ⬜ |
| 5 | Network details on map click | Popup with SSID, encryption, first seen | 1 hr | ⬜ |

## 🟡 Nice to Have (7)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 6 | Search networks | Find specific SSID | 30 min | ⬜ |
| 7 | Filter by encryption type | Show only Open, WPA2, WPA3 | 30 min | ⬜ |
| 8 | Heatmap mode | Density visualization | 2 hr | ⬜ |
| 9 | Coverage area polygon | See where you've been | 1 hr | ⬜ |
| 10 | Distance traveled stat | Per session metrics | 30 min | ⬜ |
| 11 | "Mark for attack" | Flag networks to import to Network Ops | 45 min | ⬜ |
| 12 | Session rename | Custom names instead of dates | 20 min | ⬜ |

## 🟢 Future (5)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 13 | WiGLE integration | Upload to WiGLE.net | 2 hr | ⬜ |
| 14 | Import from WiGLE | Download area data | 2 hr | ⬜ |
| 15 | Route replay | Animate the wardrive path | 3 hr | ⬜ |
| 16 | Overlap detection | "Captured this network before" | 1 hr | ⬜ |
| 17 | Compare sessions | Side-by-side changes | 2 hr | ⬜ |

---

# DASHBOARD PAGE

## What Currently Works
- ✅ Interface status display
- ✅ Flipper status
- ✅ Quick launch buttons
- ✅ Basic stats (captures, wardrive, cracked)

## 🔴 Must Have (5)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 1 | Auto-refresh stats | Dashboard should be live | 20 min | ⬜ |
| 2 | Portal status indicator | Is Evil Portal running? | 15 min | ⬜ |
| 3 | Current attack indicator | What's happening right now? | 30 min | ⬜ |
| 4 | Recent activity feed | Timeline across all pages | 1 hr | ⬜ |
| 5 | Clickable recent captures | Click to go crack it | 20 min | ⬜ |

## 🟡 Nice to Have (6)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 6 | Glass GPU temp on dashboard | Monitor without page switch | 15 min | ⬜ |
| 7 | Uptime display | How long Arsenal running | 10 min | ⬜ |
| 8 | Last scan results summary | Networks found last scan | 20 min | ⬜ |
| 9 | Credential count (portal) | How many creds captured | 15 min | ⬜ |
| 10 | Session summary | Today's activity overview | 45 min | ⬜ |
| 11 | System health alerts | Low disk, high temp warnings | 30 min | ⬜ |

## 🟢 Future (3)

| # | Feature | Why | Effort | Status |
|---|---------|-----|--------|--------|
| 12 | Customizable widgets | Drag/drop layout | 4 hr | ⬜ |
| 13 | Dark/light theme toggle | User preference | 1 hr | ⬜ |
| 14 | Export daily report | PDF summary | 2 hr | ⬜ |

---

# SUMMARY

## By Priority

| Priority | Count | Est. Total Time |
|----------|-------|-----------------|
| 🔴 Must Have | 26 | ~15 hours |
| 🟡 Nice to Have | 33 | ~20 hours |
| 🟢 Future | 22 | ~30 hours |
| **TOTAL** | **81** | **~65 hours** |

## By Page

| Page | Must | Nice | Future | Total |
|------|------|------|--------|-------|
| Network Ops | 6 | 6 | 6 | 18 |
| Evil Portal | 5 | 7 | 4 | 16 |
| Cracking | 5 | 7 | 4 | 16 |
| Wardriving | 5 | 7 | 5 | 17 |
| Dashboard | 5 | 6 | 3 | 14 |

## Quick Wins (30 min or less)

| Page | Feature | Time |
|------|---------|------|
| Network Ops | Fix duplicate IDs | 5 min |
| Network Ops | Signal strength bars | 20 min |
| Network Ops | Search by SSID | 20 min |
| Network Ops | Export CSV | 20 min |
| Evil Portal | More channels | 15 min |
| Evil Portal | Preview in new tab | 10 min |
| Evil Portal | Uptime display | 15 min |
| Cracking | Copy password button | 10 min |
| Cracking | Clear queue button | 15 min |
| Cracking | File info on hover | 20 min |
| Wardriving | Session rename | 20 min |
| Dashboard | Auto-refresh stats | 20 min |
| Dashboard | Portal status | 15 min |
| Dashboard | Uptime display | 10 min |

---

*Update this file as features are implemented. Mark ✅ when done.*

---

# FUTURE: MITM LAYER (Post Evil Twin)

## The Full Attack Chain
1. Crack password (Glass)
2. Evil Twin WPA2 (clone network with known password)
3. Victim connects (auto-connects, everything matches)
4. MITM - YOU are their router, traffic flows through you

## What MITM Captures & Difficulty

| Data Type | Capture Method | Difficulty | Tool |
|-----------|---------------|------------|------|
| DNS queries | dnsmasq logs | **Easy** | Already have |
| HTTP traffic | tcpdump/mitmproxy | **Easy** | tcpdump (Kali) |
| HTTP credentials | mitmproxy/bettercap | **Easy** | bettercap |
| HTTPS domains (SNI) | TLS handshake parse | **Medium** | tshark/bettercap |
| HTTPS content | sslstrip/HSTS bypass | **Hard** | Limited use now |
| Cookies | mitmproxy | **Medium** | mitmproxy |

## Practical Value for Consulting

**Easy wins (still valuable):**
- DNS queries - see EVERY site they visit, even HTTPS
- HTTP creds - old sites, internal apps, IoT still use HTTP
- HTTP cookies - session hijacking on non-secure sites
- Captive portal creds - people reuse passwords

**Limited now:**
- HTTPS content - HSTS, cert pinning, browser warnings
- Banking/email - always HTTPS + pinning + 2FA
- Modern apps - certificate pinning breaks MITM

## Recommended Tool: Bettercap

All-in-one MITM suite - DNS spoofing, credential sniffing, HTTP proxy. Already on Kali.

## Implementation Notes (For Later)

1. DNS logging - add to dnsmasq config, parse logs
2. Bettercap integration - run alongside Evil Twin
3. Traffic capture dashboard - show live activity
4. Credential extraction - parse HTTP POST params
5. Export for reports - evidence collection

*Do NOT build until Evil Twin foundation is solid.*

---

# HARDWARE TRUTH (Discovered Jan 2026)

## Interface Assignments - REAL WORLD TESTED

| Interface | Card | Chipset | Driver | GOOD AT | BAD AT |
|-----------|------|---------|--------|---------|--------|
| alfa0 | AWUS036ACH | Realtek RTL8812AU | rtl88XXau | **AP mode** (broadcasts visible) | - |
| alfa1 | AWUS036ACM | MediaTek MT7612U | mt76x2u | Monitor mode, deauth | **AP mode** (invisible!) |

## Script Assignments

```
start_portal.sh / stop_portal.sh:
  INTERFACE="alfa0"        # Evil Twin AP (Realtek - phone can see it)
  DEAUTH_INTERFACE="alfa1" # Deauth attacks (MediaTek - monitor works)
```

## Why This Matters

Original udev rules had it backwards. Real-world testing proved:
- MediaTek hostapd says "AP-ENABLED" but phone can't see the network
- Realtek broadcasts properly, phone connects immediately

## Evil Twin WPA2 Attack - CONFIRMED WORKING

Full chain tested and verified:
1. Victim on real WPA2 network
2. Know/crack the password
3. Evil Twin with same SSID + password + channel
4. Deauth kicks victim off real AP
5. Victim auto-reconnects to Evil Twin (password matches)
6. Captive portal captures credentials
7. **MITM position achieved**

