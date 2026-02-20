# Managed Client Remote Access Agent — Concept Document

**Created:** 2026-02-19 (phone conversation)
**Status:** Idea phase — not scoped, not started
**Related business:** Custom Computer Connection (Ben's computer build/repair service for personal clients)

---

## The Idea

Ben builds, repairs, and installs computers for people he knows through Custom Computer Connection. Some clients have already asked about ongoing support. The idea is a remote access agent that comes pre-installed on machines Ben builds, giving him the ability to monitor system health and remotely fix problems — often before the client even notices.

This would integrate into WiFi Arsenal as a new UI page ("Managed Clients" or similar), giving Ben a dashboard of all deployed agents with one-click remote access.

## What It Would Do

- **Silent monitoring agent** — runs as a Windows service, reports system health (disk, CPU, updates, malware alerts) back to Arsenal
- **Remote access** — screen sharing, command execution, file transfer when Ben needs to fix something
- **Encrypted comms** — agent phones home to Ben's server, only he can connect
- **Arsenal integration** — new UI page showing all deployed agents, system health dashboard, one-click connect

## Authorization Model

Every deployment comes with a written contract/disclosure. Key points discussed:

- Disclosure language along the lines of: "Access to this computer by any user at any time can be monitored. As the owner of this computer, it is up to you to know that."
- Ben also agrees to certain obligations in the contract (TBD — needs proper drafting)
- **Per-account scoping:** if a new user account is created (computer sold, etc.), the agent deactivates for that account
- **Transfer notification:** contract includes requirement to notify Ben if computer is sold/transferred
- **Deactivation:** Ben deactivates the agent if the computer changes hands or the client opts out

## Technical Approach

**Fork RustDesk** (open source, GPL, free) rather than building from scratch.

Why:
- Already handles remote desktop, file transfer, encrypted comms, relay servers
- Security-audited by thousands of developers — critical since a vulnerability = door into every client machine
- Can be rebranded, customized, stripped of unnecessary UI
- Self-hosted relay server (Glass, VPS, or Arsenal itself)
- Free — no per-seat licensing

What to customize:
- Rebrand as Custom Computer Connection / S.P.A.R.K.
- Strip client-side UI to run as silent Windows service
- Add system health telemetry reporting
- Add Arsenal integration hook (API endpoint for agent check-ins)
- Add per-account deactivation logic
- Add auto-update mechanism

## Scoping Checklist (For When This Becomes Active)

- [ ] Research RustDesk fork process and customization options
- [ ] Draft client consent/disclosure agreement language
- [ ] Design Arsenal "Managed Clients" page concept
- [ ] Define agent telemetry — what system health data to collect
- [ ] Define server-side component — where does the relay live (Glass? VPS? Arsenal?)
- [ ] Determine auto-update mechanism for deployed agents
- [ ] Scope per-account deactivation logic
- [ ] Determine Windows-only vs. cross-platform
- [ ] Create GitHub issue when ready to start building

## Target Audience

- **Primary:** Personal clients (home users, people Ben knows)
- **Secondary:** Business clients (offered as optional add-on)

## Business Value

- Proactive support — Ben sees problems before clients do
- Remote fixes without house calls
- Differentiator for a local IT service — "your computer is always monitored by a professional"
- Bundled with every Custom Computer Connection build (if client wants it)
- Recurring service relationship, not one-time fix

## Priority

**Low — future project.** Arsenal Issue #7 (Internal Network page) and v1.6.0 (Field Ready) are current priorities. This is captured here so the idea and decisions don't get lost across sessions.

---

*Documented from phone conversation between Ben and Claude, 2026-02-19*
