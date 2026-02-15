# Issue #7 Step 1 Part B — Review Notes

## Status
- Structural 5-panel layout: DONE (CSS + HTML + JS in web/index.html)
- DOM integrity: VERIFIED (all 33 IDs, 23 handlers, polling intact)
- Design polish: PENDING (see below)
- Bug fixes: PENDING (see below)

## Bugs to Fix (from js-reviewer)

### Bug 1: autoAttack toggle-off race (MEDIUM)
`autoAttack()` iterates ALL `.host-item` elements and calls `selectHost()` for matches.
If same IP appears twice (vulnerability + host), second call triggers toggle-off → deselected.
**Fix:** Break after first match in autoAttack's forEach.

### Bug 2: Polling blows away selection highlight (LOW-MEDIUM)
`refreshDiscoveryResults()` replaces innerHTML of `#discoveryResults` every 3 seconds.
This destroys `.selected` class on the highlighted host item. The `selectedHost` variable
and target info bar survive, but the visual highlight disappears.
**Fix:** After setting innerHTML, re-apply `.selected` to element matching `selectedHost.ip`.

### Bug 3: Host count badge includes cleartext creds (LOW)
Cleartext credential items use `.host-item` class. `updateHostCount()` counts ALL `.host-item`.
**Fix:** Add `data-host` attribute check or use `.host-item[data-host]` selector.

## Design Improvements (from designer, priority order)

### 1. Panel border/depth treatment
- `.internal-left`: border-right `#1a3a1a`, background `#060806`, subtle inset shadow
- `.internal-center`: border-right `#1a3a1a`, background `#040404`
- `.internal-bottom`: border-top 2px `#003300`, background `#030303`

### 2. Attack section differentiation
- Credential Access: green top border `#004400`
- Exploitation: red top border `#660000`, faint red background `#080505`
- Listener: grey top border `#333`
- Use `.attack-section-cred`, `.attack-section-exploit`, `.attack-section-listener` classes

### 3. Host item scannability
- Padding 10px (was 8px), border `#111` (was `#1a1a1a`)
- Hover: background `#0a1a0a`, hint of border color
- Selected: box-shadow inset green glow
- Critical: faint red background `#0a0505`
- IP: 13px (was 12px), letter-spacing 0.5px
- Ports: warmer yellow `#ffcc00`, faint yellow background

### 4. Target info bar glow
- Border-left 3px solid `#00ff00`
- IP: 18px (was 16px), text-shadow green glow
- Border color `#004400` (was `#003300`)

### 5. Scrollbar styling
- 6px width, dark track, green thumb, hover highlight

### 6. Top bar status pills
- Background `#0a0a0a`, padding, border-radius, border `#1a1a1a`

### 7. Top bar gradient
- Background gradient `#0c0c0c → #080808`
- Bottom border 2px

### 8. Right panel header gradients
- Gradient `#0c0c0c → #080808`
- Creds/evidence divider 2px `#333300`

### 9. Badge refinement
- Sharper corners (2px), letter-spacing, uppercase
- Info badge: transparent green bg with border

### 10. Placeholder refinement
- Larger icon (64px), more ghostly opacity (0.3)
- Uppercase text with letter-spacing
