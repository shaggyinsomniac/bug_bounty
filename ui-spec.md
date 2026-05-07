# Interactive Cockpit UI Specification

The UI is the operator's workstation for the bug bounty automation system. Single-user,
runs on localhost (or Tailscale-accessible). It is NOT a passive dashboard — it is a
live cockpit where you trigger scans, watch them run, drill into findings, and ship
reports.

## Design Principles

1. **Keyboard-first.** Every common action has a shortcut. Cmd+K opens a global
   command palette. Slash key focuses search. Most lists support j/k navigation
   and arrow keys.

2. **Real-time everywhere.** Scans, findings, logs, queue depth all stream live
   via Server-Sent Events (SSE) or WebSocket. No "refresh to see updates."

3. **Information density.** Tailored for a power user. Compact tables with 100+
   rows visible without scroll. Drawer-based detail views (Cmd+Click opens detail
   without leaving the list).

4. **Dark mode default**, light mode optional. Toggle persists per-browser.

5. **Single-page app feel** with HTMX-driven server rendering — fast first paint,
   server-authoritative state, no JS framework build pipeline. Alpine.js for tiny
   interactivity bits.

6. **Evidence-first.** Every finding shows raw evidence prominently. Operator
   trust depends on being able to verify claims at a glance.

7. **No empty states without action.** Every empty state has a clear "do this
   next" CTA.

---

## Tech Stack (locked)

- **Backend**: FastAPI (Python 3.11+, async)
- **Templates**: Jinja2, server-rendered HTML
- **Interactivity**: HTMX (CDN, single script tag)
- **Live updates**: SSE (Server-Sent Events) — simpler than WebSocket, sufficient
  for one-way streaming. WebSocket only for terminal-style log streaming if needed.
- **Styling**: Tailwind CSS via CDN (Play CDN — fine for single-user dev tool)
- **Charts**: Chart.js via CDN (compact, no build)
- **Tables/grids**: HTMX-paginated tables; if a table needs >1000 rows, virtual
  scroll via Alpine + intersection observer
- **Code/payload viewer**: Highlight.js (CDN) for syntax highlighting; raw text
  area for editing
- **Icons**: Lucide icons via CDN script
- **Forms**: server-validated, HTMX swap on submit, inline error rendering

---

## Information Architecture

```
/                        → Dashboard (overview)
/programs                → Program list
/programs/new            → Add program
/programs/<id>           → Program detail (assets, findings, scans, settings)
/assets                  → Asset inventory (filterable)
/assets/<id>             → Asset detail (timeline, fingerprint, findings)
/findings                → Findings queue
/findings/<id>           → Finding detail (evidence, report draft, workflow)
/scans                   → Scan history + active scans
/scans/<id>              → Scan detail (live progress, logs, results)
/scans/new               → Trigger scan (interactive form)
/secrets                 → Validated secrets vault (separate from findings for
                          quick "what live keys did we find" view)
/intel                   → Intelligence feed (new CVEs, KEV updates, trending exploits)
/reports                 → Generated reports (drafts + submitted)
/reports/<id>            → Report editor + preview
/queue                   → Live job queue (workers, in-flight tasks, throughput)
/logs                    → System log stream (filterable)
/settings                → Webhooks, API keys, scan defaults, tool versions
/health                  → Tool versions, disk usage, queue health, last-runs
```

---

## Global Components

### Top Nav Bar
- Logo / app name (left, click → dashboard)
- Global search box (slash `/` to focus): searches assets, findings, programs, CVEs
- Active scan indicator (badge with count of in-flight scans, click → /scans?status=running)
- Findings indicator (badge with unread P0/P1 count, pulses if new in last 5min)
- Notifications bell (recent Discord-pushed alerts mirrored here)
- Theme toggle
- Settings cog

### Left Sidebar (collapsible)
- Dashboard
- Programs
- Assets
- Findings (with sub-counts: P0 / P1 / P2+)
- Scans (with active count badge)
- Secrets (with live-key count badge — pulse if any are unrevoked)
- Intelligence
- Reports
- Queue
- Logs
- Settings

### Command Palette (Cmd+K / Ctrl+K)
- Modal opens with search input.
- Fuzzy-search across actions: "scan acme.com", "find P0 findings", "open program 
  Shopify", "go to asset api.example.com", "trigger nuclei rescan"
- Recent actions shown when empty.
- Each match shows the keyboard shortcut for the action if it has one.

### Toast Notifications (top-right, 4s auto-dismiss)
- Success (green), info (blue), warning (yellow), error (red)
- Click to expand/dismiss. Keyboard: Esc dismisses all.

### Live Status Strip (bottom of viewport)
- "3 scans running · 47 in queue · 1.2K findings · DB 234MB · last scan 12s ago"
- Updates via SSE every 5s.

---

## Screen-by-Screen Specification

### Dashboard (`/`)

Purpose: at-a-glance current state of all hunting activity.

Layout: 4 rows.

**Row 1 — KPI cards (4 across)**
- Active programs: number + sparkline of programs added over last 30d
- Total assets monitored: number + delta vs 7d ago
- Open findings: number, broken into P0/P1/P2/P3 stacked bar
- Validated secrets (unrevoked): number, in red if > 0

**Row 2 — Recent findings table (full width)**
- Last 10 findings, sortable.
- Columns: severity badge, title, asset, program, age, status, [evidence] button
- Click row → opens finding detail in side drawer (Cmd+Click → new tab)
- Header has filter pills: P0 only / Last 24h / Unverified / Has secret

**Row 3 — Two-column**
- Left: Active scans card. Live list of running scans with progress bars,
  currently-being-probed asset, ETA. Click → scan detail.
- Right: Queue depth chart. Last 1h of queue depth as line chart, color-coded
  by job type (recon / probe / detect / validate).

**Row 4 — Two-column**
- Left: Newly discovered subdomains in last 24h (list, click → asset detail)
- Right: Recent tool failures (list, with retry button per item)

**Empty state**: "Add your first bug bounty program to start hunting." with prominent
CTA button → `/programs/new`.

---

### Programs List (`/programs`)

Purpose: manage which bug bounty programs the system monitors.

Layout: top toolbar + table.

**Toolbar**
- Search box (filter by name)
- "+ Add Program" button → modal
- Filter: source (HackerOne / Bugcrowd / Intigriti / Manual / All)
- Filter: active / paused / archived

**Table columns**
- Name (link → program detail)
- Source (badge with platform logo)
- Assets monitored (count)
- Open findings (count, severity-colored)
- Last scan (relative time)
- Status (active / paused with toggle)
- Actions menu (rescan all, pause, archive, edit)

**Add Program modal**
- Tabs at top: H1 / Bugcrowd / Intigriti / YesWeHack / Manual
- Per-tab inputs:
  - H1: paste program handle (e.g., `shopify`) → fetch scope
  - Bugcrowd: paste program slug → fetch scope
  - Manual: paste YAML or JSON scope, or upload file
- Preview pane shows parsed scope (in_scope domains/IPs/wildcards).
- "Test parse" button validates the scope.
- "Add and start initial recon" checkbox (default on).
- Submit → creates program + queues initial recon scan.

---

### Program Detail (`/programs/<id>`)

Tabbed view.

**Tab: Overview**
- Program metadata (name, platform link, scope summary, payouts, contact)
- Assets count + sparkline (assets discovered over time)
- Findings histogram (severity over time)
- "Trigger full rescan" button (with confirmation)
- "Pause monitoring" toggle

**Tab: Scope**
- Editable list of in-scope and out-of-scope rules.
- For platform-sourced scopes: "Re-fetch from platform" button.
- Manual additions clearly distinguished from platform-fetched.

**Tab: Assets**
- Filtered asset table for this program.

**Tab: Findings**
- Filtered findings table for this program.

**Tab: Scans**
- Scan history for this program.

**Tab: Settings**
- Per-program scan schedule (recon every X hours, detection every Y hours)
- Notification overrides (e.g., "Discord-ping me even on P3 for this program")
- Excluded detection modules (e.g., "skip cloud detection for this program")

---

### Assets List (`/assets`)

Purpose: full inventory across all programs, filterable.

**Toolbar**
- Search (full-text on hostname, IP, title, technology)
- Filter pills: New (24h), Has findings, Live, Down, By program (dropdown), 
  By technology (dropdown — autocompleted from observed tech)
- "Export CSV" button
- Bulk action menu (visible when rows selected): rescan, tag, mark out-of-scope

**Table** (virtual scroll for 10K+ rows)
- Checkbox (multiselect)
- Hostname (link → asset detail)
- IP
- Status code (color-coded badge)
- Title (truncated)
- Tech stack (small pills, max 3 visible + "more")
- Open findings count (severity-colored)
- Last seen (relative time)
- Program (link)
- Actions menu

**Right-click context menu**: rescan, view in browser, copy URL, copy curl, mark
as not-interesting, view findings.

---

### Asset Detail (`/assets/<id>`)

Layout: left rail (metadata) + right pane (tabs).

**Left rail (sticky)**
- Hostname
- Resolved IPs (with ASN, country)
- Status, last seen
- Tech stack (full list, with version where known)
- Tags (editable)
- "Open in browser" button
- "Rescan now" button (dropdown: full / detection-only / fingerprint-only)
- Program (link)
- Discovery source (CT log / DNS / wordlist / etc.)
- First seen / last seen timestamps
- Notes (markdown textarea, autosave)

**Right pane tabs**
- **Findings**: list of all findings on this asset.
- **Timeline**: chronological event log (first seen, status changes, tech changes,
  findings appearing, scans run).
- **Fingerprint**: full enriched fingerprint dump (headers, cookies, favicon hash,
  JS bundles detected, paths discovered).
- **Evidence**: screenshots, response captures, cached HTML.
- **Probes**: paths probed historically with status codes (lets you see what's
  been checked vs what hasn't).
- **Related**: assets sharing the same IP / certificate / tech profile.

---

### Findings Queue (`/findings`)

Purpose: triage workspace. The most-used screen.

**Toolbar**
- Search
- Filter pills: severity (P0/P1/P2/P3), status (new/triaging/verified/reported/closed),
  category (exposed_files/admin_panels/secrets/etc.), program, has_secret, age, 
  validated_only
- View toggle: Table / Kanban / Detailed list
- "Bulk triage" mode toggle

**Table view** (default)
- Severity badge, title, asset, category, status, age, validated indicator,
  assigned (yourself, basically), action menu

**Kanban view**
- Columns: New → Triaging → Verified → Reported → Closed
- Drag cards between columns (HTMX submits status change)
- Card shows: severity, title, asset, age

**Detailed list view** (denser per-row info)
- Two-line per finding: title + asset on top, evidence-snippet on second line
- Evidence-snippet shows the smoking gun (the sensitive line from .env, the 
  exposed admin URL, etc.)

**Bulk triage mode**
- Select multiple findings via checkboxes
- Bulk actions: change status, assign tag, suppress, generate combined report,
  send to Discord summary

---

### Finding Detail (`/findings/<id>`)

The single most important screen. Designed for "see → understand → submit" in
under 5 minutes.

Layout: 3 columns (or 2 + drawer on smaller screens).

**Left column — metadata**
- Severity (with priority score breakdown explanation)
- Status (with workflow buttons: mark verified / mark FP / mark dupe / suppress / 
  send to report)
- Asset (link)
- Program (link)
- Detection module that fired
- CVE references (if applicable)
- First detected / last verified
- Tags (editable)

**Center column — evidence**
- Evidence summary block (the smoking gun — e.g., parsed .env contents with
  secrets redacted by default, click-to-reveal)
- Tabs:
  - **Request**: full HTTP request that produced the finding, syntax-highlighted,
    "Copy as curl" button, "Replay" button (re-runs the request and shows live
    response — useful for confirming the finding still exists)
  - **Response**: full response, syntax-highlighted, headers separated from body
  - **Screenshot**: rendered screenshot if browser-captured
  - **Validations**: for findings with secrets — the validation requests and 
    responses, per secret, with PASS/FAIL badges
  - **Raw**: full evidence package as JSON (for export)

**Right column — actions & report**
- "Generate report" button — opens report drawer (see below)
- Status workflow buttons (large, clear)
- Comments (markdown, your private notes)
- Activity log (who changed what when — even single-user, useful for memory)
- Related findings (same asset, same detection elsewhere)

**Report drawer (slides in from right)**
- Template selector: HackerOne / Bugcrowd / Intigriti / Generic markdown
- Live preview of generated report on the right
- Editable fields on the left:
  - Title (auto-generated, editable)
  - Severity (pre-filled)
  - Affected asset (pre-filled)
  - Reproduction steps (auto-generated from request, editable markdown)
  - Impact (template-driven, editable)
  - Suggested remediation (template-driven, editable)
  - Evidence section (auto-includes screenshots and request/response, optionally
    redacted)
  - References (CVE links, OWASP, vendor advisories — auto-populated)
- "Copy markdown" button (to paste into platform)
- "Open in HackerOne" button (deep-links to H1 new-report page if H1 program)
- "Save as draft" button → finding gets `report_drafted` flag
- "Mark as submitted" button → finding moves to REPORTED status, prompt for 
  H1/Bugcrowd report ID for tracking

---

### Scans Page (`/scans`)

Purpose: see what's running and what's been run.

**Top — Active scans (live updates)**
- Card per active scan with: program, scan type, started, progress bar with %,
  current task description, ETA, "Halt" button (with confirmation)

**Middle — Scan history table**
- Columns: program, type, started, duration, assets probed, findings produced,
  status (success/partial/failed), actions

**"+ New scan" button → /scans/new**

---

### New Scan (`/scans/new`)

Interactive form for triggering a scan.

- **Target selection**: dropdown of programs, or "Custom target" (paste 
  domain/IP/URL — bypasses program scope, since you removed scope enforcement)
- **Scan type radio**:
  - Full pipeline (recon → probe → fingerprint → detect → validate)
  - Recon only (subdomain discovery)
  - Probe only (HTTP probing of known assets)
  - Detection only (run detection modules against known assets)
  - Single detection module (dropdown to pick one)
  - Single asset deep-scan (paste URL, run all applicable detections)
- **Detection module selection** (multiselect, default = all enabled)
- **Intensity slider**: gentle (10 req/s, no aggressive checks) / normal 
  (50 req/s, standard) / aggressive (200 req/s, all checks including network)
- **Tool overrides** (advanced): custom Nuclei flags, custom subfinder sources
- **Notification preference**: silent / Discord on findings / Discord on completion
- "Start scan" button.

After submission: redirect to /scans/<id> for live view.

---

### Scan Detail (`/scans/<id>`)

Live cockpit view of one scan.

**Top — Status header**
- Progress bar (overall %)
- Started, ETA, current phase
- "Halt" button if running

**Middle — Phase progress (visual pipeline)**
- Visual flow: Recon → Probe → Fingerprint → Detect → Validate → Report
- Each stage shows: % complete, items processed/total, errors
- Click a stage → filter logs to that stage

**Bottom — Live log stream (scrollable, autoscroll toggle)**
- Per-line: timestamp, level (debug/info/warn/error), source module, message
- Color-coded by level
- Filter: level, module, search box
- "Pause stream" button (so logs don't scroll past while you read)
- "Download log" button

**Right side panel — findings as they appear**
- Each new finding from this scan pops in at the top with a subtle animation
- Click → finding detail drawer

---

### Secrets Vault (`/secrets`)

Purpose: dedicated view of validated live credentials. Separate because they are
the highest-value findings and need fast eyeballing.

**Filter pills**: provider (AWS/GCP/Stripe/etc.), status (live/revoked/unknown),
program, age

**Table columns**
- Provider badge (with logo)
- Account info (e.g., AWS account ID, Stripe account name, GitHub username — proves
  it's real)
- Token preview (first 8 chars + last 4, rest masked)
- Found at (asset + path)
- Validated at (timestamp + result)
- Status (LIVE pulsing red, REVOKED green, UNKNOWN gray)
- "Revalidate" button (re-checks if still live)
- Actions menu: view full evidence, generate report, mark revoked, delete

**Bulk action**: revalidate all (rate-limited, scheduled).

---

### Intelligence Feed (`/intel`)

Purpose: stay current on new CVEs and exploits relevant to your monitored assets.

**Top — Trending now**
- New KEV additions in last 7d
- New high-EPSS CVEs in last 7d
- New Nuclei templates published in last 7d

**Per-CVE card**
- CVE ID + summary
- Affected products
- KEV status, EPSS score
- "Affected assets in your inventory" — count + click to drill in
- "Trigger targeted scan" button — runs the relevant detection against affected
  assets immediately

---

### Reports (`/reports`)

Purpose: track what's been drafted, submitted, and resolved.

**Toolbar**
- Filter: status (draft / submitted / accepted / duplicate / closed / not-applicable)
- Filter: program

**Table columns**
- Title, finding link, program, severity, status, submitted date, payout (manual 
  entry field), actions

**Click row → /reports/<id>** (report editor)

---

### Queue (`/queue`)

Purpose: see the live job queue. Useful when something feels stuck.

- Worker status: list of worker processes with PID, current task, uptime, 
  tasks completed
- Pending jobs by type (recon / probe / detect / validate / report) — count per
  type as live bars
- Recent failures with retry button per failed job
- Throughput chart (jobs/min over last 1h)
- "Pause queue" / "Resume queue" buttons (for when you want to stop everything)

---

### Logs (`/logs`)

Purpose: system-wide log stream when debugging.

- Live log stream (SSE)
- Filters: level, module, time range, search
- "Pause stream" toggle
- "Download last 1000 lines" button

---

### Settings (`/settings`)

Tabbed.

**Tab: General**
- Data directory path
- Log level
- Theme default
- Log retention (days)

**Tab: Tools**
- Subfinder, httpx, nuclei, naabu — installed version, latest available, 
  "Update" button per tool
- Nuclei templates last updated, "Update templates" button
- Wordlists status, "Update wordlists" (pulls SecLists)

**Tab: Notifications**
- Discord webhook URL (per-channel: findings, secrets, scan-failures)
- Notification rules: severity threshold for Discord, quiet hours
- Test notification button per channel

**Tab: API Keys** (for outbound integrations)
- Optional: HackerOne API token (for fetching scope, deep-linking)
- Optional: Bugcrowd API token
- Stored encrypted

**Tab: Validators**
- Per-provider toggle (enable/disable validation for AWS/Stripe/etc.)
- Per-provider rate limit
- Per-provider "use cached result for X days" setting

**Tab: Scan Defaults**
- Default intensity, default schedule, default detection modules
- Per-program overrides accessible from program settings

**Tab: Backup**
- "Download DB snapshot" button
- "Download evidence archive" button
- Restore from backup

---

### Health (`/health`)

Purpose: system self-check.

- Tool versions table (with red flag if outdated)
- Disk usage (data dir, evidence storage, logs) with bars
- Database stats (size, table row counts)
- Queue health (depth, age of oldest job)
- Last successful scan per program
- External dependency reachability (Discord webhook test, optional H1 API test)
- "Run system diagnostics" button → runs a self-test, reports issues

---

## Real-Time Update Mechanism

**SSE endpoint**: `/events/stream` — single connection, multiplexed event types.

Event types:
- `scan.started`, `scan.progress`, `scan.completed`, `scan.failed`
- `finding.created`, `finding.updated`, `finding.status_changed`
- `secret.validated` (with severity badge for highlight)
- `asset.discovered`, `asset.changed`
- `queue.depth_changed`, `queue.worker_status_changed`
- `log.line` (filtered to current view if /logs is open)

Client-side: HTMX SSE extension subscribes; each event has a `target` selector
and `swap` strategy. Updates are surgical — only the affected DOM nodes re-render.

Reconnect logic: exponential backoff if connection drops, status indicator in 
the bottom strip turns yellow (reconnecting) or red (offline).

---

## Keyboard Shortcuts (Cheat Sheet — accessible via `?`)

Global:
- `Cmd/Ctrl+K` — command palette
- `/` — focus search
- `g d` — go dashboard
- `g p` — go programs
- `g a` — go assets
- `g f` — go findings
- `g s` — go scans
- `g k` — go secrets
- `g i` — go intel
- `g r` — go reports
- `g q` — go queue
- `g l` — go logs
- `?` — show shortcuts

In lists:
- `j` / `k` — next / previous row
- `Enter` — open detail
- `Cmd/Ctrl+Enter` — open detail in new tab
- `x` — toggle row selection (when in bulk mode)
- `e` — edit (where applicable)

In finding detail:
- `v` — mark verified
- `f` — mark false positive
- `s` — mark suppressed
- `r` — open report drawer
- `c` — focus comment
- `]` / `[` — next / previous finding

---

## Color & Visual Language

- Severity badges:
  - P0: red-600 background, white text, pulsing border on unread
  - P1: orange-500
  - P2: yellow-500
  - P3: blue-500
  - P4: gray-500
- Status badges:
  - NEW: blue
  - TRIAGING: yellow
  - VERIFIED: green
  - REPORTED: indigo
  - CLOSED: gray
  - FALSE_POSITIVE: gray-strikethrough
  - DUPLICATE: gray
  - SUPPRESSED: gray with eye-off icon
- Live elements (active scans, in-flight validations) have a subtle pulsing 
  animation on the left border.
- Empty states use illustration-style icons + actionable CTA.
- Loading states: skeleton screens, not spinners (except for actions <500ms).

---

## Performance Budgets

- Dashboard initial paint: <1s
- Asset list with 10K assets: <1s, smooth virtual scroll
- Finding detail open: <300ms
- SSE events render: <100ms from event to DOM update
- Bulk action on 100 findings: <2s

---

## Accessibility

- Keyboard navigable everywhere
- Visible focus rings (don't disable Tailwind's defaults)
- Screen reader labels on icon-only buttons
- Color is never the only signal (severity has icon + label, not just color)
- Contrast meets WCAG AA in both themes

---

## What the UI Does NOT Have (deliberate)

- No multi-user features (no SSO, RBAC, audit log of "who did what" — single user)
- No tenant switcher
- No billing/subscription pages
- No marketing pages — straight to the tool
- No onboarding wizard beyond "add your first program"
- No "compliance reports" templates
