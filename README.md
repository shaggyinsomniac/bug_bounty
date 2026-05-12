# bounty — Personal Bug Bounty Automation System

A personal, single-operator tool for automating reconnaissance and triage in ethical bug bounty research. It connects to HackerOne, Bugcrowd, and Intigriti to pull scope, enumerates subdomains, resolves DNS, HTTP-probes live hosts, fingerprints technologies, scans for exposed files and admin panels, validates leaked tokens, and serves a real-time web UI — all stored locally in a SQLite database with full provenance.

> **Authorisation disclaimer**: This tool is intended **only for targets you have explicit, written permission to test**. Running it against systems you do not own or are not authorised to test may violate the CFAA (US), Computer Misuse Act (UK), and equivalents worldwide. The author accepts no liability for misuse.

---

## Quick Start

```bash
# 1. Clone and install
git clone <repo-url> && cd bug_bounty
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Initialise the database
bounty init-db

# 3. Launch the web UI
bounty serve
# Open http://127.0.0.1:8000

# 4. Quick recon sweep (against a target you are authorised to test)
bounty smoke-recon --target hackerone.com --intensity gentle
```

---

## Feature Overview

### Recon
Passive subdomain enumeration via **subfinder**, DNS resolution via **dnspython**, optional port scanning via **naabu**. Discovered hosts are persisted to `assets` with first/last seen timestamps.

### HTTP Probing
Concurrent async HTTP probing with redirect-chain tracking, TLS extraction, CDN/WAF detection, soft-404 guard, and response body capture up to 5 MB.

### Fingerprinting (5 parsers, 4 confidence tiers)
Parsers: **headers**, **cookies**, **body**, **TLS**, **favicon hash**. Signals are confidence-tiered (`definitive > strong > weak > hint`), deduplicated, and written to `fingerprints`. Tech DB: 170+ patterns.

### Detection Engine (73 checks, 5 categories)
Fingerprint-gated — checks only fire when the prerequisite technology is confirmed.

| Category | Checks |
|---|---|
| Exposed Source Control | 7 |
| Exposed Env and Config | 10 |
| Exposed Backups and Archives | 4 |
| Exposed Files (misc) | 26 |
| Admin Panels | 26 |

Confirmed findings call `capture_http_evidence()` and are deduplicated via `ON CONFLICT(dedup_key) DO UPDATE`.

### Secret Scanner and Token Validation
Regex scanner on response bodies. Tokens validated against 30+ providers (AWS, GCP, Azure, GitHub, Stripe, Slack, Datadog, Anthropic, and more). Live tokens trigger Discord alerts and persist to `secrets_validations`.

### Intel (Shodan)
Shodan host/search queries with file-based caching (TTL: 7 days). Leads stored in `leads`, triaged via API or UI.

### Web UI (Phase 7.4)
Dark-mode FastAPI + Jinja2 + HTMX + Alpine.js + Tailwind CSS. No build step — all frontend dependencies loaded via CDN.

**Live pages:**
- `/` — Dashboard: KPI cards, recent scans, critical findings
- `/scans` — Paginated scan list with filters and New Scan modal
- `/scans/{id}` — Scan detail: phases, findings, cancel button
- `/assets` — Asset list with fingerprint/tech filters; detail page with fingerprint tags
- `/findings` — Paginated table + kanban view with drag-and-drop status columns
- `/programs` — Program list/detail with scope rules and finding counts
- `/secrets` — Validated secrets list (preview only — raw values never shown)
- `/reports` — Reports module at /reports — H1/Bugcrowd/Markdown templates; New Report modal with program/finding picker
- `/settings` — Settings at /settings — General, Integrations, Notifications, System tabs
- Global Cmd-K command palette searches across assets, findings, scans, programs, reports

---

## CLI Command Reference

| Command | Description                          |
|---|--------------------------------------|
| `bounty init-db` | Create / migrate the SQLite database |
| `bounty serve [--host H] [--port P] [--reload]` | Start the web UI server              |
| `bounty smoke-recon --target HOST [--intensity LEVEL]` | Quick single-host recon              |
| `bounty scan run --program PROGRAM_ID [--intensity LEVEL]` | Full pipeline scan                   |
| `bounty programs list` | List programs                        |
| `bounty programs add --id ID --platform P --handle H --name N` | Add a program                        |
| `bounty findings list [--severity LABEL] [--limit N]` | List findings                        |
| `bounty findings show FINDING_ID` | Show finding + evidence              |
| `bounty findings count` | Count findings by severity           |
| `bounty findings export [--format json\|csv] [--output FILE]` | Export findings                      |
| `bounty secrets list [--status STATUS]` | List secr2486et validations          |
| `bounty intel shodan --query QUERY` | Run Shodan query, store leads        |

---

## Web UI

### Running

```bash
bounty serve                              # http://127.0.0.1:8000
bounty serve --host 0.0.0.0 --port 8765  # custom bind
bounty serve --reload                     # hot-reload (dev)
```

### Authentication

```bash
export UI_TOKEN=your-secret-token
bounty serve
```

- **No `UI_TOKEN`**: all routes open (dev mode).
- **With `UI_TOKEN`**: `/api/*` and `/sse/*` require `Authorization: Bearer <token>`; browser sessions use cookie set via `POST /login`.

### API Reference

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Liveness probe |
| GET | `/readyz` | Readiness probe (DB check) |
| GET | `/api/dashboard/stats` | KPI stats for dashboard |
| GET | `/api/assets` | Paginated asset list |
| GET | `/api/findings` | Paginated findings list |
| GET | `/api/findings/stats` | Counts by severity/status/category |
| PATCH | `/api/findings/{id}` | Update finding status |
| GET | `/api/scans` | Paginated scan list |
| POST | `/api/scans` | Trigger new scan |
| GET | `/api/scans/{id}` | Scan detail with phases |
| DELETE | `/api/scans/{id}` | Cancel scan |
| GET | `/api/programs` | Program list |
| POST | `/api/programs` | Create program |
| PATCH | `/api/programs/{id}` | Update program |
| DELETE | `/api/programs/{id}` | Delete program |
| GET | `/api/secrets` | Secret validation list |
| POST | `/api/secrets/{id}/revalidate` | Re-validate a secret |
| GET | `/api/intel/leads` | Intel leads list |
| PATCH | `/api/intel/leads/{id}` | Triage lead |
| GET | `/sse/events` | Global SSE stream |

### Template Architecture

All pages extend `bounty/ui/templates/_base.html` (sidebar + topbar + status bar, dark mode, SSE, toasts, keyboard shortcuts). Component macros in `templates/components/` imported via Jinja2 macro import syntax.

---

## Configuration

```env
DATA_DIR=data              # DB + evidence dir
TOOLS_DIR=tools            # subfinder/naabu binaries
UI_TOKEN=                  # empty = open (dev mode)
HTTP_TIMEOUT=15.0
MAX_CONCURRENT_PER_TARGET=10
LOG_LEVEL=INFO             # DEBUG | INFO | WARNING | ERROR
LOG_FORMAT=console         # console | json
DEFAULT_INTENSITY=normal   # light | normal | aggressive
SHODAN_API_KEY=
INTEL_CACHE_TTL_DAYS=7
SECRET_VALIDATION_ENABLED=true
SECRET_VALIDATION_CACHE_TTL_DAYS=7
DISCORD_WEBHOOK_FINDINGS=
DISCORD_WEBHOOK_SECRETS=
```

---

## Architecture

```
bounty/
  cli.py               CLI (typer)
  config.py            Settings (pydantic-settings)
  db.py                SQLite schema, migrations, get_conn()
  events.py            In-process async event bus
  models.py            Pydantic domain models
  ulid.py              ULID generator
  recon/               Subdomain enum, DNS, HTTP probe, port scan
  fingerprint/         5 parsers, confidence-tiered detections
  detect/              73-check runner (fingerprint-gated)
  secrets/             Regex scanner + 30+ token validators
  intel/               Shodan + lead cache
  triage/              Dedup, prioritisation, Discord notify
  evidence/            HTTP evidence capture + storage
  report/              H1 / Bugcrowd / Intigriti / generic builder
  ui/
    app.py             FastAPI app factory + lifespan
    auth.py            Login / logout routes
    deps.py            FastAPI dependency injectors
    sse.py             SSE manager (fan-out)
    routes/            API + page route modules
    templates/         Jinja2 templates
    static/            app.css + app.js

data/
  bounty.db            SQLite (WAL mode)
  evidence/            HTTP evidence per finding
```

**Request flow:**
```
Browser -> FastAPI
           /api/*  -> route handlers -> aiosqlite -> bounty.db
           /sse/*  -> SSEManager <- bounty.events.bus
           /*      -> page handlers -> Jinja2 templates
```

---

## TruffleHog Integration

Phase 14a integrates [TruffleHog OSS](https://github.com/trufflesecurity/trufflehog) as an optional subprocess, extending native secret detection with ~800 community-maintained secret patterns and ~100 token validators.

### Install

```bash
bounty tools install-trufflehog
```

This downloads the platform-appropriate binary from GitHub Releases into `~/.bounty/tools/trufflehog` and marks it executable.  No Python packages are installed — only a subprocess call.

### Coverage

| Source | Patterns | Validators |
|---|---|---|
| Native (bounty) | ~39 | 39 (all validated via direct API calls) |
| TruffleHog | ~800 | ~100 community detectors |

TruffleHog scans each HTTP response body captured by the evidence pipeline.  Detectors include AWS, GCP, Azure, GitHub, Stripe, Slack, Discord, Shopify, OpenAI, Anthropic, and hundreds more.

### Precedence Rules

1. **Native validator takes precedence** — if bounty has a registered validator for a provider, TruffleHog results for that provider are skipped.
2. **TruffleHog fills the gaps** — for unknown or unsupported providers, TruffleHog detections are persisted with `source='trufflehog'`.
3. **Verified = live** — TruffleHog's `verified: true` maps to `status='live'`; otherwise `status='invalid'`.

### Database

The `secrets_validations` table now has a `source` column:

```sql
SELECT source, COUNT(*) FROM secrets_validations GROUP BY source;
-- native     | 14   (bounty's 14-key direct validators)
-- trufflehog | 8    (additional patterns only TruffleHog detected)
```

### Without TruffleHog

The tool runs normally without TruffleHog installed.  If the binary is missing:
- No subprocess is spawned
- A warning is logged once per scan
- Native detection + validation continues unaffected

---

## Development

```bash
pytest -q                                     # all tests (excludes integration)
pytest tests/test_phase7_2.py -q              # single phase
python -m mypy --strict bounty/               # type check
ruff check bounty/ tests/                     # lint
```

Tests use `tmp_path`-isolated SQLite and `httpx.ASGITransport` — no live HTTP.

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| 1 | Done | Recon pipeline (subdomains, DNS, HTTP probe) |
| 2 | Done | Fingerprinting engine (5 parsers, confidence tiers) |
| 3 | Done | Detection engine v1 (exposed files, config) |
| 3.2 | Done | Fingerprint refinement (vendor overrides) |
| 4 | Done | Detection v2 (backups, archives) |
| 5 | Done | Secret scanner + 30+ token validators |
| 6 | Done | Admin panel detections (26 checks) |
| 7.1 | Done | FastAPI backend, API routes, SSE, auth |
| 7.2 | Done | Web UI shell, dashboard, scans list/detail |
| 7.3 | Done | Assets + Findings full pages, evidence viewer |
| 7.4 | Done | Programs UI, report builder, command palette, settings |
