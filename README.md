# bounty — Personal Bug Bounty Automation System

A personal, single-operator tool for automating the reconnaissance and
triage phases of ethical bug bounty research. It connects to HackerOne,
Bugcrowd, and Intigriti to pull scope, enumerates subdomains, resolves DNS,
HTTP-probes live hosts, fingerprints technologies, validates leaked tokens,
and stores everything in a local SQLite database with full provenance.

> **⚠️ Authorisation disclaimer**: This tool is intended for use **only
> against targets that you have explicit, written permission to test**. Running
> it against systems you do not own or have not been authorised to test may
> violate laws including the Computer Fraud and Abuse Act (US), the Computer
> Misuse Act (UK), and equivalents worldwide. This is a personal tool, not a
> product or service. The author accepts no liability for misuse.

---

## Prerequisites

| Dependency | Version | Install |
|---|---|---|
| Python | ≥ 3.11 | `brew install python@3.11` or [python.org](https://python.org) |
| subfinder | any | `brew install subfinder` or `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| naabu (optional) | any | `brew install naabu` or `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |

Subfinder is used for passive subdomain enumeration. naabu is used for port
scanning (skipped in `gentle` intensity mode). Both can be placed in the
`tools/` directory instead of PATH.

---

## Quick Start

```bash
# 1. Clone and install
git clone <repo-url> && cd bug_bounty
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Initialise the database
bounty init-db

# 3. Run a smoke test against a target you're authorised to scan
bounty smoke-recon --target hackerone.com --intensity gentle
```

Expected output includes a list of discovered subdomains with HTTP status
codes, a `PHASES` summary, and `scan status=completed`.

### Environment Variables

Create a `.env` file (or set env vars) to customise behaviour:

```env
DATA_DIR=data          # directory for bounty.db and evidence files
TOOLS_DIR=tools        # directory for subfinder/naabu binaries
LOG_LEVEL=INFO         # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT=console     # console (pretty) or json (structured)
```

---

## Current Capabilities (Phase 2.5)

### Subdomain Enumeration
- **subfinder** — passive source aggregation (crtsh, virustotal, etc.)
  Requires API keys in `~/.config/subfinder/provider-config.yaml` for full
  coverage; works with zero configuration for passive/free sources.
- **crt.sh** — certificate transparency log query, completely free and
  unauthenticated, runs in parallel with subfinder via `asyncio.create_task`.

### DNS Resolution
- Async batch resolution via `dnspython` with concurrency control.
- Wildcard detection: A-record fans to a single IP are flagged as likely
  wildcard zones and tagged accordingly.
- Private/internal IPs filtered out (RFC 1918, loopback, link-local).

### HTTP Probing
- Full response capture: status, headers, body, TLS metadata, redirect chain.
- Concurrent probing via `httpx` (async) with per-host concurrency limits.
- Extracts page `<title>` and `Server` header for quick triage.

### Port Scanning (optional)
- `naabu` integration for web-port detection (80, 443, 8080, 8443, …).
- Skipped in `gentle` intensity to avoid noisy active probing.
- Open web ports are HTTP-probed in addition to the defaults.

### Persistence
- SQLite with WAL mode for concurrent reads during active scans.
- All tables use ULID primary keys (TEXT) for portable, sortable IDs.
- Assets are upserted on URL uniqueness — re-scans update existing rows.
- `scans` and `scan_phases` tables track progress of each pipeline run.
- `PRAGMA foreign_keys = ON` enforced on every connection.

### CLI
- `bounty init-db` — initialise / migrate the database.
- `bounty smoke-recon --target <domain>` — end-to-end pipeline test.

---

## Architecture

```
bounty/
├── __init__.py       logging configuration (structlog)
├── cli.py            Typer CLI (smoke-recon, init-db)
├── config.py         pydantic-settings configuration
├── db.py             SQLite schema, migrations, get_conn context manager
├── events.py         in-process asyncio pub/sub (SSE bus)
├── exceptions.py     ToolMissingError, ToolFailedError, PlatformError, …
├── models.py         Pydantic v2 models (Asset, Scan, Finding, …)
├── scheduler.py      APScheduler integration for automated periodic scans
├── ulid.py           pure-Python ULID generator (no dependencies)
│
├── recon/            Recon pipeline
│   ├── __init__.py   recon_pipeline() — orchestrates all phases
│   ├── subdomains.py subfinder + crt.sh enumeration
│   ├── resolve.py    async DNS resolution with wildcard detection
│   ├── http_probe.py httpx-based HTTP probing with TLS capture
│   └── port_scan.py  naabu port scanner wrapper
│
├── fingerprint/      Technology fingerprinting (headers, body, favicon hash)
├── detect/           Misconfiguration detectors + Nuclei runner
├── validate/         Token validators (AWS, Stripe, GitHub, …)
├── evidence/         Screenshot + HAR capture for findings
├── triage/           Deduplication, prioritisation, notifications
├── report/           HackerOne / Bugcrowd / Intigriti report templates
├── targets/          Platform scope fetchers (h1, bugcrowd, intigriti)
│
└── ui/               FastAPI + Jinja2 web UI (background asset browser)
    ├── app.py        FastAPI application factory
    ├── routes/       API + page routes
    └── templates/    Jinja2 HTML templates
```

---

## Roadmap

1. **Phase 1** ✅ — DB schema, HTTP probe, EventBus SSE
2. **Phase 2** ✅ — Recon pipeline (subfinder, DNS, port scan, HTTP probe)
3. **Phase 2.5** ✅ — Integration bug fix, crt.sh, ULID ids, smoke CLI
4. **Phase 3** — Technology fingerprinting (Wappalyzer categories, favicon hash)
5. **Phase 4** — Detection base class + Nuclei runner integration
6. **Phase 5** — Detection modules (admin panels, cloud misconfigs, secrets scanner)
7. **Phase 6** — Token validators (50+ providers: AWS, Stripe, GitHub, …)
8. **Phase 7** — Evidence capture (Playwright screenshots, HAR), triage, reporting
9. **Phase 8** — Scheduler (APScheduler) for automated periodic scans
10. **Phase 9** — UI base (FastAPI + Jinja2 dashboard skeleton)
11. **Phase 10** — Full UI screens (assets, findings, scan status, live log)
12. **Phase 11** — End-to-end integration test suite across all phases

---

## Development

```bash
# Run unit tests (no network)
pytest tests/smoke.py tests/test_phase2.py -k "not live and not pipeline" -v

# Run integration test (requires network)
pytest tests/test_phase2.py::test_recon_pipeline_mini -v -s

# Type-check
mypy bounty/ --strict

# Lint
ruff check bounty/ tests/
```

