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

## Current Capabilities (Phase 3)

### Fingerprinting Engine (Phase 3)

After HTTP probing, each successful `ProbeResult` is passed through four pure-function
parsers plus an async favicon fetcher. Results are deduped with confidence boosting,
persisted to `fingerprints`, and summarised back in the `assets` row.

#### Parsers

| Parser | Source | Examples detected |
|---|---|---|
| `headers.py` | HTTP response headers | nginx, apache, IIS, cloudflare, cloudfront, fastly, akamai, PHP, ASP.NET, drupal, wordpress, jenkins, shopify |
| `cookies.py` | Set-Cookie names | PHPSESSID→php, JSESSIONID→java, laravel_session, cf_clearance→cloudflare, incap_ses→imperva, datadome |
| `body.py` | HTML body (BeautifulSoup + lxml) | `<meta generator>` WordPress/Drupal/Hugo/Jekyll, path patterns `/wp-content/`/`/_next/`, `__NEXT_DATA__`, title-based admin panels |
| `tls.py` | TLS certificate fields | self-signed, Let's Encrypt, legacy TLS, cert-expired, cert-expiring-soon |
| `favicon.py` | Favicon byte hash | Shodan/FOFA-compatible mmh3(base64(favicon)) lookup against `favicon_db.json` |

#### Confidence Scoring

- **90–100**: Direct version-bearing signal (Server header with version, `<meta generator>`, `X-Drupal-Cache`)
- **60–89**: Strong indirect signal (JSESSIONID cookie, `/wp-content/` path, distinctive favicon hash)
- **30–59**: Weak heuristic (generic body class patterns, admin path presence)
- Two signals for same tech → `max(conf) + 10`, capped at 100
- Three+ signals → `max(conf) + 20`, capped at 100

#### Admin Panel Detection

`body.py` contains title-based detection for 30+ admin panels & services:
Jenkins, Grafana, Kibana, phpMyAdmin, Adminer, Confluence, Jira, GitLab, Gitea, 
Argo CD, Harbor, Nexus, SonarQube, RabbitMQ Management, Kubernetes Dashboard,
Portainer, Rancher, Zabbix, Nagios, Prometheus, Mattermost, Rocket.Chat,
Discourse, Webmin, cPanel, Plesk, Apache Spark, Apache Airflow, Apache Solr,
Consul, Vault, and default pages (nginx-default-page, directory-listing, **phpinfo-exposed**).

#### Favicon Hash DB

`bounty/fingerprint/data/favicon_db.json` contains ~33 starter entries (one per tool
listed above). Hash fields are `null` placeholders — fill as you encounter real installs:

```bash
# After observing a real Jenkins instance
bounty fingerprint add-favicon-hash jenkins -- -1425421542
```

#### SAN Hostname Discovery

The TLS parser extracts Subject Alternative Names from cert fields. SANs that share
the asset's root domain are inserted as `discovered_via_san` asset rows for the same
program, enabling further probing.

#### Database

Migration V4 converts `fingerprints.id` from `INTEGER AUTOINCREMENT` to `TEXT` (ULID).
The `assets` table gains `server`, `cdn`, and `waf` summary columns updated from the
highest-confidence fingerprint in each category.

#### CLI

```bash
# View fingerprints for a specific asset
bounty fingerprint show <asset_id>

# Update favicon hash in the DB
bounty fingerprint add-favicon-hash <tech> <hash> [--category=other]

# Scan with fingerprint summary in output
bounty smoke-recon --target hackerone.com --intensity gentle
```

Sample `smoke-recon` output with fingerprinting:
```
  ASSETS DISCOVERED: 8
    [200] hackerone.com         HackerOne | Leader in ...  server=cloudflare cdn=cloudflare
           techs: cloudflare(cdn,100),  drupal(cms,100),  fastly(cdn,90)
    [200] docs.hackerone.com    Home | HackerOne Help ...  server=cloudflare cdn=cloudflare
           techs: cloudflare(cdn,100),  nextjs(framework,100)
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

---

## Bulk asset ingestion

`bounty scan-ips` reads a plain-text file of IPs, CIDRs, and ASNs (one per
line, `#` lines are comments) and automatically runs the recon pipeline against
all of them.

```
# my-scope.txt
# Cloudflare public resolvers
1.1.1.1
1.0.0.1/32
# Google ASN (demo — would expand to thousands of CIDRs)
# AS15169
```

```bash
bounty scan-ips --program my-program --file my-scope.txt --intensity gentle
```

Asset type is auto-detected per line:
- `AS12345` → `asn`  (expanded via BGPView API to CIDR list)
- `1.2.3.0/24` → `cidr`  (expanded to individual IPs, refuses < /16)
- `1.2.3.4` → `ip`  (probed directly)

IP-based targets skip subdomain enumeration and DNS resolution.  They are
port-scanned (non-gentle intensity) then HTTP-probed at standard and alternate
web ports (80, 443, 8080, 8443, 8000, 9000, 9090, 3000, 5000, 8888).

IPs that time out within 3 seconds twice in succession are marked unreachable
and skipped for the remainder of the scan to avoid wasting time.

---

## Shodan intel integration

> Requires `SHODAN_API_KEY` — set it in `.env` or as an environment variable.

### Setup

```bash
echo "SHODAN_API_KEY=your-key-here" >> .env
```

### Check remaining credits

```bash
bounty intel-credits
# [bounty intel-credits] 97 query credits remaining  [OK]
```

### Run a sweep and create leads

```bash
bounty intel-sweep \
  --query 'http.title:"Index of /" country:"US"' \
  --max-pages 1 \
  --program h1:my-program
# results:      100
# new leads:    87
# credits used: 1
```

Useful query patterns:

| Goal | Query |
|---|---|
| Open directory listings | `http.title:"Index of /"` |
| Exposed .git repos | `http.html:".git/HEAD"` |
| Spring Boot actuator | `http.title:"Spring Boot"` |
| Default credentials | `http.title:"admin" http.html:"admin"` |
| Expired TLS certs | `ssl.cert.expired:true` |
| Specific org assets | `org:"Example Corp"` |
| Custom port + banner | `port:8443 product:"nginx"` |

### Review and triage leads

```bash
# List new leads
bounty leads list --status new --limit 20

# Promote a lead to an asset row
bounty leads promote 01KR0K4YK07W5CTHVNKBTSBD7A --program h1:my-program

# Dismiss a false positive
bounty leads dismiss 01KR0K4YK07W5CTHVNKBTSBD7B
```

### Example workflow

```bash
# 1. Add a CIDR scope to a program and run recon
echo "203.0.113.0/24" > targets.txt
bounty scan-ips --program my-prog --file targets.txt

# 2. Run a Shodan sweep for the same org
bounty intel-sweep --query 'org:"My Target Corp"' --program my-prog --max-pages 3

# 3. Review leads
bounty leads list --program my-prog --status new

# 4. Promote interesting leads to asset rows for further testing
bounty leads promote <lead-id> --program my-prog

# 5. Run recon on the promoted assets
bounty smoke-recon --target <asset-host>
```

