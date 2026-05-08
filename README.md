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

## Current Capabilities (Phase 6 — Admin Panel Detections)

### Admin Panel Detections (Phase 6)

Phase 6 extends the detection engine with **26 fingerprint-gated admin panel checks** across 21 technology modules.  Detections only run when the relevant tech is fingerprinted during the earlier reconnaissance stage, keeping scans efficient and targeted.

> **Fingerprint gating**: `applicable_to()` calls `has_tech(fingerprints, "<tech>")` from `bounty/detect/_fingerprint_helpers.py`. If the fingerprint stage did not detect the relevant technology at `weak` confidence or above, the detection is skipped entirely — zero HTTP probes are made.

#### Admin Panel Detections — 26 checks

| Module | Detection ID | Probe Path | Default Severity |
|---|---|---|---|
| Jenkins | `admin_panel.jenkins.anonymous_dashboard` | `/api/json` | 700–900 |
| Jenkins | `admin_panel.jenkins.script_console` | `/script` | 950 (critical) |
| Jenkins | `admin_panel.jenkins.build_history` | `/api/json?tree=...` | 600–800 |
| Grafana | `admin_panel.grafana.anonymous` | `/api/datasources` | 600–800 |
| Grafana | `admin_panel.grafana.snapshots` | `/api/snapshots` | 500 (medium) |
| Kibana | `admin_panel.kibana.anonymous` | `/api/status` | 800 (critical) |
| phpMyAdmin | `admin_panel.phpmyadmin.login_exposed` | `/` | 400 (medium) |
| Adminer | `admin_panel.adminer.login_exposed` | `/` | 400 (medium) |
| Apache Solr | `admin_panel.solr.admin_console` | `/solr/` | 700 (high) |
| Apache Solr | `admin_panel.solr.cores_exposed` | `/solr/admin/cores` | 800 (critical) |
| Apache Airflow | `admin_panel.airflow.anonymous` | `/api/v1/dags` | 850 (critical) |
| Apache Airflow | `admin_panel.airflow.config_exposed` | `/config` | 900 (critical) |
| Argo CD | `admin_panel.argocd.anonymous` | `/api/v1/applications` | 900 (critical) |
| RabbitMQ | `admin_panel.rabbitmq.mgmt_exposed` | `/api/overview` | 700 (high) |
| HashiCorp Vault | `admin_panel.vault.ui_exposed` | `/v1/sys/health` | 500–700 |
| HashiCorp Consul | `admin_panel.consul.api_exposed` | `/v1/agent/self` | 700–850 |
| Elasticsearch | `admin_panel.elasticsearch.cluster_exposed` | `/` | 800 (critical) |
| Elasticsearch | `admin_panel.elasticsearch.indices_exposed` | `/_cat/indices` | 900 (critical) |
| Prometheus | `admin_panel.prometheus.metrics_exposed` | `/api/v1/status/config` | 600–800 |
| Kubernetes Dashboard | `admin_panel.k8s_dashboard.exposed` | `/api/v1/login/status` or `/` | 950 (critical) |
| Portainer | `admin_panel.portainer.api_exposed` | `/api/endpoints` | 800 (critical) |
| SonarQube | `admin_panel.sonarqube.anonymous` | `/api/projects/search` | 600 (high) |
| Harbor | `admin_panel.harbor.registry_exposed` | `/api/v2.0/projects` | 700 (high) |
| Nexus | `admin_panel.nexus.repository_exposed` | `/service/rest/v1/repositories` | 600 (high) |
| GitLab | `admin_panel.gitlab.public_projects` | `/api/v4/projects` | 300–700 |
| Gitea | `admin_panel.gitea.public_repos` | `/api/v1/repos/search` | 300–700 |

#### CLI usage (findings work as before — no new commands needed)

```bash
# List all admin panel findings
bounty findings list --severity high

# Show a specific finding
bounty findings show 01JXYZ...

# Count findings by category
bounty findings count
```

---

## Current Capabilities (Phase 4 — Detection Engine)

### Detection Engine (Phase 4)

After fingerprinting, every live asset is scanned by the detection engine.
The runner iterates `REGISTERED_DETECTIONS` (47 checks across 4 categories)
and persists confirmed vulnerabilities as `findings` rows with full evidence.

#### Detection Registry — 21 checks

**Category 1 — Exposed Source Control (7)**

| ID | Name | Severity |
|---|---|---|
| `exposed.source_control.git` | Exposed .git directory | 700 (high) |
| `exposed.source_control.git-credentials` | Exposed .git-credentials | 900 (critical) |
| `exposed.source_control.svn` | Exposed .svn directory | 700 (high) |
| `exposed.source_control.hg` | Exposed .hg directory | 700 (high) |
| `exposed.source_control.bzr` | Exposed .bzr directory | 700 (high) |
| `exposed.source_control.gitlab-ci` | Exposed .gitlab-ci.yml | 300–600 |
| `exposed.source_control.github-workflows` | Exposed workflow directory | 200 (low) |

**Category 2 — Exposed Env & Config (10)**

| ID | Name | Severity |
|---|---|---|
| `exposed.env_config.env` | Exposed .env file | 400–900 |
| `exposed.env_config.wp-config-backup` | Exposed wp-config.php backup | 800 (critical) |
| `exposed.env_config.config-php` | Exposed PHP config backup | 700 (high) |
| `exposed.env_config.java-app-config` | Exposed Spring/Java config | 400–800 |
| `exposed.env_config.rails-credentials` | Exposed Rails credentials | 800 (critical) |
| `exposed.env_config.terraform-state` | Exposed Terraform state | 950 (critical) |
| `exposed.env_config.docker-compose` | Exposed Docker Compose | 500–800 |
| `exposed.env_config.kubeconfig` | Exposed kubeconfig | 950 (critical) |
| `exposed.env_config.private-key` | Exposed PEM private key | 950 (critical) |
| `exposed.env_config.ds-store` | Exposed .DS_Store | 200 (low) |

**Category 3 — Exposed Backups & Archives (4)**

| ID | Name | Severity |
|---|---|---|
| `exposed.backups.database-dump` | Exposed SQL database dump | 900 (critical) |
| `exposed.backups.filesystem-archive` | Exposed filesystem backup | 800 (critical) |
| `exposed.backups.source-map` | Exposed JS source map | 400 (medium) |
| `exposed.backups.editor-swap` | Exposed editor swap/backup | 500 (medium) |

#### False-Positive Guards

Every path-based detection passes through two guards before yielding a finding:

1. **Soft-404 guard** — before scanning, the runner probes a random path
   (`/bounty-soft404-probe-xj7k9m3p`). If the server returns 200 + ≥200 bytes,
   the asset is marked as a soft-404 site and all path-based detections are
   skipped for that asset.

2. **`is_real_file_response()`** — validates that the response body contains
   the expected file signatures AND does not start with HTML DOCTYPE/tags
   (catches catch-all SPA routes serving the homepage for any path).

#### Evidence Capture

Every confirmed finding triggers `capture_http_evidence()`, which writes the
raw HTTP request/response to the `evidence_packages` table and links the row
to the finding via `finding_id`. Evidence includes:
- Request method, URL, headers
- Response status, headers, body (first 64 KB)
- Scan ID for provenance tracing

#### Dedup / UPSERT Behaviour

Findings are inserted via `ON CONFLICT(dedup_key) DO UPDATE`, so re-scanning
an asset that still has the same vulnerability updates `updated_at` and the
`scan_id` without creating duplicate rows. The `dedup_key` is
`{detection_id}:{asset_id}:{path}`.

#### Findings CLI Commands

```bash
bounty findings list [--limit N] [--severity LABEL] [--program PROGRAM_ID]
bounty findings show FINDING_ID
bounty findings count
bounty findings export [--format json|csv] [--output FILE]
```

Example output:
```
ID                         SEVERITY   TITLE
01HXYZ...                  critical   Exposed .env file at example.com/.env
01HXYZ...                  high       Exposed .git directory at staging.example.com
```

---

## Current Capabilities (Phase 3.2)

### Fingerprinting Engine (Phase 3.2)

After HTTP probing, each successful `ProbeResult` is passed through five parsers.
Raw signals are deduplicated and filtered through five **design principles** before
being persisted to `fingerprints` and back-filled into the `assets` row.

#### The Five Principles

These answer *why* the engine works the way it does, not just what rules exist.

**Principle 1 — Confidence is a tier, not a sliding scale.**
Every rule emits one of four tiers:

| Tier | Meaning | Examples |
|---|---|---|
| `definitive` | Version-bearing, vendor-specific, or mathematically exact | `Server: nginx/1.18.0`, `X-Generator: Drupal 9`, `laravel_session` cookie, `cert-expired` from date comparison |
| `strong` | Vendor-specific signal without version, or well-known vendor pattern | `Server: cloudflare`, `X-Drupal-Cache`, `ASP.NET_SessionId` cookie, Let's Encrypt issuer |
| `weak` | Single indirect heuristic — needs corroboration | `PHPSESSID` cookie, `/wp-content/` path, Magento body class |
| `hint` | Suggestive only; never produces a standalone result | `X-Runtime` header (any Rack app), `_session_id` cookie, `data-turbo` attribute |

A `weak` signal with no other signal for the same tech is **dropped**.
A `hint` alone is always **dropped**.

**Principle 2 — Same-category mutual exclusion.**
Within each category (`cms`, `framework`, `web-server`, …):
- If a `definitive` detection exists: all `weak` (and `hint`) signals for that category are suppressed.
- If two `definitive` signals exist for the same category: the second is **demoted** to `strong` with a warning.
- If only a `strong` exists: `hint` signals are suppressed.

This is the rule that fixes Drupal+Magento collisions: Drupal `definitive` (from `X-Generator`) suppresses Magento `weak` (from body class) — no per-case patch needed.

**Principle 3 — Vendor precedence over generic.**
Some platforms (Zendesk, GitHub, Vercel, Netlify) serve other frameworks internally or host arbitrary
content. When these are detected at `strong` or above, their override rules suppress misleading
detections. Configured in `bounty/fingerprint/data/vendor_overrides.json`.

Examples:
- `zendesk` detected → suppress `rails-hotwire` (Zendesk runs Rails internally, but the asset is a help-centre)
- `github` detected → suppress all `cms` category findings (GitHub Pages hosts arbitrary static content)

**Principle 4 — Corroboration boost is conservative.**
- Two independent signals at the **same tier** → upgrade by **one tier** (max `definitive`).
- Three or more at the same tier → **still only one-tier upgrade** (no double-jump).
- One `definitive` + any weaker → stays `definitive`; weaker absorbed into evidence.

**Principle 5 — Evidence is structured per source.**
Every evidence string uses `source:key=value` format for machine-parseability:
```
header:server=nginx/1.18.0; cookie:PHPSESSID; meta:generator=WordPress 6.4
```
Sources: `header:`, `cookie:`, `meta:`, `body:`, `tls:`, `favicon:`.

#### Parsers

| Parser | Source | Examples detected |
|---|---|---|
| `headers.py` | HTTP response headers | nginx/apache/IIS (DEFINITIVE with version, STRONG without), cloudflare (STRONG via Server, DEFINITIVE via CF-Ray), PHP/ASP.NET, Drupal, WordPress, Jenkins, Shopify, CloudFront, Akamai, DataDome |
| `cookies.py` | Set-Cookie names | laravel_session→DEFINITIVE, cf_clearance→DEFINITIVE, incap_ses→DEFINITIVE, ASP.NET_SessionId→STRONG, PHPSESSID→WEAK, JSESSIONID→WEAK |
| `body.py` | HTML body (BeautifulSoup + lxml) | `<meta generator>` → DEFINITIVE, `/_next/static/`/`__NEXT_DATA__` → DEFINITIVE, `/wp-content/` → STRONG, Zendesk script src → STRONG (suppresses rails-hotwire), Magento body class → WEAK |
| `tls.py` | TLS certificate fields | self-signed/cert-expired/legacy-TLS → DEFINITIVE, Let's Encrypt/cert-expiring-soon → STRONG |
| `favicon.py` | Favicon byte hash | Shodan/FOFA-compatible mmh3(base64(favicon)) → DEFINITIVE on match |

#### Admin Panel Detection

`body.py` contains title-based detection (`STRONG` tier) for 30+ admin panels:
Jenkins, Grafana, Kibana, phpMyAdmin, Adminer, Confluence, Jira, GitLab, Gitea,
Argo CD, Harbor, Nexus, SonarQube, RabbitMQ Management, Kubernetes Dashboard,
Portainer, Rancher, Zabbix, Nagios, Prometheus, Mattermost, Rocket.Chat,
Discourse, Webmin, cPanel, Plesk, Apache Spark, Apache Airflow, Apache Solr,
Consul, Spinnaker. Plus `DEFINITIVE` tier for phpinfo-exposed and directory-listing.

#### Favicon Hash DB

`bounty/fingerprint/data/favicon_db.json` contains ~33 starter entries.
Hash fields are `null` placeholders — fill as you encounter real installs:

```bash
# After observing a real Jenkins instance
bounty fingerprint add-favicon-hash jenkins -- -1425421542
```

#### SAN Hostname Discovery

The TLS parser extracts Subject Alternative Names from cert fields. SANs that share
the asset's root domain are inserted as `discovered_via_san` asset rows for the same
program, enabling further probing.

#### Database

Migration V5 converts `fingerprints.confidence` from `INTEGER` (0–100) to `TEXT` tier
(`definitive` | `strong` | `weak` | `hint`) per Principle 1.
Migration V4 converted `fingerprints.id` from `INTEGER AUTOINCREMENT` to `TEXT` (ULID).

#### Vendor Overrides

`bounty/fingerprint/data/vendor_overrides.json` — edit to add or change vendor suppression rules.
Current entries: `zendesk`, `github`, `github-pages`, `vercel`, `netlify`, `heroku`.

#### CLI

```bash
# View fingerprints for a specific asset
bounty fingerprint show <asset_id>

# Update favicon hash in the DB
bounty fingerprint add-favicon-hash <tech> <hash> [--category=other]

# Scan with fingerprint summary in output
bounty smoke-recon --target hackerone.com --intensity gentle
```

Sample `smoke-recon` output with fingerprinting (tier shown in uppercase):
```
  ASSETS DISCOVERED: 8
    [200] hackerone.com             HackerOne | Leader in ...  server=cloudflare cdn=cloudflare
           techs: cloudflare(cdn,DEFINITIVE),  drupal(cms,DEFINITIVE),  fastly(cdn,STRONG)
    [200] docs.hackerone.com        Home | HackerOne Help ...  server=cloudflare cdn=cloudflare
           techs: zendesk(other,STRONG),  cloudflare(cdn,DEFINITIVE)
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
4. **Phase 3** ✅ — Technology fingerprinting (Wappalyzer categories, favicon hash)
5. **Phase 4** ✅ — Detection base class + exposed-file detections (21 checks)
6. **Phase 5** ✅ — Token validators (50+ providers: AWS, Stripe, GitHub, …) + secret scanning
7. **Phase 6** ✅ — Admin panel detections (26 fingerprint-gated checks across 21 modules)
8. **Phase 7** — Evidence capture (Playwright screenshots, HAR), triage, reporting
9. **Phase 8** — Scheduler (APScheduler) for automated periodic scans
10. **Phase 9** — UI base (FastAPI + Jinja2 dashboard skeleton)
11. **Phase 10** — Full UI screens (assets, findings, scan status, live log)
12. **Phase 11** — End-to-end integration test suite across all phases

---

## Development

```bash
# Run unit tests only (no network required) — this is the default
pytest

# Run integration tests (requires live DNS + HTTP access)
pytest -m integration

# Run everything (unit + integration)
pytest -m ''

# Type-check
mypy bounty/ --strict

# Lint
ruff check bounty/ tests/


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

---

## Secret Scanning + Token Validation

Phase 5 adds inline secret scanning and live-token validation to the detect pipeline.  Every time a finding is persisted with evidence (HTTP response bodies, `.env` files, etc.), the scanner extracts credentials and validates them against provider APIs in the background.

### Supported providers (12 total)

| Slug | Validation method | Cost |
|---|---|---|
| `aws` | STS `GetCallerIdentity` (boto3) | free |
| `github` | `GET /user` with `Authorization: token …` | free |
| `stripe` | `GET /v1/balance` with Bearer auth | free |
| `openai` | `GET /v1/models` with Bearer auth | free |
| `anthropic` | Minimal `POST /v1/messages` (1-token prompt) | ~$0.001 |
| `slack` | `POST /api/auth.test` | free |
| `discord` | `GET /api/users/@me` | free |
| `twilio` | `GET /Accounts/{SID}` with Basic auth (SID + auth token) | free |
| `sendgrid` | `GET /v3/scopes` with Bearer auth | free |
| `mailgun` | `GET /v3/domains` with Basic auth | free |
| `razorpay` | `GET /v1/payments?count=0` with Basic auth | free |
| `shopify` | `GET /admin/api/2024-01/shop.json` (requires store domain from context) | free |

### How validation works

1. **Discovery** — the scanner searches response bodies, headers, and saved body files for credential patterns (compiled regex + pairing logic for paired secrets like AWS key+secret and Twilio SID+auth token).
2. **Caching** — if a (hash, provider) pair was checked within `SECRET_VALIDATION_CACHE_TTL_DAYS` (default: 7 days) with a conclusive result (`live` or `invalid`), the cached status is reused and the live API is NOT called.
3. **Validation** — a read-only API call verifies the credential.  No state-mutating calls are ever made.
4. **Persistence** — results are UPSERTed into `secrets_validations` keyed on `(secret_hash, provider)`.
5. **Severity bump** — if any secret is `live`, the finding's severity is raised to at least the provider's bump floor (see below) and `validated-secret:<provider>` tags are added.

#### Severity bumping rules

| Provider category | Providers | Minimum severity |
|---|---|---|
| Cloud / payments | `aws`, `gcp`, `azure`, `stripe`, `paypal`, `razorpay`, `shopify` | **950** (critical) |
| Source control | `github`, `gitlab` | **850** (critical) |
| Email / comms | `sendgrid`, `mailgun`, `twilio` | **800** (critical) |
| Chat | `slack`, `discord` | **700** (high) |
| Unknown provider | *(any unregistered)* | **750** (high) |

### Configuration

All settings are read from environment variables (or `.env`):

| Env var | Default | Description |
|---|---|---|
| `SECRET_VALIDATION_ENABLED` | `true` | Enable/disable the entire pipeline |
| `SECRET_VALIDATION_CACHE_TTL_DAYS` | `7` | Days before a cached result expires |
| `SECRET_VALIDATION_MAX_CONCURRENT` | `5` | Max concurrent validator API calls per finding |

### CLI commands

```bash
# List recent secret validations
bounty secrets list --limit 20

# Filter by status
bounty secrets list --status live

# Filter by provider
bounty secrets list --provider stripe

# Filter by finding
bounty secrets list --finding 01JXYZ...

# Show full detail for a specific record (use id prefix or full id)
bounty secrets show 01JXYZ...

# Force re-validation of a record (bypasses cache)
# Note: raw secret values are never stored; re-validation uses the stored hash
# and will typically return 'invalid' for HTTP-based providers.
bounty secrets revalidate 01JXYZ...

# Show counts grouped by provider and status
bounty secrets stats
```

### Example output

```
By provider:
  aws                      3
  stripe                   2
  github                   1

By status:
  invalid                  5
  error                    1
```

