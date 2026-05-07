# Audit Report — Phase 1 & 2

_Audited: every file under `bounty/` and `tests/`. Date: 2026-05-07._

---

## Critical Issues (must fix before Phase 3)

---

### 1. Schema vs Model Drift: `id` and FK types wrong after Migration v1

- **Location:** `bounty/models.py:124`, `bounty/models.py:244`, `bounty/models.py:174`, `bounty/models.py:278-279`, `bounty/models.py:393`
- **Problem:** Migration v1 (`bounty/db.py:308–467`) converts `assets.id`, `scans.id`, `asset_history.asset_id`, `fingerprints.asset_id`, `scan_phases.scan_id`, `findings.asset_id`, `findings.scan_id`, and `secrets_validations.asset_id` from `INTEGER` to `TEXT` (to hold ULIDs). However, the Pydantic models were never updated to match:
  - `Asset.id: int | None = None` → DB column is now `TEXT PRIMARY KEY`
  - `Scan.id: int | None = None` → DB column is now `TEXT PRIMARY KEY`
  - `FingerprintResult.asset_id: int | None = None` → FK column is now `TEXT`
  - `Finding.asset_id: int | None = None` → FK column is now `TEXT`
  - `Finding.scan_id: int | None = None` → FK column is now `TEXT`
  - `SecretValidation.asset_id: int | None = None` → FK column is now `TEXT`

  Any route or logic that reads these columns from the database and validates them via `Model.model_validate(dict(row))` will raise a `ValidationError` because Pydantic will try to coerce a ULID string like `"01J5X4..."` into an `int`. The in-process pipeline currently bypasses Pydantic for DB reads (it uses raw `sqlite3.Row` access), so no crash is observed today — but the moment any UI route serialises an asset row it will explode.

- **Suggested fix:** Change the six affected fields to `str | None`: `Asset.id`, `Scan.id`, `FingerprintResult.asset_id`, `Finding.asset_id`, `Finding.scan_id`, `SecretValidation.asset_id`. Also update `ScanRequest.asset_id: int | None` to `str | None` for consistency. Run a quick `model_validate` round-trip test against a real DB row after the fix.

---

### 2. HTTP Probe Body Cap Does Not Prevent OOM

- **Location:** `bounty/recon/http_probe.py:194`
- **Problem:** The 2 MiB body cap is applied as `body = response.content[:_MAX_BODY]`. The `response.content` property in httpx **reads the entire response body into memory before returning** — the slice happens _after_ the full buffer is loaded. A malicious target that streams a 1 GB (or 50 GB) response body will exhaust process memory before the cap has any effect. The cap is purely illusory.
- **Suggested fix:** Replace the single `await client.get(url)` call with a streaming read loop using `client.stream("GET", url)` and `response.aiter_bytes()`. Accumulate bytes manually up to `_MAX_BODY`, then break. Example pattern:
  ```python
  body = b""
  async with client.stream("GET", url) as response:
      async for chunk in response.aiter_bytes(chunk_size=65536):
          body += chunk
          if len(body) >= _MAX_BODY:
              body = body[:_MAX_BODY]
              break
  ```
  This bounds memory to `_MAX_BODY + one_chunk_size` regardless of server behaviour.

---

### 3. `break` Instead of `continue` on `ToolMissingError` Silently Skips Remaining Domains

- **Location:** `bounty/recon/__init__.py:377–383`
- **Problem:** The subdomain enumeration loop iterates over `in_scope_domains`. When subfinder is missing, `enumerate_subdomains` first yields crt.sh results, then raises `ToolMissingError`. The exception is caught at line 377 and the handler does `break` — which exits the outer `for domain in ...` loop. If there are three in-scope domains, only the first domain gets crt.sh enumeration; the other two are silently dropped. The log message says `"subfinder_not_installed"` but there is no indication that the remaining domains were abandoned.
  ```python
  except ToolMissingError:
      bound_log.warning(...)
      break   # ← THIS IS THE BUG
  ```
- **Suggested fix:** Change `break` to `continue` so enumeration for remaining domains proceeds via crt.sh. The log warning is still correct (subfinder is missing), but the loop advances. Alternatively, check for subfinder once before the loop and skip it globally if missing, relying entirely on crt.sh for all domains.

---

### 4. Pydantic JSON Fields Lack Serialisation Validators — `tag` and `bounty_table` Will Fail DB Round-trips

- **Location:** `bounty/models.py:82–83` (Program), `bounty/models.py:139` (Asset), `bounty/models.py:295` (Finding)
- **Problem:** Three fields are stored as raw JSON strings in SQLite but declared as Python objects in Pydantic models with no custom validator to handle the decoding:
  - `Program.bounty_table: dict[str, float] | None` — stored as `TEXT` (e.g. `'{"critical": 10000}'`)
  - `Asset.tags: list[str]` — stored as `TEXT NOT NULL DEFAULT '[]'` (e.g. `'["wildcard_zone"]'`)
  - `Finding.tags: list[str]` — same

  When a row is loaded from SQLite and passed to `Model.model_validate({"tags": '["wildcard_zone"]', ...})`, Pydantic v2 in strict mode will not automatically JSON-parse the string into a list — it will raise `ValidationError: value is not a valid list`. This will surface as soon as any API endpoint or report generator calls `model_validate` on a DB row.

- **Suggested fix:** Add `@field_validator("tags", mode="before")` in `Asset` and `Finding` that calls `json.loads(v) if isinstance(v, str) else v`. Same for `bounty_table` in `Program`. Alternatively, adopt a `model_validator(mode="before")` that pre-processes all known JSON-stored fields.

---

## Important Issues (should fix soon)

---

### 5. Duplicate Asset Rows: `http://` and `https://` Treated as Separate Assets

- **Location:** `bounty/recon/__init__.py:451`, `bounty/recon/__init__.py:65–81`; UNIQUE constraint at `bounty/db.py:104`
- **Problem:** `_probe_host` always probes both `("https", 443)` and `("http", 80)` for every resolved host. The canonical URL is built as `https://hackerone.com` and `http://hackerone.com` respectively. Because `UNIQUE(program_id, url)` includes the scheme, both URLs are distinct and two rows are inserted. This is the observed "two rows for hackerone.com" in smoke output. For a large target like `*.example.com` this doubles the asset count and the rows are redundant — in almost all cases HTTP simply redirects to HTTPS.
- **Suggested fix:** After probing HTTPS successfully, check whether the HTTP probe's `final_url` (after redirects) matches the HTTPS URL. If HTTP redirects to HTTPS, skip the HTTP row insertion entirely (or optionally record the redirect in `asset_history` rather than creating a second asset). At minimum the canonical URL in the UNIQUE constraint should drop the scheme (store `host[:port]` only), treating both schemes as the same service.

---

### 6. `resolve_batch`: Shared `wildcard_zones` Dict Has No Lock (Data Race)

- **Location:** `bounty/recon/resolve.py:292–298`
- **Problem:** `wz_lock = asyncio.Lock()` is created at line 293 but is **never used**. The `wildcard_zones: dict[str, bool]` is mutated directly inside `_resolve_one` at line 194 (`wildcard_zones[zone] = ...`), which is called concurrently for all hostnames. Multiple coroutines can simultaneously read, write, and perform a check-then-set on the same zone key without any synchronisation. Under CPython's GIL pure dict operations survive this, but the check-then-probe-then-set pattern at lines 193–194 is a classic TOCTOU race: two tasks can both find `zone not in wildcard_zones`, both fire a wildcard DNS probe, and both write back — the redundant probe wastes real DNS queries and clock time.
- **Suggested fix:** Either (a) use `wz_lock` that was created but never wired in — pass it to `_resolve_one` and guard the check-probe-set block with `async with wz_lock`, or (b) remove `wz_lock` and accept the rare duplicate probe (low impact), but at minimum document the race explicitly.

---

### 7. TLS Capture Always Returns `None` in Practice

- **Location:** `bounty/recon/http_probe.py:203–218`
- **Problem:** The code tries to extract TLS information by traversing `client._transport._pool._connections[n]._ssl_object`. This relies entirely on httpx's private internal structure (prefixed with `_`). The internal attribute hierarchy changes between httpx versions. In current httpx (0.27+), the connection pool structure is `httpx.AsyncHTTPTransport._pool` (an `httpcore.AsyncConnectionPool`) and the individual connection's ssl object is accessed differently. In practice this code path silently fails every time (the whole block is in a bare `except Exception: pass`) and `tls` is always `None`. TLS metadata is never stored despite being in the schema and models.
- **Suggested fix:** Switch to an event hook approach. httpx supports `event_hooks={"response": [...]}` where a hook on `"response"` can inspect `response.extensions.get("ssl_object")` which is the public supported path for TLS metadata as of httpx 0.23+. Alternatively, use the `network_stream` approach already partially attempted for IP extraction at line 227.

---

### 8. `crt.sh`: No Retry on 5xx/Timeout, No Fallback CT Source

- **Location:** `bounty/recon/subdomains.py:123–127`
- **Problem:** `_crtsh_hostnames` does one HTTP request with no retry loop. On `httpx.TimeoutException` or any other exception, it logs a warning and returns an empty set. crt.sh is known to return 502 or timeout under load. When this happens all crt.sh discoveries for the domain are silently lost and no fallback is attempted. For targets with no subfinder API keys, crt.sh is the only enumeration source — losing it means zero subdomains are discovered.
- **Suggested fix:** Add a simple retry loop (2–3 attempts with exponential backoff) specifically for `502`, `503`, and `TimeoutException`. Add a second CT source as a fallback — `https://certspotter.com/api/v1/issuances?domain=DOMAIN&include_subdomains=true&expand=dns_names` is free, no auth required, returns JSON, and has independent uptime from crt.sh.

---

### 9. Per-Host Semaphore Keyed by `scheme:host:port`, Not Just `hostname`

- **Location:** `bounty/recon/http_probe.py:58–69`
- **Problem:** `_host_key()` returns `f"{scheme}:{hostname}:{port}"`. This means concurrent probes of `https://example.com` and `http://example.com` use **different semaphores** despite both connecting to the same physical host. The `max_concurrent_per_target` limit is therefore 10 HTTPS + 10 HTTP = 20 effective connections to one server simultaneously. This defeats the purpose of the per-host rate limit.
- **Suggested fix:** Key by `hostname` only (`parsed.hostname`). All scheme/port combinations to the same DNS name share one semaphore. If per-port isolation is needed for specific reasons (e.g., a host with a radically different server on port 8080), document that choice explicitly.

---

### 10. `Finding._derive_label` Validator Is a No-op

- **Location:** `bounty/models.py:299–306`
- **Problem:** The `@field_validator("severity_label", mode="before")` on `Finding` is supposed to derive the label from `severity` if `severity_label` is not set. However, both branches of the validator simply return `v` unchanged — the `severity` value from `info.data` is never read, and no derivation happens. If a raw DB row with `severity_label = NULL` (or an empty string) is validated, the validator returns `None`/`""`, which will fail the `SeverityLabel` Literal type check. `FindingDraft` has the correct `computed_severity_label` property, but `Finding` does not.
- **Suggested fix:** Fix the validator to actually read `info.data.get("severity", 500)` and call `severity_label(score)` from the module-level helper when `v` is falsy, i.e.:
  ```python
  @field_validator("severity_label", mode="before")
  @classmethod
  def _derive_label(cls, v: object, info: Any) -> str:
      if isinstance(v, str) and v:
          return v
      score = (info.data or {}).get("severity", 500)
      return severity_label(int(score))
  ```

---

### 11. `Intensity` Literal vs Runtime String Inconsistency

- **Location:** `bounty/models.py:45`, `bounty/recon/__init__.py:418`, `bounty/recon/port_scan.py:51–55`
- **Problem:** `Intensity = Literal["light", "normal", "aggressive"]` is defined in models. `ScanRequest` and `Scan` use `Intensity` — so the API layer never accepts `"gentle"`. But the entire recon pipeline and port-scan internals check for `intensity == "gentle"` and `_RATE_MAP` includes a `"gentle"` key. The CLI defaults to `"gentle"`. There is a total mismatch between what the model layer allows and what the execution layer expects. A `ScanRequest(intensity="gentle")` would be rejected by Pydantic. Running a `Scan` persisted from a `ScanRequest` would never hit the `"gentle"` code paths.
- **Suggested fix:** Pick one vocabulary and apply it everywhere. "gentle" is more expressive than "light"; rename the Literal to `Literal["gentle", "normal", "aggressive"]` and update `Settings.default_intensity` validator, models, and any constants that check for `"light"`.

---

### 12. `apply_migrations` Opens Connection Without Setting WAL Mode

- **Location:** `bounty/db.py:513`
- **Problem:** `apply_migrations()` opens a raw `sqlite3.connect()` without calling `PRAGMA journal_mode = WAL`. In practice this only matters when `apply_migrations` is called on a fresh database that has not yet been through `init_db()`. The CLI and tests always call `init_db()` first, so WAL is already set persistently. However, if any future code path calls `apply_migrations()` without a prior `init_db()` (e.g., a migration-only tool), the DB file would be created in the default DELETE journal mode and subsequent WAL assumptions would be invalid.
- **Suggested fix:** Add `conn.execute("PRAGMA journal_mode = WAL")` after opening the connection in `apply_migrations()`, mirroring what `get_conn()` and `init_db()` already do. One-liner change.

---

### 13. No Discovery Provenance Written for Any Asset

- **Location:** `bounty/recon/__init__.py:365–391` (enumeration phase), `bounty/recon/__init__.py:200–222` (`_upsert_asset`)
- **Problem:** As agreed during design ("we talked about this but didn't formally add it"), no provenance information is written per discovery. The asset row has a `tags` column but it is only used for `["wildcard_zone"]`. Nothing records whether a hostname was found by subfinder, crt.sh, or was seeded directly from a scope target. There is no `source` field in `asset_history` entries either since those aren't written during the pipeline at all. This makes post-run analysis (e.g., "which subdomains did crt.sh exclusively find?") impossible.
- **Suggested fix:** At minimum, add discovery source tags when inserting/updating assets. Pass `source` into `_upsert_asset` and append it to the `tags` list (e.g., `["source:crtsh"]`, `["source:subfinder"]`). For full provenance, add an `asset_history` insert with `field="discovered_by"` and `new_value=source` on first creation.

---

## Minor Issues / Code Smells (defer)

---

### 14. IPv6 URL with Port Parsed Incorrectly in `_normalise_target`

- **Location:** `bounty/targets/manual.py:130–142`
- **Problem:** For a URL like `https://[::1]:8080/path`, after stripping the scheme the intermediate value is `[::1]:8080/path`. After splitting by `/`, it becomes `[::1]:8080`. The port-stripping condition checks `":" in t and not t.startswith("[")` — the condition evaluates as `True and False`, so it skips port stripping. Then `t.strip("[]")` yields `"::1]:8080"` (only the leading `[` is stripped; the trailing chars are `]:8080`, not `]`). The result `::1]:8080` is not a valid address and will not match any scope rule. This bug only affects IPv6 addresses with explicit ports in URL form — an uncommon combination in bug-bounty scopes but possible.
- **Suggested fix:** Before the existing port-strip check, add an explicit IPv6 unwrap step: if `t.startswith("[")` and `"]:" in t`, extract the address between `[` and `]`, then extract the port separately.

---

### 15. Module-level `asyncio.Semaphore` / `asyncio.Lock` Creation

- **Location:** `bounty/recon/http_probe.py:41–42`, `bounty/recon/port_scan.py:62`, `bounty/events.py:58`
- **Problem:** `_sem_lock = asyncio.Lock()`, `_semaphores = {}` (dict of Semaphore), and `_scan_sem = asyncio.Semaphore(3)` are created at module import time — outside any running event loop. In Python ≤3.9 these attached to whatever loop was current; in 3.10–3.12 a DeprecationWarning is emitted; in Python 3.14 (the runtime in use, as evidenced by `cpython-314.pyc` cache files) the behaviour should be checked against the latest asyncio docs. The primitives work correctly in practice as long as they are first _used_ inside a running event loop, but the pattern is fragile and the deprecation path is clear.
- **Suggested fix:** Lazily initialise these primitives inside the first async call that needs them (using `None` sentinels and a simple `if _sem_lock is None: _sem_lock = asyncio.Lock()`), or move them inside a class with a lazy `__init__` triggered from an async context.

---

### 16. `_QUEUE_MAX = 256` Hardcoded in `events.py`

- **Location:** `bounty/events.py:46`
- **Problem:** The SSE subscriber queue depth is a hardcoded constant. For high-throughput scans or many concurrent SSE clients, 256 may be too small (causing excessive drops) or too large (wasting memory). Other numeric limits like `max_concurrent_per_target` and `http_timeout` are already in `Settings`; this one was missed.
- **Suggested fix:** Add `sse_queue_max: int = 256` to `Settings` and read `get_settings().sse_queue_max` when constructing the queue in `subscribe()`.

---

### 17. `publish_sync()` Calls `asyncio.run()` as Fallback

- **Location:** `bounty/events.py:109`
- **Problem:** `asyncio.run(self.publish(event))` is called when no event loop is running. `asyncio.run()` creates a brand-new event loop, runs the coroutine to completion, and tears it down. If this is called even once from a thread that is _itself_ managed by an event loop (e.g., `run_in_executor` worker), it will raise `RuntimeError: This event loop is already running`. The comment says "dev/CLI context" but the scheduler (APScheduler) — mentioned in the docstring — may invoke `publish_sync` from a background job where a loop is present yet `get_running_loop()` raises `RuntimeError` because the call isn't on the loop thread.
- **Suggested fix:** Use `asyncio.run_coroutine_threadsafe(self.publish(event), loop)` instead of `call_soon_threadsafe(lambda: ensure_future(...))`. This gives a future back, but the fire-and-forget semantic is preserved by discarding it. The existing `call_soon_threadsafe` path should work; the `asyncio.run()` fallback is the dangerous one.

---

### 18. `subdomains.py`: Double-Timeout on crt.sh Await

- **Location:** `bounty/recon/subdomains.py:250`
- **Problem:** `_crtsh_hostnames` already enforces `timeout=_CRTSH_TIMEOUT` on the httpx client (line 105). Then in `enumerate()`, the already-running crt.sh task is awaited with another `asyncio.wait_for(..., timeout=_CRTSH_TIMEOUT)` (line 250). If the first timeout fires, the task is cancelled, and the second wait_for fires on the cancelled task. If eventually the httpx timeout fires first, the second `wait_for` may see a completed task (with empty result) or a task that already raised. The logic is not harmful — the except blocks absorb errors — but it is confusing and the outer `wait_for` is redundant since the inner httpx timeout already bounds the operation.
- **Suggested fix:** Remove the outer `asyncio.wait_for` and just `await crtsh_task`. The httpx client timeout in `_crtsh_hostnames` is the real deadline.

---

### 19. `assert` Statements Used for Subprocess Pipe Availability

- **Location:** `bounty/recon/subdomains.py:191`, `bounty/recon/port_scan.py:168–169`
- **Problem:** `assert proc.stdout is not None` and `assert proc.stderr is not None` are used to assert that pipes were opened. While these are always `True` given `stdout=asyncio.subprocess.PIPE`, the asserts are stripped in optimised builds (`python -O`) and raise `AssertionError` rather than a typed exception when they do fail.
- **Suggested fix:** Replace with explicit checks: `if proc.stdout is None: raise ToolFailedError("subfinder", -1, "stdout pipe unavailable")`.

---

### 20. Missing `scope_type` Index on `targets` Table

- **Location:** `bounty/db.py:77`
- **Problem:** `targets` has an index on `program_id` but the most common filter is `WHERE scope_type = 'in_scope' AND program_id = ?`. A composite index on `(program_id, scope_type)` would serve this query without a table scan for programs with large target lists.
- **Suggested fix:** Add `CREATE INDEX IF NOT EXISTS idx_targets_program_scope ON targets(program_id, scope_type)` to both `_SCHEMA` and `_recreate_indexes`.

---

### 21. `phase_check.py` / `smoke.py` Import Side Effects at Module Level

- **Location:** `tests/smoke.py` (entire file), `tests/phase2_check.py`
- **Problem:** The smoke test module imports `bounty.recon.http_probe` which creates `_sem_lock = asyncio.Lock()` at import time. Under pytest-asyncio, tests may run in different event loops depending on the `asyncio_mode` setting. If the lock was created in one loop context and used in another (possible with `scope="session"` tests), you can see `RuntimeError: no running event loop` or subtle double-acquire bugs. Currently the tests use default pytest-asyncio settings (function scope), so each test gets a fresh loop — but the module-level lock object persists across tests.
- **Suggested fix:** Add a `conftest.py` with `asyncio_mode = "auto"` and `event_loop_policy` set explicitly. This is a standard pytest-asyncio 0.23+ pattern.

---

## Verified-Good Areas

- **Out-of-scope precedence:** `ScopeRules.matches()` checks `out_of_scope` first before `in_scope`. Rules tested and documented correctly.
- **Wildcard scope semantics:** `*.example.com` correctly matches multi-level subdomains (`deep.sub.example.com`) and correctly rejects the apex domain (`example.com`). Confirmed in both implementation and test suite.
- **Case-insensitive scope matching:** Both in-scope patterns and target strings are lowercased on entry; matching is case-insensitive throughout.
- **URL stripping before scope matching:** Scheme, path, query string, fragment, and port are stripped with a documented multi-step procedure before hostname matching. Works correctly for standard IPv4/hostname URLs.
- **CIDR matching:** Uses Python's `ipaddress` standard library, which handles IPv4, IPv6, and edge cases like `/32` correctly.
- **Foreign key enforcement:** Every connection opened via `get_conn()` sets `PRAGMA foreign_keys = ON` before yielding. `init_db()` also sets it.
- **WAL mode:** Both `get_conn()` and `init_db()` set `PRAGMA journal_mode = WAL`.
- **Explicit commits:** All write paths call `conn.commit()` explicitly. No reliance on auto-commit or context manager implicit commit.
- **Connection close on exception:** `get_conn()` has a `try/except/finally` that calls `conn.rollback()` on exception and `conn.close()` unconditionally in `finally`.
- **No hardcoded DB paths:** All code obtains the DB path from `settings.db_path` or accepts it as a parameter. No path strings are hardcoded in business logic.
- **Subprocess handling:** Both `subfinder` and `naabu` use `asyncio.create_subprocess_exec` (no `shell=True`). Both have explicit timeouts. Both capture and log stderr on non-zero exit. `_find_tool()` checks `settings.tools_dir` first, then PATH. `ToolMissingError` is raised with an install hint when the binary is absent.
- **Event bus drop-oldest semantics:** On queue overflow, `publish()` calls `q.get_nowait()` to discard the oldest event before enqueuing the new one. This is the desired drop-oldest behaviour, and a warning is logged.
- **Subscriber cleanup:** `subscribe()` is an async generator with a `finally` block that removes the queue from `_subscribers` regardless of how the generator exits (normal, exception, or `GeneratorExit` from client disconnect).
- **`publish()` non-blocking:** All queue operations use `put_nowait` — the publisher never suspends waiting for a slow consumer.
- **No SQL injection:** All SQL parameters are passed as tuple arguments using `?` placeholders. The only f-string in SQL is `PRAGMA user_version = {migration_version}` where the value is a Python `int` from `enumerate()`.
- **No logging of raw secrets:** Based on the available code, only `secret_preview` (first 8 characters + `…`) is stored, logged, or displayed. The full secret value is only ever seen as a SHA-256 hash.
- **User-Agent is non-default:** `http_probe` uses a realistic Chrome UA string rather than the default `python-httpx/0.x`.
- **crt.sh always runs:** Even when subfinder is missing, `_crtsh_hostnames` runs via the pre-created `asyncio.Task` and its results are yielded before the `ToolMissingError` is propagated. Passive enumeration is never completely blocked.
- **Migration pattern is forward-only:** Migrations are indexed by position in `_MIGRATIONS` and gated by `PRAGMA user_version`. Once applied, a migration is never re-applied. The rename-table-and-copy pattern correctly handles SQLite's lack of `ALTER COLUMN`.
- **Tool binary resolution from config:** `_find_tool()` in `subdomains.py` checks `settings.tools_dir / name` first, then falls back to `shutil.which`. `naabu` reuses this function via direct import. No binary paths are hardcoded.
- **HTTP timeout from settings:** `probe()` defaults to `settings.http_timeout` with the ability to override per call.
- **Migrations disable FK during table rename:** `apply_migrations()` correctly sets `PRAGMA foreign_keys = OFF` before `executescript()` (which cannot be set inside a transaction) to avoid FK cycle errors during table drops.

