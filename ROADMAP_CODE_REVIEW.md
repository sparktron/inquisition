# Code Review & Roadmap — recent changes (2026-06-15 → 06-29)

Scope: the attack-narrative subsystem (`mitre`, `attack_graph`, `attack_rules`,
`reachability`, `provenance`, `poc_validation`, `vuln_correlation` refactor) and
the fleet-intelligence subsystem (`fleet_correlation`, `fleet_config` D1/D2),
plus the `report.py` growth and active-scan/audit/metrics changes.

**Baseline:** 358 tests + 60 subtests pass (`pytest -q`, 5.2s). Overall quality
is high — strong module docstrings, clear separation, deterministic/offline-by-
default design, good test coverage on the new logic. The items below are
refinements, not a rescue.

---

## P0 — Correctness (do first)

### 1. PoC validation over-confirms: curl exit 0 ≠ HTTP success  *(poc_validation.py)*
`PocCheck.confirming` returns `True` whenever a probe exits 0. But `curl -s`
(the form the KB emits, e.g. `curl -s https://target.com/.env`) exits **0 for
4xx/5xx** — it only fails on transport errors. A probe that hits a **404**
therefore promotes the finding to `Confidence.CONFIRMED` and `provenance.py`
labels it *"Confirmed — live PoC validation."* That is precisely the
overclaiming `provenance.py`'s own docstring warns against, and it silently
fires whenever a resource has moved/been patched between detection and the
later validation phase.

- **Fix:** inject `--fail` (`-f`) into curl probes before running, so exit 0
  means a 2xx/3xx response; or capture `-w '%{http_code}'` and gate
  `confirming` on an expected-status set. Keep `openssl`/`dig` as-is (exit code
  is meaningful for them).
- **Test:** add cases for a 404-but-exit-0 curl (must NOT confirm) and a 200
  curl (must confirm). Current tests use a fake runner returning exit 0, so the
  bug is invisible today.

---

## P1 — Robustness & maintainability

### 2. Fleet correlation couples on parsed evidence strings  *(fleet_correlation.py)*
`_target_ips` / `_target_cert_fingerprints` find siblings by regex-parsing
`f.evidence` keyed to exact titles (`"DNS A/AAAA records"`, `"Certificate
fingerprint"`) and wording (`"resolves to:"`, `"SHA-256:"`). It matches the real
`dns_recon`/`tls_analysis` output *today*, but `tests/test_fleet_correlation.py`
builds synthetic findings with the **same hardcoded strings**, so if those
modules ever reword their output, correlation breaks with the test suite still
green.

- **Fix:** have `dns_recon`/`tls_analysis` stamp structured fields
  (`finding.metadata["resolved_ips"]`, `["cert_sha256"]`) and read those;
  fall back to the regex only for legacy snapshots. At minimum, add an
  integration test that runs the real modules against a fixture and feeds their
  output into `correlate_fleet`.

### 3. `report.py` is a 2061-line monolith  *(report.py)*
`render_html` alone is ~680 lines (1122–1801); the file mixes text, markdown,
JSON, SARIF, HTML, and fleet renderers plus all scoring helpers. This is the
single biggest maintainability drag in the new code.

- **Fix:** split into a `report/` package — `text.py`, `markdown.py`,
  `serialize.py` (json+sarif), `html.py`, `fleet.py`, `scoring.py` (the
  `_risk_score`/`_SEVERITY_WEIGHTS`/grade helpers shared across renderers).
  Pure mechanical extraction; the existing tests pin behavior.

### 4. Redundant recomputation per render  *(report.py)*
`reachability.exposure_index(report)` is called 4× (lines 274, 513, 792, 1127)
and `attack_graph.build_attack_graph(report)` 2× (410, 1523) within a single
render. Both are pure; recompute once and thread the result, or memoize.
Cheap now, but it scales with finding count and invites drift between callers.

### 5. PoC classifier allowlist gaps  *(poc_validation.py)*
`_CURL_MUTATING_FLAGS` blocks `-d/-F/-T/-o` but not `-K`/`--config` (curl reads
a config file that can itself declare mutating options) and the classifier
doesn't constrain URL **scheme** (`file://`, `gopher://`). PoCs are KB-authored
(not attacker-controlled), so severity is low — but the module sells itself as
"fails closed," so close these: add `-K`/`--config` to the blocklist and require
`http(s)://` URLs.

---

## P2 — Polish & smaller cleanups  ✅ DONE (2026-06-25)

### 6. Title-convention coupling for active-scan detection  *(provenance.py, attack_graph.py)* ✅
Both detect active-scan findings via `title.startswith("[active]")` +
`FindingCategory.VULNERABILITY`. Prefer a structured signal —
`finding.metadata["active_scan"] = True` set at creation in `active_scan.py` —
and key the consumers off that.
- **Done:** `active_scan.py` stamps `metadata["active_scan"] = True` on every
  Nuclei/ZAP finding. New `models.is_active_scan_finding()` reads that flag and
  falls back to the legacy `"[active] "` title prefix for old snapshots;
  `provenance.py` and `attack_graph._active_finding_edges` both consume it.

### 7. Cosmetic: authorization banner box is misaligned  *(safety.py)* ✅
`_AUTHORIZATION_BANNER` top/divider rows are wider than the content rows, so the
right border doesn't line up. Recompute the box to a single width.
- **Done:** rebuilt the box at a uniform 68-column width (interior 66); all rows
  now align.

### 8. Micro-nits ✅
- `poc_validation._run_check`: `except (OSError, FileNotFoundError)` —
  `FileNotFoundError ⊆ OSError`, drop the redundant member. **Done.**
- `reachability.exposure_index`: `... if count else 0` is dead (buckets only
  ever hold `count >= 1`). **Done.**
- `fleet_config._coerce`: `bool(value)` mis-coerces the JSON string `"false"`
  to `True`. Accept native bools / explicit `true|false` strings and reject
  others. (YAML native booleans are fine.) **Done** via new `_coerce_bool`.

---

## P3 — Feature opportunities (net-new value)  ✅ DONE (2026-06-25)

- **Status-aware confirmation evidence.** ✅ `_harden_curl` now also injects a
  `--write-out` status sentinel; `_run_check` parses + strips it into
  `PocCheck.http_status`. Surfaced as "ran successfully (HTTP 200)" in the
  verification line, "HTTP 200" in the HTML evidence block, and `httpStatus` in
  SARIF. (`2c11f83`)
- **Fleet dashboard: confirmed-vs-modeled rollup.** ✅ `render_fleet_dashboard`
  leads with a headline callout: N confirmed (proven via active scan) / M
  modeled objectives across K targets, via `_fleet_objective_rollup`. (`02667cd`)
- **Blast-radius in the attack story.** ✅ `attack_story(report, *, fleet=...)`
  appends a cross-target pivot note built from the D2 blast-radius graph, naming
  the most valuable endangered sibling. Threaded through render_text/html;
  render_combined passes `fleet=reports`. (`3a6dacb`)
- **EPSS/KEV freshness surfaced in report header.** ✅ `_intel_freshness_summary`
  distills `intel_sources` into a one-line "intel current as of …" header in
  text/HTML/markdown, flagging stale feeds. (`01548bd`)

---

## Suggested order

1. P0 #1 (correctness — affects the integrity of every confirmed finding).
2. P1 #2 and #5 (robustness of the two newest subsystems).
3. P1 #3/#4 (report.py split + dedupe — unblocks faster future work).
4. P2 cleanups (batch into one commit).
5. P3 features as capacity allows.

**Status:** Original P0–P3 items are complete, with 388 unit tests passing.

---

## Two-week review addendum — 2026-06-29

Scope: all code changes committed from 2026-06-15 through 2026-06-29. The
review covered the crawler URL handoff, TLS chain/DH work, fleet execution,
watch mode, metrics/audit logging, active-scan integration, PoC validation,
attack-narrative intelligence, report package split, and the P2/P3 polish pass.

**Status: all three confirmed findings resolved 2026-06-29** (commits
`2e3291a`, `641402c`, `be34adf`). 394 unit tests pass and `mypy --strict`
is clean.

### Confirmed findings

#### P1 — `mypy --strict` fails on new test helpers _(Fixed 2026-06-29)_
`python -m mypy .` currently fails with 11 `no-untyped-def` errors in:

- `tests/test_poc_validation.py`
- `tests/test_mitre.py`
- `tests/test_attack_rules.py`
- `tests/test_active_scan.py`

The errors are limited to test helper functions/fake runners, but they make the
documented strict type-checking gate red.

**Fix plan:** add precise helper and fake-runner annotations without weakening
`pyproject.toml` strictness. Prefer small local protocols or `Callable[..., Any]`
where runner signatures intentionally vary.

**Regression check:** `python -m mypy .`.

**Resolution:** added precise annotations to the fake runners and finding
factories in all four test modules; no `pyproject.toml` strictness was
weakened. `mypy --strict` is clean.

#### P1 — Negative SLA thresholds are accepted and silently disable enforcement _(Fixed 2026-06-29)_
The CLI parser accepts values like `--sla-by-severity high=-1` because it strips
`-` before the numeric check. Fleet config also coerces `sla_max_age` and
`sla_by_severity` values with `int(...)` and does not reject negatives. In
`notifications.sla_breaches`, thresholds `<= 0` disable the SLA, so a negative
typo suppresses alerts instead of failing fast.

**Fix plan:** reject negative SLA values in `_parse_sla_overrides`,
`fleet_config._coerce_sla`, and `fleet_config._coerce` for `sla_max_age`.
Keep `0` as the documented "disabled" value.

**Regression check:** add CLI and fleet-config tests for negative values, then
run `python -m unittest discover -s tests -v`.

**Resolution:** negatives are now rejected in `_parse_sla_overrides`, the
`--sla-max-age` handler, and the fleet-config coercers (`_coerce`,
`_coerce_sla`); `0` remains the documented "disabled" value. CLI and
fleet-config regression tests cover the negative and zero cases.

#### P2 — Test suite leaks file/socket resources under the standard unittest run _(Fixed 2026-06-29)_
The full unit suite passes, but `tests/test_audit.py` leaves several opened
audit-log file handles unclosed and `tests/test_metrics_server.py` only
schedules `server.shutdown`. `ThreadingHTTPServer` sockets remain unclosed and
the suite produces `ResourceWarning` output during `python -m unittest discover
-s tests -v`.

**Fix plan:** use context managers for audit-log reads and add
`server.server_close` as cleanup after shutdown, or use a single cleanup helper
that calls both in order.

**Regression check:** rerun `python -m unittest discover -s tests -v` and verify
the file/socket warnings are gone.

**Resolution:** audit-log reads use `with` blocks, and the metrics-server
test cleanup now calls `server.shutdown()` then `server.server_close()`.

### Execution order _(completed 2026-06-29)_

1. [x] Fix the `mypy` failures first so the repo's strict static gate is
   reliable again.
2. [x] Tighten SLA validation next because it affects watch/notification
   behavior.
3. [x] Clean up test file/socket resources so the unit suite is warning-clean.
4. [x] Re-run the full validation path: `python -m unittest discover -s tests
   -v`, `python -m mypy .`, `python -m compileall -q .`, then remove generated
   `__pycache__` directories.

---

## Repository-wide review addendum — 2026-07-12

Scope: all Python source, tests, package metadata, container/deployment files,
examples, and operator documentation at `5c560b7`. This is a review and plan;
runtime behavior was not changed. Findings below were reproduced locally where
possible rather than inferred from style alone.

### Current validation baseline

- `python -m pytest -q`: **423 passed, 60 subtests passed**.
- `python -m mypy .`: **clean across 73 source files**.
- `python -m compileall -q .`: **clean**.
- `python -m pip wheel . --no-deps`: **wheel built**, and inspection confirmed
  the top-level modules, `modules` package/data, and `report` package are present.
- `ruff check .`: **23 findings** (unused imports/variables, import ordering,
  redundant f-strings, and ambiguous test variable names). These are not runtime
  failures, but the documented lint gate is not currently green.

Passing tests do not cover the boundary cases below.

### P0 — Restore the PoC validator's fail-closed boundary

#### Compact curl flags and OpenSSL output options can execute writes

**Status: fixed 2026-07-12.** Curl compact/body/upload/config/output forms and
OpenSSL output-writing forms are rejected before execution.

`poc_validation._classify_curl` recognizes separated flags (`-X POST`, `-d
value`, `-o file`) and GNU `--flag=value` forms, but not compact short-option
forms. The following all currently return `(True, "")` from
`classify_command`: `curl -XPOST ...`, `curl -dvalue ...`, `curl -Fname=value
...`, `curl -Tfile ...`, `curl -Kconfig ...`, and `curl -ofile ...`. Those can
send mutating requests, upload/read local files, or write output. The OpenSSL
subcommand allowlist also accepts output-writing forms such as `openssl x509
-in cert.pem -out /tmp/copied.pem`.

**Fix plan:** parse curl short-option clusters and attached values explicitly,
reject every body/upload/config/output option in both attached and separated
forms, require at least one HTTP(S) URL, and reduce OpenSSL validation to
operation/flag combinations proven not to write. Prefer a declarative option
schema over prefix matching. Keep `shell=False` and the metacharacter block.

**Regression checks:** add table-driven tests for every compact and separated
form, safe lookalikes, missing URLs, and OpenSSL `-out`/file-writing options;
assert rejected commands never reach the fake runner. Run the focused PoC tests
before the full suite.

**Resolution:** curl short-option clusters and attached values are parsed, with
body/upload/config/output and persistent cookie/header/trace output rejected.
Every executable curl command must also contain an explicit HTTP(S) URL.
OpenSSL file, key-log, session, message, OCSP request/response, random-state,
and CA serial create/update options are rejected across the allowed inspection
subcommands. Safe compact curl methods and read-only OpenSSL options have
positive regression coverage; rejected commands are verified never to reach
the subprocess runner.

### P1 — Enforce network and credential boundaries

#### Crawler follows out-of-origin sitemap URLs

**Status: fixed 2026-07-12.** Sitemap documents and nested indexes are fetched
only when their normalized scheme, hostname, and effective port match the
resolved target origin. Traversal is capped at 20 sitemap documents and two
nested-index levels.

`CrawlerModule` filters discovered page results to the target origin, but
`_collect_from_sitemaps` fetches `Sitemap:` URLs from `robots.txt` and nested
sitemap-index `<loc>` values before applying an origin check. A target can
therefore make the scanner contact an unrelated or internal HTTP(S) host,
contradicting the module's same-origin contract.

**Fix plan:** normalize the configured target origin once; reject sitemap URLs
whose scheme/hostname/effective port differ before enqueue or fetch; cap nested
sitemap count/depth as well as discovered URL count. Add fixture tests proving
external robots and nested-index URLs are never requested.

#### Custom auth headers survive cross-origin redirects

**Status: fixed 2026-07-12.** The shared client now follows at most ten
redirects itself, retains configured credentials on same-origin hops, and
permanently strips every configured credential header after an origin change.
Session access is serialized while the response cache remains independently
locked.

The shared `HttpClient` passes arbitrary configured auth headers to
`requests.Session` with redirects enabled. Requests strips `Authorization` and
`Cookie` on relevant redirects, but a custom credential header such as
`X-API-Key` remains on a redirect to another host. This can disclose credentials
to a target-controlled redirect destination. A single `Session` is also shared
across concurrently running modules, although Requests does not promise
thread-safe session mutation.

**Fix plan:** implement bounded redirect handling in `HttpClient`, forwarding
configured auth material only when the next hop has the same normalized origin;
use per-thread sessions or serialize session access while retaining a shared,
thread-safe response cache. Add two-local-server regression tests for same-origin
retention and cross-origin stripping of every configured secret header.

### P1 — Fail cleanly on untrusted parser/config input

#### Malformed scanner/API output can abort work

**Status: fixed 2026-07-12.** Nuclei and ZAP retain valid findings while
returning concise warnings for malformed records. GraphQL introspection accepts
`data: null`, filters malformed schema members, and reports an indeterminate
shape without erasing earlier module findings. NVD, CISA KEV, and EPSS validate
container and record shapes and skip only invalid entries.

- `active_scan.parse_nuclei_output('{"info":"bad"}')` raises `AttributeError`;
  `run_active_scan` does not contain parser exceptions, so malformed/truncated
  tool output can abort the whole scan.
- `AppChecksModule._graphql_introspection` raises `AttributeError` for the valid
  JSON shape `{"data": null}` and assumes every schema type is a mapping with a
  string `name`. The module wrapper catches the eventual exception but discards
  all findings accumulated by that module.
- NVD/CISA/EPSS parsing has similar nested-shape assumptions; bad upstream data
  can turn enrichment into an error or incomplete report.

**Fix plan:** validate mapping/list/scalar shapes at every external-data boundary,
skip only malformed records, and return a concise parser error alongside valid
results. Add malformed, partial, and mixed-validity fixtures for Nuclei, ZAP,
GraphQL, NVD, CISA, and EPSS.

#### Fleet and CLI numeric validation is incomplete

**Status: fixed 2026-07-12.** Fleet and CLI paths now share typed finite-number,
port, and range validators. Fleet failures are consistently surfaced as
`FleetConfigError`; CLI failures are argparse errors. Jobs, threads, and history
size require at least one, ports require `1..65535`, and every zero-as-disabled
field has explicit documentation and coverage.

Fleet values such as `timeout: "oops"` and `max_threads: null` escape as raw
`ValueError`/`TypeError`, while the CLI catches only `FleetConfigError`.
`ports: [0, 70000]` is accepted, and CLI/fleet options such as history size,
jobs, audit limits, and ports do not share one range validator. Bad input can
produce a traceback, silently disable behavior, or cause an entire module to
fail after valid work was scheduled.

**Fix plan:** centralize `ScanConfig` validation/coercion, convert all type/range
failures to actionable `FleetConfigError`/argparse errors, validate ports in
`1..65535`, and define explicit semantics for zero on jobs/history/audit options.
Run the same validator for CLI and fleet-derived configs. Add boundary tests for
every numeric field.

### P1 — Make DNS results truthful and time-bounded

**Status: fixed 2026-07-12.** A, AAAA, and PTR resolution now use dnspython's
bounded lifetime instead of an uncancellable executor around `getaddrinfo`.
DMARC NXDOMAIN/NoAnswer is reported as absent, while timeouts and resolver
failures produce an informational inconclusive result rather than a false
medium-severity finding.

`_safe_dns_resolve` times out `future.result`, but `socket.getaddrinfo` continues
in a non-daemon executor thread after `shutdown(wait=False)`; repeated DNS
timeouts can accumulate blocked threads and delay process exit. Separately, the
DMARC lookup catches every exception and reports "Missing DMARC record", so a
timeout or resolver outage becomes a medium-severity false positive.

**Fix plan:** use dnspython's bounded resolver consistently for hostname/DNS
queries (or another cancellable process boundary), distinguish NXDOMAIN/NoAnswer
from timeout/NoNameservers, and emit an error/unknown result for transient
failures. Add timeout and resolver-outage regression fixtures and a thread-count
or prompt-exit test.

### P2 — Streamline execution and preserve evidence

- NVD correlation sleeps six seconds before the first request and enriches each
  CPE's records separately. Track the last NVD request time so only subsequent
  calls wait, collect all CVEs first, then batch EPSS/exploitability enrichment
  once per scan. Preserve public API rate limits. **Fixed 2026-07-12:** a
  lock-protected monotonic request slot makes the first call immediate and spaces
  later calls, while the scanner defers exploitability enrichment until all CPE
  results have been collected.
- Active Nuclei results are deduplicated by display title, so distinct templates
  or endpoints with the same name are silently reduced to the first match.
  Deduplicate on template ID plus matched endpoint (or aggregate endpoints and
  retain the worst severity/evidence). **Fixed 2026-07-12:** exact
  template/endpoint duplicates collapse, while distinct matches carry structured
  IDs/endpoints through the scanner-wide deduplication pass.
- The default HTML file is mostly portable but loads Mermaid from jsDelivr for
  attack graphs. Vendor/embed the renderer, pre-render the graph, or provide an
  offline fallback; documentation now states the dependency explicitly.

### P2 — Make quality and performance gates honest

1. Fix the 23 current Ruff findings with focused edits and add an explicit Ruff
   configuration matching repository conventions.
2. Add `ruff check .` and wheel installation/import smoke tests to CI; keep
   pytest, strict mypy, and compileall as required gates.
3. Immediate example/docs drift was corrected during this review: the
   Prometheus risk-weight comment now matches critical=40, high=15, medium=5,
   low=1; the README exposes the current safety/offline limitations; and the
   main roadmap labels its testless opening assessment as historical. Keep
   documentation reconciliation in the gate whenever behavior changes.
4. Add security-boundary integration tests: redirect credential stripping,
   same-origin crawling, malformed external payloads, and validator command
   matrices. These are higher value than increasing happy-path test count.

### Recommended execution order

1. [x] Close the PoC classifier bypasses and verify the regression matrix.
2. [x] Enforce same-origin sitemap fetching and redirect credential stripping.
3. [x] Harden Nuclei/GraphQL/threat-intel parsers so one malformed record cannot
   abort a scan or erase a module's valid findings.
4. [x] Centralize CLI/fleet validation and reject invalid ranges consistently.
5. [x] Replace the DNS timeout shim and distinguish absence from lookup failure.
6. [x] Batch/throttle threat-intel work and preserve distinct active-scan
   evidence.
7. [ ] Clear Ruff, add package/security smoke gates, and finish documentation
   reconciliation.
