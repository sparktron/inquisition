# Code Review & Roadmap — last 10 days (2026-06-15 → 06-25)

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

**Status: ALL items P0–P3 complete.** 388 tests pass, mypy clean.
