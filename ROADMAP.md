# Inquisition — Code Review & Development Roadmap

_Last updated: 2026-06-10_

This document captures a full code review of the Inquisition scanner and a
phased roadmap toward the goal: **continuously verify that your websites are as
secure as they can be, with comprehensive analysis and reporting.**

It is organized as:

1. **Architecture assessment** — what's solid, what's structurally weak.
2. **Bugs & correctness issues** — ranked, each with a fix.
3. **Coverage gaps** — what a "most secure" verdict actually requires.
4. **Roadmap** — phased, with the bug fixes folded in.

---

## 1. Architecture Assessment

**Strengths**
- Clean module pattern: every check is a `BaseModule` subclass returning
  `Finding` objects, orchestrated concurrently in `scanner.run_scan`. Easy to
  extend.
- Strong separation: `models` (data) / `modules` (collection) /
  `vuln_correlation` (enrichment) / `report` (rendering) / `ui` (presentation).
- Type-hinted throughout, `mypy --strict` configured.
- Read-only positioning is coherent and honestly scoped.
- Reporting is genuinely rich: severity grading, priority matrix, deep analysis,
  remediation guide, multi-format output.

**Structural weaknesses**
- **No tests at all.** For a security tool this is the single biggest risk —
  a false negative is a silent security hole in the user's site. Nothing
  guards against regressions in detection logic.
- **No shared HTTP layer.** `http_headers`, `tech_stack`, `app_checks` (and
  `waf_detection`/`content_discovery`) each independently `GET https://target/`.
  The homepage is fetched 4+ times per scan — wasteful, slower, and noisier to
  the target than necessary.
- **`analysis_kb.py` is 90 KB / 1537 lines of static knowledge encoded as
  Python.** This is data masquerading as code; it should live as structured
  data (YAML/JSON) loaded at runtime, which makes it testable and editable
  without touching logic.
- **Detection rules evaluate _presence_, not _quality_.** Headers are graded on
  existence; a present-but-weak CSP (`unsafe-inline`), a short HSTS `max-age`,
  or `p=none` DMARC all pass. "Most secure" requires grading the _content_ of
  controls, not just their presence.

---

## 2. Bugs & Correctness Issues

Ranked by impact. Each is actionable and folded into the roadmap below.

### B1 — Report saved with wrong extension for JSON/HTML  _(High)_
`scanner.run_scan` always names the auto-generated file `…_target.md`
regardless of `--format`. A `--format html` or `--format json` scan writes
HTML/JSON content into a `.md` file. **Fix:** derive the extension from
`config.report_format` (`.txt`/`.json`/`.html`).
_Location: `scanner.py:157`._
**Status:** Fixed 2026-06-10; default report paths now use `.txt`, `.json`,
or `.html`.

### B2 — CVE correlation is mostly inert  _(High)_
`tech_stack` emits version-less CPEs like `cpe:2.3:a:wordpress:wordpress`, but
`vuln_correlation.lookup_cves_for_cpe` queries NVD with the `cpeName`
parameter, which requires a **complete** 13-field CPE 2.3 string. Partial CPEs
return nothing, so the entire CVE feature silently produces empty results for
all but the rare fully-versioned match. **Fix:** use NVD's `virtualMatchString`
(supports partial CPEs) instead of `cpeName`, and normalize CPEs to full
13-field form. _Location: `vuln_correlation.py:64-67`._
**Status:** Fixed 2026-06-10; partial CPEs are wildcard-normalized and queried
with `virtualMatchString`.

### B3 — Port scan uses the HTTP timeout for TCP connects  _(High)_
`_probe` sets `sock.settimeout(self.config.timeout)` — default **10 s**. A deep
scan probes ~1100 ports with only `max_threads` (default 10) workers; every
filtered/dropped port blocks up to 10 s. Worst case a deep scan stalls for many
minutes. **Fix:** use a short, dedicated connect timeout (1–2 s) independent of
the per-request HTTP timeout. _Location: `port_scan.py:124`._
**Status:** Fixed 2026-06-10; `ScanConfig.connect_timeout` and
`--connect-timeout` now control TCP connects.

### B4 — Authorization prompt is dead code  _(High, policy)_
`main()` calls `run_scan(..., skip_auth=True)` unconditionally, so
`safety.prompt_authorization` never runs. For a tool whose entire premise is
"authorised targets only," the consent checkpoint is bypassed. **Fix:** gate on
an explicit `--yes`/`--i-am-authorized` flag; prompt interactively otherwise.
_Location: `inquisition.py:149`._
**Status:** Fixed 2026-06-10; live scans prompt unless `--yes` /
`--i-am-authorized` is supplied. Dry runs remain non-interactive.

### B5 — `socket.setdefaulttimeout` mutates global state from a worker thread  _(Medium)_
`dns_recon._safe_dns_resolve` calls `socket.setdefaulttimeout(timeout)`, which
sets a **process-global** default. Because modules run concurrently, this races
with socket operations in `port_scan`/`tls_analysis`. **Fix:** pass timeouts
explicitly; never mutate the global default. _Location: `dns_recon.py:54`._
**Status:** Fixed 2026-06-10; DNS resolution uses a bounded worker instead of
mutating process-global socket defaults.

### B6 — Port scan ignores `--rate-limit`  _(Medium)_
`_probe` never calls `_rate_limit()`; all ports are opened concurrently. The
documented rate limit silently doesn't apply to the noisiest module, and a deep
scan looks like a burst to an IDS. **Fix:** honor rate limiting (or document
that port scanning is exempt and why). _Location: `port_scan.py:138`._
**Status:** Fixed 2026-06-10; each port probe now enters the shared module
rate limiter before connecting.

### B7 — `_rate_limit` is not thread-safe  _(Low, latent)_
`BaseModule._last_request_time` is read/written without a lock. Currently each
module's requests are sequential so it's latent, but any future intra-module
parallelism will corrupt pacing. **Fix:** guard with a `threading.Lock`.
_Location: `modules/base.py:22-29`._
**Status:** Fixed 2026-06-10; `_rate_limit` is lock-protected.

### B8 — Wildcard SAN matching is naive  _(Low)_
`tls_analysis` builds the wildcard candidate as `*.` + everything after the
first label. For an apex target `example.com` this yields `*.com` (never valid)
and can mis-handle multi-level hostnames, producing false "hostname not in SAN"
findings. **Fix:** proper RFC 6125 wildcard matching. _Location:
`tls_analysis.py:192`._
**Status:** Fixed 2026-06-10; hostname matching now delegates to Python's TLS
hostname matcher instead of hand-rolled wildcard logic.

### B9 — Banner grab sends `\r\n` to every open port  _(Low, policy)_
The README claims "no payloads… purely read-only," but `_probe` sends `\r\n` to
every open port including non-HTTP services (databases, etc.). Benign, but
inconsistent with the stated guarantee. **Fix:** only send a probe to known
text-protocol ports, or make banner-grab opt-in. _Location: `port_scan.py:129`._
**Status:** Fixed 2026-06-10; banner collection no longer sends bytes and only
passively reads from common text protocols that speak first.

### B10 — Dedup discards scheme context  _(Low)_
`_deduplicate` keys on `(title, category, severity)`, collapsing an HTTP-only
finding and an HTTPS-only finding into one and losing which scheme was affected.
Intended for noise reduction, but the merged finding's evidence no longer says
"present on HTTP but not HTTPS." **Fix:** include scheme in evidence or key.
_Location: `scanner.py:49`._
**Status:** Fixed 2026-06-10; dedup keys include scheme context when available.

### B11 — TLS certificate analysis silently skips real certificates  _(High)_
`_get_cert_info` disables certificate verification with `CERT_NONE` and then
calls `getpeercert(binary_form=False)`. In CPython this returns an empty parsed
certificate dict for normal public certificates, while the DER bytes are still
available. The downstream `if cert:` guard then skips subject, issuer,
expiration, self-signed, and SAN checks entirely. This directly undermines the
README claims for certificate validity/expiration and hostname mismatch
detection. **Fix:** parse `peer_cert_der` with a certificate parser
(`cryptography` or OpenSSL CLI fallback) or perform a second verified handshake
for normal certs while preserving DER parsing for invalid certs.
_Location: `tls_analysis.py:17-25`, `tls_analysis.py:101-200`._
**Status:** Fixed 2026-06-10; DER certificates are decoded before validity,
SAN, hostname, and self-signed checks run.

### B12 — Installed package is likely broken  _(High)_
`ui.py` imports `rich`, but `pyproject.toml` omits `rich` from project
dependencies. The same file declares only top-level `py-modules` and explicitly
excludes the `modules` package even though `scanner.py` imports `modules`.
Running from a source checkout can work, but `pip install .` / the console
script can fail in a clean environment. **Fix:** add `rich>=13.0` to
`project.dependencies` and package the `modules` package instead of excluding
it. _Location: `pyproject.toml:10-19`, `ui.py:8-16`._
**Status:** Fixed 2026-06-10; package metadata includes `rich` and `modules*`.

### B13 — HTTP method enumeration does not actually test methods  _(Medium)_
`_METHODS_TO_TEST` is defined but unused. `_enumerate_http_methods` only trusts
the `Allow` header returned by `OPTIONS`, so servers that omit or lie in
`Allow` can still accept `TRACE`, `PUT`, or `DELETE` without being reported.
The README says the scanner "tests TRACE, PUT, DELETE, PATCH." **Fix:** either
perform explicit safe method probes under an authorization-gated mode or change
the claim to "OPTIONS Allow header inspection" and report uncertainty.
_Location: `app_checks.py:25`, `app_checks.py:286-340`, `README.md:466`._
**Status:** Fixed 2026-06-10; reports and docs now describe `OPTIONS`
Allow-header inspection and explicitly state its uncertainty.

### B14 — Default scan sends payload-like requests despite "no payloads" claim  _(Medium, policy)_
The README promises no payloads, but the default standard scan sends a crafted
CORS preflight with `Origin: https://evil.example.com`, a GraphQL introspection
`POST`, and a `\r\n` banner probe to every open port. These are non-mutating,
but they are still active probes and can surprise operators who selected the
tool because it advertises passive/read-only behavior. **Fix:** split modes
into passive, read-only-active, and active; keep the default claims aligned with
the traffic actually sent. _Location: `README.md:7`, `app_checks.py:128-140`,
`app_checks.py:225-238`, `port_scan.py:129`._
**Status:** Fixed 2026-06-10 for the documented policy mismatch; README now
calls the scanner read-only active reconnaissance and the port scanner no
longer sends banner bytes.

### B15 — Tech-stack path probing misses HTTP-only exposures  _(Medium)_
Homepage fingerprinting tries HTTPS then HTTP, but the standard/deep path probes
always use `https://{target}{path}`. If HTTPS is absent or broken while HTTP is
reachable, exposed paths like `/.env`, `/.git/HEAD`, `/server-status`, or
`/phpmyadmin/` are silently missed. **Fix:** reuse the resolved reachable base
URL from the homepage fetch, or probe both schemes with scheme-aware evidence.
_Location: `tech_stack.py:84-100`, `tech_stack.py:130-179`._
**Status:** Fixed 2026-06-10; path probing reuses the reachable homepage scheme.

### B16 — `security.txt` validation accepts expired or malformed policy files  _(Low)_
The content-discovery module only checks whether an `Expires:` line exists; it
does not parse the timestamp, verify it is in the future, validate Contact URI
syntax, or prefer the canonical `/.well-known/security.txt` location. Reports
can therefore say "security.txt present" for an expired or malformed file.
**Fix:** implement RFC 9116 field parsing with explicit findings for expired,
missing, or malformed `Expires` and `Contact` values.
_Location: `content_discovery.py:180-207`._
**Status:** Fixed 2026-06-10; `security.txt` findings now flag expired,
missing, malformed, or non-canonical policy files.

---

## 3. Coverage Gaps (toward "most secure")

Presence-only checks and read-only recon give a good _external posture_ baseline
but stop short of "absolute most secure." Gaps, grouped:

**Quality-of-control grading**
- [x] CSP analyzed for `unsafe-inline`/`unsafe-eval`/wildcard sources, not just
  presence.
- [x] HSTS `max-age` threshold + `includeSubDomains` checks.
- [x] HSTS **preload list** membership/status.
- [x] DMARC **policy strength** (`p=none` vs `quarantine`/`reject`) and SPF
  `~all`/`?all`/`+all` vs `-all`.
- [x] **DKIM** presence via common-selector probe (positive-only; absence is not
  conclusive because selectors are arbitrary).
- [x] Cookie `__Host-`/`__Secure-` prefix validation.

**TLS depth** (README says "cipher suites" but only the single negotiated cipher
is captured)
- [x] Certificate parsing that works when the certificate is untrusted, expired, or
  hostname-mismatched.
- [x] Full protocol enumeration (per-protocol) and weak-cipher-family probing;
  TLS 1.3 confirmation.
- [x] Full chain validation, Certificate Transparency (embedded SCT) presence,
  and OCSP revocation lookup (`tls_chain.py`, cryptography-backed).
- [x] Weak DH-parameter detection (Logjam-class) — forced TLS 1.2 DHE handshake
  via `openssl s_client`, grading the negotiated finite-field DH group size.

**Site coverage**
- [x] **Crawling/spidering** — crawler discovers internal URLs from homepage
  links, robots.txt, and sitemap.xml, then feeds discovered URLs into path-aware
  modules.
- [x] **Authenticated scanning** — optional auth headers/cookies are injected
  through the shared HTTP client, so read-only modules and active engines can
  inspect the logged-in surface when authorized.
- [x] Mixed-content and Subresource-Integrity checks on discovered assets.

**Active testing tier** (optional, breaks read-only positioning — gate behind a
flag)
- Integrate or shell out to **Nuclei**/**ZAP** for templated active checks
  (XSS/SQLi/SSRF/IDOR) under explicit authorization.

**Continuous assurance** (this is what "keep my sites secure" really needs)
- **Scan diffing / trend tracking** — compare against the previous scan and
  report _what changed_ (new exposures, regressions, fixes).
- **CI/CD mode** — exit non-zero when severity ≥ threshold; **SARIF** output for
  GitHub code scanning; scheduled scans.

---

## 4. Roadmap

### Phase 0 — Correctness & Trust (do first)
Goal: the tool's existing output is correct and its claims are true.
- [x] **B11** Fix TLS certificate parsing so expiration, SAN, hostname mismatch,
      and self-signed checks actually run.
- [x] **B1** Fix report file extension by format.
- [x] **B3** Dedicated short TCP connect timeout for port scan.
- [x] **B2** Fix NVD lookup to use `virtualMatchString`; normalize CPEs.
- [x] **B12** Fix packaging metadata: include `rich` and package `modules`.
- [x] **B5** Remove global `setdefaulttimeout`; pass timeouts explicitly.
- [x] **B4** Restore authorization gate behind an explicit flag.
- [x] **B13 / B14** Reconcile scan modes and README claims with the active
      traffic the tool actually sends.
- [x] **Add an initial test suite** — unittest regressions now cover report
      extensions, dedup, CVE lookup params, TLS certificate reporting,
      `security.txt`, and HTTP fallback path probing.
- [x] Broaden tests with `models`, `report` rendering, risk scoring, and
      dry-run contract checks for every module.
- [x] Add recorded HTTP/DNS/socket fixture tests for network-facing module
      behavior.
- [x] Audit remaining README claims vs implementation (cipher "suites", WAF "20+",
      content discovery) and reconcile.

### Phase 1 — Efficiency & Hygiene
- [x] **Shared HTTP layer**: one `requests.Session` + homepage-response cache
      injected into modules; eliminates 4× redundant homepage fetches.
- [x] **B6 / B7 / B9 / B10** rate-limit + thread-safety + probe-politeness +
      dedup-scheme fixes.
- [x] **B15 / B16** fix scheme-aware tech-stack path probing and stricter
      `security.txt` validation.
- [x] Move `analysis_kb.py` content to structured data, loaded at runtime;
      add a schema validator test.
- [x] **B8** Proper RFC 6125 wildcard SAN matching.

### Phase 2 — Depth of Analysis ("most secure" core)
- [x] **Header and control quality grading** — CSP/HSTS/header-value/cookie-prefix
      grading, SPF/DMARC policy strength, and DKIM presence are implemented.
      Mixed-content and SRI checks run against homepage assets and
      crawler-discovered pages.
- [x] **TLS depth** — active protocol-version enumeration (flags TLS 1.0/1.1,
      reports TLS 1.2/1.3 gaps) and weak-cipher-family acceptance probing.
      Full chain validation, Certificate Transparency (embedded SCT) presence,
      OCSP revocation lookup, and weak DH-parameter detection (Logjam-class) are
      implemented in `tls_chain.py` (backed by the `cryptography` dependency and
      an `openssl s_client` probe for the DH group size).
- [x] **Crawler** — `modules/crawler.py` discovers the internal URL surface from
      homepage links, robots.txt, and sitemap.xml (with a bounded deep-crawl one
      level further), same-origin only, and flags sensitive discovered endpoints.
- [x] **Crawler-fed module coverage** — `scanner.py` now runs crawler as a
      sequential pre-discovery pass and feeds discovered URLs into application
      asset checks, content discovery confirmations, and technology-stack
      signature checks.

### Phase 3 — Continuous Assurance (the real product)
- [x] **Scan diffing** — `diffing.py` persists a normalized snapshot per target
      (`reports/.state/`) and reports deltas (new/regressed/fixed/improved)
      against the prior scan, keyed by a stable `(category, title)` fingerprint.
- [x] **CI/CD mode** — `--fail-on <severity>` exit codes (exit 1 when a finding
      meets the threshold); **SARIF 2.1.0** output (`--format sarif`) for GitHub
      code scanning; example workflow at `examples/github-action.yml`.
- [x] **Scheduled scanning** + notification on new/regressed findings. The
      example GitHub Action covers cron scheduling; `notifications.py` posts to a
      Slack incoming webhook (formatted message) or any other URL (structured
      JSON). `--notify-on` selects the trigger: `regression` (new/worsened at or
      above `--notify-min-severity`; default), `changes` (any new/fixed/
      regressed/improved finding), or `always` (every scan — a heartbeat).
      Payloads carry a severity summary plus the fixed/improved deltas.

### Detection quality
- [x] **Graded-confidence signatures** — `models.Confidence`
      (CONFIRMED/HIGH/MEDIUM/LOW) + `combine_confidence`. `tech_stack` tags each
      body/header signature with a base confidence and corroborates agreeing
      signals per technology (`_TechAccumulator`), emitting one graded finding
      per tech. Confidence is rendered in text/JSON/HTML reports.
- [x] **Confidence across signature modules** — `waf_detection` grades and
      aggregates header/cookie/body signals per product (`_WafAccumulator`);
      `content_discovery` grades admin/route findings by status code
      (200 = CONFIRMED, 401/403 = HIGH, 301/302 = MEDIUM).

### Fleet & multi-target
- [x] **Multi-target scan mode** — the CLI accepts several positional targets
      and/or `--targets-file`; each target is scanned, diffed, and notified
      independently, a combined overview table prints at the end, `--output` acts
      as a per-target directory, and `--fail-on` trips if any target qualifies.
- [x] **Single combined fleet artifact** — `--combined-output FILE` writes one
      artifact across all targets instead of per-target files: a fleet JSON
      object with an aggregated summary (`render_json_combined`), a multi-run
      SARIF 2.1.0 file (`render_sarif_combined`), or concatenated text/HTML.
      `run_scan(write_report=False)` suppresses per-target writes in this mode.
- [x] **Concurrent multi-target execution** — `--jobs N` scans up to N targets
      in parallel (`_run_targets`). `run_scan(quiet=True)` suppresses the live
      per-scan UI so output does not interleave; a concise per-target line prints
      as each finishes and the returned order always matches the input order.

### Trend history
- [x] **Rolling N-scan trend** — `diffing.py` keeps the last `--history-size`
      scans per target (`<target>.history.json`) and `compute_trend` reports
      direction (improving/worsening/stable by a severity-weighted score) plus
      the change in total and critical+high counts, printed after each scan.
- [x] **Per-finding age** — `diffing.update_ages` stamps each finding with
      `first_seen` and `age_scans` (consecutive scans open), persisted in the
      snapshot and rendered in text/HTML/JSON ("new this scan" / "open N scans").
- [x] **Trend sparkline in HTML** — `render_html` draws an inline SVG sparkline
      of total findings across the history window with a direction label.
- [x] **History in JSON/combined artifact** — JSON reports embed the `history`
      window and a `trend` summary (carried through the combined fleet JSON).
- [x] **SLA / age-based alerting** — `--sla-max-age N` warns and notifies when a
      finding stays open beyond N consecutive scans (fires even on a quiet diff;
      adds an `sla_breaches` payload section).
- [x] **Fleet HTML dashboard** — combined HTML output (`render_fleet_dashboard`)
      renders one page ranking every target by risk with grade, counts, and a
      per-target trend sparkline.
- [x] **Age-based history pruning** — `--history-max-age-days` drops history
      entries older than the cutoff (applied before the count cap).
- [x] **Per-severity SLA thresholds** — `--sla-by-severity critical=1,high=3`
      overrides the global `--sla-max-age` per severity (0 disables a severity).
- [x] **Dashboard Δ column** — the fleet dashboard shows the change in total
      findings vs the immediately previous scan, colored up/down.
- [x] **Prometheus/OpenMetrics export** — `--metrics-output` writes scrape-able
      gauges (findings by severity, risk score, CVE/misconfig counts, oldest
      finding age, scan duration) for every target (`metrics.py`).
- [x] **Pushgateway metrics push** — `--metrics-push URL` PUTs the current gauges
      to a Prometheus Pushgateway job (`--metrics-job`), with an injectable sender.
- [x] **Fleet config file** — `--fleet-config FILE` (JSON) supplies the target
      list and per-target overrides merged over a `defaults` block over the CLI
      flags (`fleet_config.py`); example at `examples/fleet.json`.
- [x] **Historical metrics samples** — `--metrics-history` emits the findings
      trend as timestamped Prometheus samples per stored scan (file only; the
      Pushgateway rejects timestamps).

### Phase 4 — Active Testing (optional, authorization-gated)
- [x] Integrate Nuclei behind an explicit `--active` flag (`active_scan.py`)
      with a separate, louder authorization banner (`safety.confirm_active_scan`,
      requires `--yes` or typing the consent phrase). Default stays read-only;
      DoS/intrusive/fuzz/brute-force templates are excluded. Skipped in dry-run;
      missing-binary is handled gracefully.
- [x] Authenticated scanning (session/cookie injection) — `--auth-header` /
      `--auth-cookie` are injected into every HTTP request via the shared client
      (so all read-only modules see the logged-in surface) and passed to active
      engines.
- [x] Optional: ZAP engine as an alternative to Nuclei via `--active-engine zap`;
      parses ZAP baseline JSON and reports non-informational alerts as active
      findings. Missing-binary handling mirrors Nuclei.

---

### Suggested immediate next step
All planned phases and follow-ons are complete, now including the Pushgateway
push, the JSON fleet config, and historical metric samples. Candidate future
directions: environment-variable interpolation in fleet config (e.g. `${API_TOKEN}`
in auth headers); a long-running watch/daemon mode driven by the fleet config; and
YAML fleet config support alongside JSON.
