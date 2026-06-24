# Inquisition — Attack-Narrative Roadmap

_Created: 2026-06-23_

The original `ROADMAP.md` (phases 0–4 + follow-ons) is **complete**: correctness,
depth of analysis, continuous assurance, fleet/metrics/daemon, and gated active
testing all shipped. Inquisition is now a robust *finding enumerator* with a
strong operational backbone.

This roadmap takes the next step toward a single goal:

> **Turn a list of findings into a connected, explained, prioritized picture of
> how an attacker actually compromises the target — and prove it where safe.**

It is organized into six themes (A–F), each independently shippable, ordered by
leverage. Quick wins and tech-debt items are called out inline.

---

## Where we are vs. where this goes

| Today | After this roadmap |
|---|---|
| Findings listed by severity | Findings placed on an **attack graph** with reachable attacker goals |
| 8 hardcoded attack chains, exact-string matched | **Data-driven chain rules** + graph traversal that discovers novel paths |
| MITRE techniques only on chains | **Every finding auto-mapped** to ATT&CK; Navigator layer export |
| Priority = CVSS + KEV | Priority = CVSS + KEV + **EPSS + exploit availability + reachability** |
| Static PoC text per finding | **Safe auto-validation** of read-only PoCs → "confirmed" vs "theoretical" |
| Per-target reports | **Fleet attack graph**: cross-target pivots, blast radius, crown jewels |

---

## Theme A — Exploitability & Prioritization Intelligence
*"Which of these actually matter?"* — the precondition for a holistic view.

**A1. EPSS enrichment** _(quick win)_
Add FIRST.org EPSS lookup alongside the existing KEV check in
`vuln_correlation.py`. Each `CVERecord` gains `epss_score` / `epss_percentile`.
Sort and color CVEs by *probability of exploitation in the wild*, not just CVSS.
KEV (is exploited) + EPSS (will be) + CVSS (how bad) is the industry-standard
triad. Cache per-process like `_load_cisa_kev`.

**A2. Exploit-availability signal**
Enrich each CVE with whether a public exploit exists: Nuclei template present,
Metasploit module, Exploit-DB entry, public GitHub PoC. Even a boolean
`exploit_public: bool` + source link massively sharpens triage. Start with the
cheapest source (Nuclei template id ↔ CVE map, already adjacent to
`active_scan.py`).

**A3. Exposure / attack-surface index**
A per-target scalar (0–100) summarizing reachable attack surface: open risky
ports, unauthenticated services, exposed admin panels, weak TLS, missing
controls. Distinct from the existing risk *score* (which weights finding
severity) — this measures *how much door is open*. Feeds the fleet dashboard
ranking and Prometheus (`metrics.py`).

**A4. Reachability / precondition modeling**
Tag each finding with what an attacker needs to use it (`network_position`,
`auth_required`, `user_interaction`, `preconditions: [...]`). This is the data
substrate Theme B's graph consumes. Without it, "critical" findings that require
implausible preconditions over-rank, and cheap chainable findings under-rank.

---

## Theme B — Dynamic Attack-Graph Engine
*"How are they carried out?"* — the core of the holistic view.

**B1. Replace exact-string chain matching with a predicate DSL** _(tech debt + feature)_
`detect_attack_chains` (`vuln_correlation.py:607`) matches `required_misconfig_names`
by exact string — brittle and unmaintainable. Replace with declarative
conditions over finding *attributes* (category, severity, tags, CVE id, port,
confidence). Chains become data, not coupled to display strings.

**B2. Externalize attacker knowledge to versioned YAML** _(tech debt)_
`analysis_kb.py` was already moved to structured data; do the same for the
attacker intel still hardcoded in `vuln_correlation.py`: `attack_scenario`,
`poc_command`, and the `_ATTACK_CHAINS` list. One `data/attacks/*.yaml` set,
schema-validated by a test. Lets the KB grow without touching logic and makes it
auditable.

**B3. True attack-graph construction**
Model attacker **states** as nodes (`unauthenticated-remote`, `on-path`,
`credentials-obtained`, `code-execution`, `db-access`, `cloud-account`,
`lateral-pivot`) and **findings as edges** that enable transitions between them.
Then traverse from the attacker's start state to high-value goal states.

This generalizes the 8 hardcoded chains into emergent paths: e.g. *exposed `.env`*
→ creds → *cloud account* → *S3 dump* is discovered by traversal, and so are
combinations nobody hand-wrote. Output: the set of reachable goals + the
shortest/most-likely path to each.

**B4. Auto-map every finding to MITRE ATT&CK**
Today only chains carry `mitre_techniques`. Attach tactic/technique IDs to each
finding category (data table). Enables a per-scan **ATT&CK coverage matrix** and
the Navigator export in C2.

---

## Theme C — Visualization & Holistic Reporting
*"Let me see the whole picture at a glance."*

**C1. Attack-graph diagram in the HTML report**
Render the Theme-B graph as Mermaid/Graphviz embedded in the existing
`render_html` (`report.py`): nodes = attacker states, edges labeled with the
enabling finding, goal states highlighted. This is the single highest-impact
"holistic view" deliverable — one diagram showing every way in and where it leads.

**C2. MITRE ATT&CK Navigator layer export** _(quick win once B4 lands)_
Emit a Navigator `layer.json` (`--format attack-navigator` or a side artifact)
so findings overlay on the standard ATT&CK matrix — instantly legible to any
blue/red team.

**C3. "Executive attack story" narrative**
Auto-generate prose describing the *single most dangerous reachable path*
end-to-end ("An unauthenticated attacker on the network can… then… resulting
in…"), stitched from the graph + per-finding `attack_scenario`. Optional
LLM-assisted phrasing behind a flag, with a deterministic template fallback so
the tool stays offline-capable.

**C4. Interactive HTML report**
Make the (currently static) HTML filterable by tactic, severity, exploitability,
and confidence; collapsible attack narratives; "show only confirmed-exploitable."
Turns a long scroll into an explorable model.

---

## Theme D — Fleet-Level Attack Paths
*"How does one weak host endanger the rest?"* — leverages the existing fleet mode.

**D1. Cross-target correlation**
The fleet already scans many targets (`fleet_config.py`, `_run_targets`). Connect
them: a subdomain-takeover on `dev.target.com` that bypasses CSP on
`www.target.com`; shared TLS certs / shared origin IPs / trust relationships;
one compromised host as a pivot. Produce an **org-level attack graph** spanning
targets, not just per-target graphs.

**D2. Blast-radius & crown-jewel analysis**
Let users tag targets by value (in `fleet_config.yaml`); compute which low-value
exposures provide paths to high-value assets. Rank remediation by *blast radius
reduced*, not just local severity. Surface in `render_fleet_dashboard`.

---

## Theme E — Validation & Evidence (prove "how it's carried out", safely)
*"Don't just claim it — show it."*

**E1. Safe PoC auto-validation harness**
Many existing `poc_command` entries are **read-only and safe to run**
(`curl -sI`, `dig`, `openssl s_client`, status-code probes). Add a gated runner
that executes only the verification-class steps, captures output as evidence, and
upgrades a finding from *theoretical* to **confirmed exploitable**. Reuse the
existing authorization gating (`safety.confirm_active_scan`) and the
`active_scan.py` injectable-runner pattern for testability. Mutating PoCs stay
display-only.

**E2. Evidence bundles**
Attach the captured request/response (or command output) to each confirmed
finding; include in JSON/HTML reports and SARIF. Makes findings auditable and
defensible — the difference between "you might have X" and "here is X."

**E3. Link active-scan results into chains**
When `--active` runs Nuclei/ZAP, feed confirmed vulns (XSS/SQLi/etc.) back into
the Theme-B graph as *confirmed* edges, elevating any chain they complete (e.g.
confirmed XSS + no-HttpOnly cookie → confirmed account-takeover path).

---

## Theme F — Knowledge & Data Freshness
*Keep the intelligence current and trustworthy.*

**F1. Threat-intel auto-refresh + provenance**
KEV, EPSS, exploit-availability, and Nuclei templates should self-update on a
cadence with timestamps shown in reports ("KEV catalog as of …"). Stale intel in
a security tool is a silent false-negative.

**F2. Confidence + provenance on attacker claims**
Every attack-scenario/chain assertion should carry where it came from (KB rule
id, live validation, active scan) so readers can distinguish *modeled* from
*confirmed*. Pairs with E2.

---

## Suggested sequencing

1. **A1 + A2 (EPSS + exploit availability)** — small, high-signal, immediately
   improves prioritization. *(quick wins)*
2. **B4 + C2 (per-finding ATT&CK + Navigator export)** — mostly a data table plus
   a serializer; big legibility payoff.
3. **B1 + B2 (predicate DSL + externalized YAML KB)** — pays down the brittlest
   tech debt and unblocks everything in B/C.
4. **B3 + C1 (attack graph + diagram)** — the centerpiece holistic view.
5. **A3/A4, C3/C4** — round out scoring and the report experience.
6. **E1–E3 (validation & evidence)** — turn the model into proof.
7. **D1/D2 (fleet attack paths)** and **F1/F2 (freshness)** — scale and trust.

## Definition of done for the theme
A user runs one scan and gets: a ranked list of *reachable* attacker goals, an
attack-graph diagram of how each is reached, every step mapped to ATT&CK and
scored by real-world exploit probability, the most dangerous path narrated in
plain English, and — where safe — evidence that the path actually works.
