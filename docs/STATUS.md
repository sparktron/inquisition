# Current Status

**Updated:** 2026-08-17 · **Branch:** `master` · **Commit:** `8a76e7a`

> Compiled from repository evidence on 2026-08-17. Nothing was built or run.

## Objective

A security scanner that connects findings rather than listing them. The stated
goal: **turn a list of findings into a connected, explained, prioritized picture
of how an attacker actually compromises the target — and prove it where safe.**

## Current state

The original roadmap (phases 0–4 plus follow-ons) is **complete**: correctness,
depth of analysis, continuous assurance, fleet/metrics/daemon, and gated active
testing all shipped. Inquisition is a robust finding *enumerator* with an
operational backbone.

Work since then is the attack-narrative transition:

| Today | Target |
|---|---|
| Findings listed by severity | Findings on an **attack graph** with reachable attacker goals |
| 8 hardcoded chains, exact-string matched | **Data-driven chain rules** plus graph traversal |
| MITRE techniques on chains only | **Every finding auto-mapped** to ATT&CK; Navigator export |
| Priority = CVSS + KEV | Priority = CVSS + KEV + **EPSS + exploit availability + reachability** |
| Static PoC text | **Safe auto-validation** of read-only PoCs — "confirmed" vs "theoretical" |
| Per-target reports | **Fleet attack graph**: cross-target pivots, blast radius |

Recent: report artifact P2 fixes, attack-graph cloud credential inference, and a
documented authorized Nuclei canary scan (all 2026-07-29).

## Active work

`master`, clean but for 1 untracked file. Attack-narrative themes A–F, each
independently shippable, ordered by leverage.

## Next

Per [`ROADMAP_ATTACK_NARRATIVE.md`](../ROADMAP_ATTACK_NARRATIVE.md) — the
current roadmap. Themes are read from there, not summarised here.

## Blockers

None identified from repository evidence.

## Known problems

Not enumerated here.
[`ROADMAP_CODE_REVIEW.md`](../ROADMAP_CODE_REVIEW.md) reviews the
attack-narrative and fleet-intelligence subsystems over 2026-06-15 → 06-29 and
carries the findings. Which remain open is **unverified**.

## Validation state

| Check | Status |
|---|---|
| Test suite, including `tests/test_dry_run_modules.py` | Present; dry-run inertness is explicitly tested. **Not run in this session.** |
| CI (GitHub Actions) | Configured; versions updated 2026-07-26. |
| Authorized Nuclei canary scan | Documented 2026-07-29. |

## Unverified

- Whether the suite passes at `8a76e7a`.
- Open findings from the code review.
- Whether every scan module currently routes through the `safety.py` gate —
  the invariant is stated and tested in part, but not audited here.

## Safety invariant

**This tool must remain read-only reconnaissance.** `safety.py` is the contract:
authorization, dry-run enforcement, read-only checks. The CLI prints a banner
stating the scan performs read-only reconnaissance, no exploit payloads, no
authentication attempts.

Adding a code path that sends payloads, guesses credentials, or mutates a target
**makes that banner a lie**. Dry-run must stay genuinely inert. See
[`AGENTS.md`](../AGENTS.md) — this is the repository's most important rule and
is restated here because a status file gets read when the instructions do not.

## Recent decisions

No `docs/decisions/` series. The roadmaps carry the reasoning.

## Deep context

**Three roadmap files exist. They are a sequence, not competing plans** —
a distinction that matters, because their names suggest otherwise:

| Document | Role | State |
|---|---|---|
| [`ROADMAP.md`](../ROADMAP.md) | Original code review + phased roadmap, phases 0–4 | **Complete.** Historical; retained. |
| [`ROADMAP_ATTACK_NARRATIVE.md`](../ROADMAP_ATTACK_NARRATIVE.md) | Successor. Themes A–F toward the attack-graph goal | **Current.** Start here. |
| [`ROADMAP_CODE_REVIEW.md`](../ROADMAP_CODE_REVIEW.md) | Point-in-time review, 2026-06-15 → 06-29, scoped to attack-narrative and fleet subsystems | Reference. |

None should be renamed or merged. Each is authoritative for its own scope.

| Topic | Document |
|---|---|
| Agent instructions and safety contract | [`AGENTS.md`](../AGENTS.md) |
| Project overview | [`README.md`](../README.md) |
