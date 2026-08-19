# AGENTS.md

Guidance for coding agents working in this repository. Single source of truth;
`CLAUDE.md` imports it.

## What this is

Inquisition — an attack-surface reconnaissance and vulnerability-correlation
scanner. Python 3.12, flat module layout at the repo root (no `src/`, no
package directory). Ships as a Docker image to GHCR.

## Layout

Modules live at the repo root and import each other by bare name
(`from models import ScanConfig`). Keep that convention — there is no package
prefix.

| Module | Role |
|---|---|
| `inquisition.py` | CLI entry point |
| `scanner.py`, `active_scan.py` | Scan execution |
| `safety.py` | **Authorization gate, dry-run enforcement, read-only checks** |
| `models.py` | Core data models |
| `attack_graph.py`, `attack_rules.py`, `reachability.py` | Attack-path modeling |
| `vuln_correlation.py`, `fleet_correlation.py` | Finding correlation |
| `mitre.py` | MITRE ATT&CK mapping |
| `tls_chain.py` | TLS chain inspection |
| `metrics.py`, `metrics_server.py` | Prometheus metrics |
| `notifications.py` | Alert dispatch |
| `provenance.py`, `diffing.py`, `audit.py` | Result history and change tracking |
| `fleet_config.py`, `config_validation.py` | Multi-host config |
| `poc_validation.py` | PoC verification |

`examples/` holds runnable integration artifacts: `docker-compose.yml`,
`fleet.{json,yaml}`, `prometheus.yml`, `grafana-dashboard.json`,
`inquisition.rules.yml`, `github-action.yml`. These are user-facing — if you
change a config schema, update the matching example in the same commit.

## Commands

```bash
python -m pytest -q
python -m mypy .
python -m compileall -q .
ruff check .
```

All four run in `.github/workflows/ci.yml` on Python **3.12**. mypy is
blocking here — unlike some of the other repos, a type error fails CI.

`docker-publish.yml` pushes to `ghcr.io/sparktron/inquisition`.

## Safety — read before touching scan code

`safety.py` exists to enforce that this tool stays read-only reconnaissance.
Its module docstring is the contract: *authorization, dry-run enforcement,
read-only checks*. The CLI prints an authorization banner stating that the
scan performs **read-only reconnaissance, no exploit payloads, no
authentication attempts**.

Rules:

- Do not add code that sends exploit payloads, attempts credential guessing, or
  performs any write/mutate operation against a target. That would make the
  banner a lie.
- Any new scan module must route through the `safety.py` gate. Do not add a
  code path that reaches the network before authorization is confirmed.
- Dry-run must stay genuinely inert. If you add a network call, verify it is
  suppressed under dry-run — `tests/test_dry_run_modules.py` exists for this.
- Treat all scan targets and all parsed responses as untrusted input.

If a change would broaden what the tool does to a target, stop and ask rather
than implementing it.

## Where to find deeper context

| Topic | Document |
|---|---|
| Current state | [`docs/STATUS.md`](docs/STATUS.md) |
| Current roadmap | [`ROADMAP_ATTACK_NARRATIVE.md`](ROADMAP_ATTACK_NARRATIVE.md) |
| Original roadmap (phases 0–4, complete) | [`ROADMAP.md`](ROADMAP.md) |
| Code review, 2026-06-15 → 06-29 | [`ROADMAP_CODE_REVIEW.md`](ROADMAP_CODE_REVIEW.md) |

The three roadmap files are a **sequence, not competing plans**: `ROADMAP.md` is
complete and historical, `ROADMAP_ATTACK_NARRATIVE.md` is current, and
`ROADMAP_CODE_REVIEW.md` is a point-in-time review. Do not merge or rename them.
