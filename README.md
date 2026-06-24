# Inquisition

[![Publish image](https://github.com/sparktron/inquisition/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/sparktron/inquisition/actions/workflows/docker-publish.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Image on GHCR](https://img.shields.io/badge/ghcr.io-inquisition-blue)](https://github.com/sparktron/inquisition/pkgs/container/inquisition)

**A comprehensive, read-only security reconnaissance scanner for identifying misconfigurations, exposed services, and known vulnerabilities on authorised targets.**

Inquisition probes your target across DNS, network, TLS, HTTP, and application layers — then generates a detailed analysis of every issue found, explaining *why* it matters, *how an attacker would exploit it*, and *exactly how* to fix it. Reports include risk scoring, remediation priority matrices, deep-dive guidance with platform-specific configuration examples, MITRE ATT&CK technique mappings, proof-of-concept attacker commands, and attack chain visualisations.

**Read-only active reconnaissance by design.** No exploit payloads, authentication bypasses, injection attacks, login attempts, or data-modifying requests are sent. Inquisition does send non-mutating reconnaissance probes such as DNS lookups, TCP connects, HTTP `GET`/`OPTIONS`, CORS preflights, and GraphQL introspection checks, so only scan targets you are authorized to assess.

> **Current review status:** Inquisition is a useful external reconnaissance baseline, but it is not yet a complete "all clear" security assurance tool. A June 2026 code review fixed the first correctness issues and tracks remaining coverage gaps in [ROADMAP.md](ROADMAP.md). Do not rely on reports alone for production security sign-off.

## Key Features

### Reconnaissance & Fingerprinting
- **DNS reconnaissance** — A/AAAA resolution, reverse DNS, subdomain enumeration, MX/NS/TXT records, SPF/DMARC presence and policy-strength checks, **DNS zone transfer (AXFR) detection**
- **Port scanning** — TCP connect-scan with banner grabbing; enhanced service detection for Telnet, SMB, VNC, Redis, Elasticsearch, MongoDB, MySQL, PostgreSQL, RDP
- **TLS/SSL analysis** — negotiated protocol/cipher, active protocol-version and weak-cipher-family enumeration, weak Diffie-Hellman (Logjam) parameter detection, certificate validity/expiration, self-signed detection, hostname mismatch, full chain validation, Certificate Transparency (embedded SCT) presence, and OCSP revocation lookup
- **WAF/CDN detection** — Signature-based detection for common protective layers including Cloudflare, AWS CloudFront, Akamai, Fastly, Imperva, and Sucuri
- **Crawler-fed analysis** — Homepage, robots.txt, and sitemap.xml URL discovery feeds application, content, and technology checks
- **Technology stack detection** — WordPress, Joomla, Drupal, Laravel, Django, PHP, nginx, Apache, IIS, Node.js, and more via body/header signatures, path probing, and discovered pages

### Security Headers & Application Layer
- **HTTP header audit** — HSTS policy and preload status, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, **SameSite cookie validation**, information disclosure headers
- **Application checks** — CORS misconfiguration, XSS-Protection disabled, mixed content, missing Subresource Integrity, **GraphQL introspection**, **HTTP method Allow-header inspection**, debug endpoints, exposed API docs
- **Content discovery** — **security.txt validation (RFC 9116)**, **robots.txt path leakage**, admin panels (Kibana, Grafana, Jenkins, Jupyter, Portainer, etc.), backup files, sensitive configs (`.env`, `docker-compose.yml`, `.htpasswd`)

### Vulnerability Analysis
- **CVE correlation** — CPE-based lookup against the National Vulnerability Database (NVD) with CVSS scoring, days-since-disclosure, CISA KEV flag, and references
- **Subdomain takeover detection** — Identifies dangling CNAMEs pointing to unclaimed Heroku apps, GitHub Pages, S3 buckets, etc.
- **Misconfiguration detection** — 30+ pattern-matched rules for common security weaknesses (expired certs, legacy TLS, missing HSTS, exposed credentials, etc.)
- **Attack chain detection** — Automatically derives multi-step kill chains from the combination of misconfigurations detected

### Reporting & Analysis
- **Deep issue analysis** — Multi-paragraph explanations of what each vulnerability is, why it's dangerous, named CVE references, and real-world attack scenarios
- **Attack scenarios** — Step-by-step attacker narratives for every finding and misconfiguration (e.g. sslstrip on a shared network, session token harvesting after HSTS bypass)
- **MITRE ATT&CK mapping** — Every finding is tagged with relevant technique IDs (e.g. T1557, T1040) linking directly to the ATT&CK knowledge base
- **Proof-of-concept commands** — Illustrative attacker commands (Bettercap, Nmap, Metasploit, sqlmap, etc.) show what exploitation looks like in practice
- **Exploitability timeline** — CVEs display days-since-disclosure and a `⚠ KEV` badge when CISA has confirmed active exploitation in the wild
- **Consequence ladder** — Plain-language table maps your security grade to real-world outcomes (data exfiltration, account takeover, full compromise)
- **Attack chain visualisation** — HTML reports render inline SVG flowcharts for each detected multi-step kill chain
- **Remediation guidance** — Step-by-step fix instructions with platform-specific examples (nginx, Apache, IIS, Docker, Kubernetes, AWS, Azure)
- **Risk scoring & grading** — Weighted numeric score (0–∞) and security grade (A+ to F) derived from all findings
- **Priority matrix** — Ranked table of CRITICAL/HIGH/MEDIUM findings sorted by severity (or exploitability in `--attacker-pov` mode)
- **Finding deduplication** — Overlapping probes automatically collapsed to eliminate noise
- **Text, Markdown, JSON, SARIF, and HTML output** — HTML reports are self-contained with collapsible attack scenario / PoC panels and inline SVG chain diagrams

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Container & Deployment](#container--deployment)
5. [Report Structure](#report-structure)
6. [Modules Reference](#modules-reference)
7. [Misconfiguration Rules](#misconfiguration-rules)
8. [Active Testing](#active-testing-1)
9. [Examples](#examples)
10. [Legal & Safety](#legal--safety)
11. [License](#license)

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/sparktron/inquisition.git
cd inquisition
pip install -r requirements.txt

# Run a standard scan
python inquisition.py example.com

# Full deep scan
python inquisition.py example.com --depth deep

# Save HTML report
python inquisition.py example.com -o report.html
```

Or pull the pre-built container image:

```bash
docker pull ghcr.io/sparktron/inquisition:latest
docker run --rm ghcr.io/sparktron/inquisition example.com --depth quick
```

---

## Installation

### Requirements

- **Python 3.10+** (type hints, match statements)
- **pip** (package installer)
- Optional: **dnspython** (for advanced DNS queries like zone transfer attempts; installed by requirements.txt)

### Setup

```bash
git clone https://github.com/sparktron/inquisition.git
cd inquisition
pip install -r requirements.txt

python inquisition.py example.com
```

**Note:** The source checkout can be run directly with `python inquisition.py`. When installed with `pip install .`, the `inquisition` console script is also available.

```bash
inquisition example.com
```

---

## Usage

### Basic Invocation

```bash
python inquisition.py <target> [options]
```

The **target** is a hostname or IP address (`example.com`, `93.184.216.34`, `internal.company.local`, etc.).

**Important:** Ensure you have authorization to scan the target before running this tool, as it will begin reconnaissance immediately upon execution.

### Common Examples

```bash
# 1. Standard scan
python inquisition.py example.com

# 2. Full deep assessment
python inquisition.py example.com --depth deep

# 3. Quick reconnaissance only
python inquisition.py example.com --depth quick

# 4. Save HTML report for stakeholder review
python inquisition.py example.com -o report.html

# 5. Brief text report (no remediation steps) to stdout
python inquisition.py example.com --brief

# 5a. Attacker's-eye-view — findings ordered by exploitability, PoC commands highlighted
python inquisition.py example.com --attacker-pov -o report.html

# 6. Internal hostname on custom port (standard scan)
python inquisition.py internal.company.local --depth standard

# 7. Dry run (preview without sending traffic)
python inquisition.py example.com --dry-run

# 8. JSON for automated parsing
python inquisition.py example.com -f json -o findings.json

# 9. Slower scanning to avoid rate-limit triggers
python inquisition.py example.com --rate-limit 0.5 --timeout 15

# 10. Custom port list
python inquisition.py example.com --ports 22 80 443 8080 8443 9000
```

### Scan Depth

Three depth levels control the scope of port scanning and path probing:

```bash
python inquisition.py example.com --depth quick      # Lightweight scan
python inquisition.py example.com --depth standard   # Balanced (default)
python inquisition.py example.com --depth deep       # Thorough
```

| Depth | TCP Ports | Path Probing | Admin Panels | Zone Transfer | Typical Duration |
|---|---|---|---|---|---|
| `quick` | 5 core (22, 80, 443, 8080, 8443) | No | No | No | 10–20s |
| `standard` | 20 well-known | Yes | No | Yes* | 30–60s |
| `deep` | 1–1024 + 133 web/app ports | Yes | Yes | Yes* | 3–7min |

*Requires `dnspython`; skipped if missing.

#### Deep Scan: Comprehensive Web Server Ports

The deep scan includes all ports 1–1024 plus a curated list of 133 additional web and application server ports:

**Standard Web (2 ports):** 80, 443

**HTTP Alternates (30 ports):** 8000–8009, 8080–8090, 8099, 8888–8889

**HTTPS Alternates (9 ports):** 8443–8449, 8453–8454

**High-Number HTTP (7 ports):** 9000, 9001, 9090–9091, 9099, 9443, 9999

**JavaScript/Node.js Frameworks (6 ports):** 3000–3005

**Application Servers (30+ ports):** 4000, 4200 (Angular), 4443, 4567, 5000 (Flask/Django), 5005, 5173 (Vite), 5174, 5432, 5443, 5500, 5555, 5600, 6000, 6001, 6080, 6443, 6545, 6789, 6969, 7000, 7001, 7080, 7175, 7547, 7777–7779

**Enterprise Servers (15+ ports):** 8010 (Tomcat), 8020, 8025, 8030, 8040, 8050, 8060, 8070, 8160–8162, 8200, 8686–8687 (Glassfish), 8480–8481 (JBoss)

**Cloud/Container Platforms (8 ports):** 2375–2376 (Docker), 6443 (Kubernetes), 8042, 8088 (Hadoop YARN), 9200, 9300 (Elasticsearch), 10250 (Kubelet)

**Databases (8 ports):** 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017–27020 (MongoDB)

**Monitoring/Admin (6 ports):** 8161–8162 (ActiveMQ), 8686–8687 (Glassfish), 8834, 9999

**Other Services (20+ ports):** 1080, 1433, 1521, 1944, 2181, 3128, 3389 (RDP), 5005, 5555, 5900 (VNC), 5984 (CouchDB), 7474 (Neo4j), 8012, 8086 (InfluxDB), 8140, 8500, 9042, 9160, 10000, 10250

### Output Formats

Inquisition supports five output formats:

```bash
python inquisition.py example.com -f text      # Human-readable (default)
python inquisition.py example.com -f html      # Self-contained HTML with collapsible panels, SVG attack chains
python inquisition.py example.com -f markdown  # GitHub-flavoured Markdown
python inquisition.py example.com -f json      # Machine-readable JSON for parsing/integration
python inquisition.py example.com -f sarif     # SARIF 2.1.0 for GitHub code scanning / CI gates
```

When using `--output`, the format is inferred from the file extension:

```bash
python inquisition.py example.com -o report.html   # → HTML format
python inquisition.py example.com -o report.md     # → Markdown format
python inquisition.py example.com -o report.json   # → JSON format
python inquisition.py example.com -o report.txt    # → Text format
python inquisition.py example.com -o report.sarif  # → SARIF format
```

### Options Reference

#### Target & Scope
| Option | Type | Default | Description |
|---|---|---|---|
| `target` | string(s) | *required* | One or more hostnames/IPs (space-separated). Multiple targets run a fleet scan |
| `--targets-file` | path | none | Read additional targets from a file, one per line (`#` comments and blank lines ignored) |
| `-d`, `--depth` | `quick` \| `standard` \| `deep` | `standard` | Scan depth: controls ports and path probing |
| `--ports` | list of ints | 20 well-known | Override default ports (e.g. `--ports 22 80 443 8080`) |

**Fleet scanning:** pass several targets (or `--targets-file`) to scan each in turn. A combined overview table prints at the end, each target is diffed and notified independently, and `--fail-on` exits non-zero if *any* target meets the threshold. With multiple targets, `--output` is treated as a **directory** and a per-target report (`<target>.<ext>`) is written into it; with a single target it remains a file path.

To collect a whole fleet into **one artifact**, use `--combined-output FILE` (it replaces the per-target files). JSON and SARIF are merged structurally — a fleet JSON object with an aggregated severity summary, or a single SARIF 2.1.0 file with one `run` per target (GitHub code scanning accepts multiple runs). Text and HTML are concatenated with per-target separators. This is the simplest way to upload one SARIF file from a multi-target CI job:

```bash
inquisition --targets-file hosts.txt --format sarif \
  --combined-output fleet.sarif --fail-on high
```

#### Output & Reporting
| Option | Type | Default | Description |
|---|---|---|---|
| `-f`, `--format` | `text` \| `json` \| `html` \| `sarif` \| `markdown` | `text` | Report output format |
| `-o`, `--output` | path | stdout | Write report to file (for multiple targets, a per-target directory) |
| `--combined-output` | path | none | Write a single artifact spanning all targets instead of per-target files |
| `--brief` | flag | off | Omit deep-dive analysis and remediation sections |
| `--attacker-pov` | flag | off | Render from an attacker's perspective: findings sorted by exploitability (easiest first), PoC commands highlighted, kill chains annotated |

#### Concurrency & Timing
| Option | Type | Default | Description |
|---|---|---|---|
| `-j`, `--jobs` | int | 1 | Scan up to N targets concurrently (fleet runs). N>1 runs each scan quiet and prints a per-target line as it finishes |
| `-t`, `--threads` | int | 10 | Max concurrent threads per module |
| `--rate-limit` | float (seconds) | 0.1 | Minimum delay between requests within a module |
| `--timeout` | float (seconds) | 10.0 | Per-request timeout for HTTP, TLS, DNS, and API operations |
| `--connect-timeout` | float (seconds) | 2.0 | TCP connect timeout for port scanning |

#### Testing & Debugging
| Option | Type | Default | Description |
|---|---|---|---|
| `--dry-run` | flag | off | Preview scan without sending any traffic |
| `--yes`, `--i-am-authorized` | flag | off | Skip the active-scan authorization prompt when used with `--active` |
| `-v`, `--verbose` | flag | off | Enable debug logging to stderr |

#### Active Testing
| Option | Type | Default | Description |
|---|---|---|---|
| `--active` | flag | off | Enable payload-based active scanning after the explicit active-scan authorization prompt |
| `--active-engine` | `nuclei` \| `zap` | `nuclei` | Active scanner engine to run when `--active` is set |
| `--auth-header` | string | empty | Header injected into HTTP modules and active engines, e.g. `Authorization: Bearer <token>` |
| `--auth-cookie` | string | empty | Cookie header injected into HTTP modules and active engines, e.g. `session=<value>` |

See [Active Testing](#active-testing-1) for a full explanation of how this works and what it does.

#### Continuous Assurance & Notifications
| Option | Type | Default | Description |
|---|---|---|---|
| `--fail-on` | `critical` \| `high` \| `medium` \| `low` | never | Exit non-zero when any finding meets this severity (CI gating) |
| `--notify` | URL | none | Webhook to POST to. Slack incoming-webhook URLs (`hooks.slack.com`) get a formatted message; any other URL gets structured JSON |
| `--notify-min-severity` | `critical` \| `high` \| `medium` \| `low` | `high` | For `--notify-on regression`, the minimum severity of a new/worsened finding that triggers a notification |
| `--notify-on` | `regression` \| `changes` \| `always` | `regression` | When to notify: only new/worsened findings at/above the threshold (`regression`); any new/fixed/regressed/improved finding (`changes`); or every scan, even a clean one, as a heartbeat (`always`) |
| `--sla-max-age` | int | 0 (off) | Warn and notify when a finding has stayed open beyond N consecutive scans (notifies even if nothing changed) |
| `--sla-by-severity` | spec | none | Per-severity SLA overrides, e.g. `critical=1,high=3,medium=10` (falls back to `--sla-max-age`; `0` disables a severity) |
| `--attack-navigator` | path | none | Write a MITRE ATT&CK Navigator layer (`layer.json`) covering all targets — import at [attack-navigator](https://mitre-attack.github.io/attack-navigator/) to overlay observed techniques on the ATT&CK matrix |
| `--metrics-output` | path | none | Also write Prometheus/OpenMetrics text exposition for all targets to this file |
| `--metrics-history` | flag | off | In the metrics file, emit the findings trend as timestamped samples per stored scan (backfill) |
| `--metrics-push` | URL | none | Push current metrics to a Prometheus Pushgateway base URL (PUT under `--metrics-job`) |
| `--metrics-job` | name | `inquisition` | Pushgateway job name for `--metrics-push` |
| `--metrics-serve` | int (port) | 0 (off) | Serve the latest metrics at `http://HOST:PORT/metrics` for Prometheus to scrape, plus `/healthz` (liveness) and `/readyz` (readiness) |
| `--audit-log` | path | none | Append one JSON line per scan cycle (targets, counts, durations, fail status) to this file |
| `--audit-max-bytes` | int | 0 (off) | Rotate the audit log when it would exceed N bytes |
| `--audit-max-age-days` | float | 0 (off) | Rotate the audit log when its oldest record is older than DAYS |
| `--audit-backups` | int | 3 | Number of rotated audit-log backups to keep |
| `--fleet-config` | path | none | JSON or YAML file defining targets and per-target scan overrides (`${VAR}` filled from env) |
| `--watch` | int (seconds) | 0 (off) | Run continuously, re-scanning all targets every N seconds until interrupted (SIGHUP reloads a fleet config) |
| `--watch-jitter` | float (seconds) | 0 | In watch mode, stagger each target by a random 0–N second delay |
| `--history-size` | int | 10 | Number of past scans retained per target for trend tracking |
| `--history-max-age-days` | int | 0 (off) | Also drop history entries older than this many days (count cap still applies) |

Each scan is diffed against the previous run for the same target (state is kept under `reports/.state/`). Inquisition also keeps a rolling window of the last `--history-size` scans per target and reports the **trend** (improving / worsening / stable, by a severity-weighted score, plus the change in total and critical+high counts) at the end of each run. Continuous-assurance extras:

- **Per-finding age** — every finding records when it was *first seen* and how many consecutive scans it has been open ("new this scan" / "open 4 scans since 2026-06-01"), shown in the text/HTML reports and the JSON `age_scans` / `first_seen` fields.
- **Trend sparkline** — the HTML report draws an inline sparkline of total findings across the history window with an improving/worsening/stable label.
- **History in JSON** — JSON (and the combined fleet JSON) embed the `history` window and a `trend` summary for downstream dashboards.
- **SLA alerting** — `--sla-max-age N` flags findings open beyond N consecutive scans; they print a warning and are pushed to the webhook (with an `sla_breaches` payload section) even when nothing changed. `--sla-by-severity` sets stricter per-severity thresholds (e.g. `critical=1,high=3`).
- **Fleet HTML dashboard** — a fleet run with `--combined-output report.html` renders one dashboard page ranking every target by risk, with grade, severity counts, a per-target trend sparkline, and a Δ-vs-last-scan column.
- **Prometheus/OpenMetrics** — `--metrics-output metrics.prom` writes scrape-able gauges (findings by severity, risk score, CVE/misconfig counts, oldest finding age, scan duration) for every target. `--metrics-push http://gateway:9091` pushes the current gauges to a Pushgateway, and `--metrics-history` adds the findings trend as timestamped samples (for backfill; not pushed, since the Pushgateway rejects timestamps). `--metrics-serve 9092` exposes the latest metrics at `http://HOST:9092/metrics` for Prometheus to **scrape** (refreshed after each scan) — the natural pairing with `--watch` — and serves `/healthz` (liveness) and `/readyz` (readiness, 503 until the first cycle completes) for orchestrators.
- **Audit log** — `--audit-log audit.jsonl` appends one structured JSON line per scan cycle (targets, severity counts, highest severity, durations, fail-on status) for ingestion into a log pipeline or SIEM. Rotation is controlled by **size** (`--audit-max-bytes`) or **age** (`--audit-max-age-days` — rotates when the oldest record in the log exceeds the given number of days), keeping `--audit-backups` files to bound disk use. Both triggers can be combined.
- **Fleet config** — `--fleet-config fleet.json` (or `.yaml`) defines the target list and per-target overrides (depth, ports, auth, SLA, …) so a single run can scan many targets with different settings. Per-target settings override a `defaults` block, which overrides the CLI flags. String values may reference environment variables as `${VAR}` (an undefined variable is an error, so secrets fail loudly rather than leak a literal placeholder).
- **Watch / daemon mode** — `--watch SECONDS` re-scans every target on an interval until interrupted, pairing naturally with `--fleet-config`, `--notify`, and `--metrics-push`/`--metrics-serve` for continuous monitoring. In watch mode `--fail-on` only warns (it does not exit the loop), `--watch-jitter` staggers targets to spread load, and the daemon responds to signals: **SIGHUP** reloads the fleet config without restarting, **SIGUSR1** triggers an immediate scan cycle (skipping the rest of the interval), **SIGTERM** drains (finishes the in-flight cycle, then exits 0), and Ctrl-C/SIGINT stops immediately.
- **History retention** — `--history-max-age-days` prunes the trend window by age in addition to the `--history-size` count cap.

Notification payloads include a severity summary and, for `changes`/`always`, the fixed and improved findings as well as regressions. See `examples/github-action.yml` for a scheduled (cron) workflow that uploads SARIF and notifies a Slack webhook on every change.

### Safety

**Inquisition is safe by design:**

- ✅ All probes are **read-only active checks** — no exploit payloads, no login attempts, no injection, and no data-modifying requests
- ✅ **Rate limiting** to avoid overwhelming targets (default 0.1s between requests)
- ✅ **Timeout controls** to gracefully handle slow/hanging connections
- ✅ **Dry-run mode** (`--dry-run`) previews what would be scanned without sending any traffic

---

## Container & Deployment

### Docker

The repo ships a `Dockerfile` that builds a minimal image (Python 3.12 slim + OpenSSL). Inquisition runs as a non-root user (`inquisitor`, UID 10001) with `/data` as the writable working directory for reports and the audit log.

```bash
# Build locally
docker build -t inquisition .

# One-off scan
docker run --rm inquisition example.com --depth quick

# Save an HTML report to the host
docker run --rm -v "$PWD/reports:/data" inquisition \
  example.com -o /data/report.html
```

The pre-built image is published to GHCR on every version tag:

```bash
docker pull ghcr.io/sparktron/inquisition:latest
docker pull ghcr.io/sparktron/inquisition:0.1.0   # specific version
```

### Watch Mode with Prometheus (docker-compose)

`examples/docker-compose.yml` runs Inquisition in continuous watch mode alongside a Prometheus instance:

```bash
# Edit examples/fleet.yaml first — list hosts you are authorised to scan
docker compose -f examples/docker-compose.yml up --build
```

Inquisition scans the fleet hourly, serves `/metrics` (plus `/healthz` and `/readyz`) on port 9090, and writes a rotating audit log to the `inquisition-data` volume. Prometheus is configured to scrape it automatically.

### Signal Reference (watch mode)

| Signal | Effect |
|---|---|
| `SIGUSR1` | Trigger an immediate scan cycle — skips the remainder of the current interval |
| `SIGHUP` | Reload `--fleet-config` without restarting |
| `SIGTERM` | Graceful drain — finish the in-flight cycle, then exit 0 |
| `SIGINT` / Ctrl-C | Stop immediately |

With docker-compose, send signals via:

```bash
docker compose kill -s SIGUSR1 inquisition   # run now
docker compose kill -s SIGHUP  inquisition   # reload fleet config
docker compose stop inquisition              # SIGTERM → graceful drain
```

`stop_grace_period: 5m` in the compose file gives a long-running scan cycle up to five minutes to complete before the container is killed.

### Grafana Dashboard

`examples/grafana-dashboard.json` is an importable Grafana dashboard for the metrics exported by `--metrics-serve` / `--metrics-push`. Import it via **Dashboards → Import → Upload JSON file**.

The dashboard visualises:

- Finding counts by severity (CRITICAL / HIGH / MEDIUM / LOW) per target
- Risk score and security grade time-series
- CVE and misconfiguration counts
- Oldest open finding age
- Scan duration

### Image Publishing (CI)

`.github/workflows/docker-publish.yml` runs automatically when a version tag (`v*`) is pushed or via manual `workflow_dispatch`. It:

1. Runs the full test suite and type-checker (`mypy`) on Python 3.12
2. Builds and pushes the image to `ghcr.io/sparktron/inquisition` tagged with the semver version (`0.1.0`), the minor release (`0.1`), and `latest`

```bash
git tag v0.1.0 && git push origin v0.1.0   # triggers the workflow
```

---

## Report Structure

Every completed scan produces the following sections:

| Section | Description |
|---|---|
| **Executive Summary** | Finding counts by severity, CVE count, misconfiguration count, risk score, and security grade (A+–F) |
| **What Could Happen** | Consequence ladder: plain-language table mapping your security grade to real-world outcomes, with the current grade highlighted |
| **Remediation Priority Matrix** | Ranked table of CRITICAL/HIGH/MEDIUM findings in severity order (exploitability order with `--attacker-pov`), with PoC availability indicator |
| **Detailed Findings** | Per-finding evidence, MITRE ATT&CK technique badges, impact, quick fix, CPE, and recommended tools |
| **Attack Scenario** | Realistic step-by-step narrative of how an attacker would exploit each finding *(expandable panel in HTML; block-quote in Markdown)* |
| **PoC Command** | Illustrative attacker command for each finding showing exploitation in practice *(expandable code panel in HTML; fenced code block in Markdown)* |
| **Attack Chain Analysis** | Multi-step kill chains inferred from the combination of findings present (data-driven rules in `modules/data/attack_chains.yaml`, matched by a predicate DSL), with inline SVG flowcharts (HTML) and MITRE technique tags |
| **Attack Graph — Reachable Objectives** | Emergent attacker-state graph: each finding is an edge between attacker states, and a traversal from an external position reveals every objective an attacker can reach (RCE, data access, cloud takeover, lateral movement, …) and the shortest path to each — rendered as a Mermaid diagram in HTML |
| **MITRE ATT&CK Coverage** | Every finding mapped to ATT&CK techniques (explicit or category-level fallback), grouped by tactic in kill-chain order; exportable as a Navigator layer with `--attack-navigator` |
| **Deep Issue Analysis** | Multi-paragraph explanation of what each issue is, why it is dangerous, and relevant CVEs *(text/HTML only; omitted with `--brief`)* |
| **Remediation Guide** | Step-by-step fix instructions with configuration examples for common platforms and verification commands *(text/HTML only; omitted with `--brief`)* |
| **CVE Correlation** | CVEs matched to detected CPEs via the NVD API, **ranked by real-world exploitation risk** — CISA KEV (actively exploited) > public exploit available (local Nuclei template) > FIRST.org EPSS probability > CVSS — with EPSS percentile and exploit badges |
| **Misconfiguration Summary** | Higher-level pattern analysis derived from raw findings, with MITRE tags, attack scenarios, and PoC commands per entry |
| **Tool Reference** | Recommended open-source tools for deeper investigation by category |

### Risk Score and Grade

The risk score is a weighted sum of finding severities:

| Severity | Weight |
|---|---|
| CRITICAL | 40 |
| HIGH | 15 |
| MEDIUM | 5 |
| LOW | 1 |
| INFO | 0 |

| Grade | Score | Assessment |
|---|---|---|
| **A+** | 0 | No findings — clean bill of health |
| **A** | 1–9 | Negligible — informational findings only |
| **B** | 10–24 | Minor — low-severity issues present |
| **C** | 25–49 | Moderate — medium-severity issues require attention |
| **D** | 50–99 | Significant risk — high-severity issues present |
| **F** | 100+ | Critical — immediate action required; high-risk exposure |

### HTML Report

The HTML report is a self-contained single file (no external dependencies). Each finding is rendered as a severity-coloured card with expandable panels:

- **Issue Analysis** — multi-paragraph deep-dive into what the issue is and why it matters
- **How an Attacker Exploits This** — step-by-step realistic attack scenario (purple panel)
- **Attacker's Command (PoC)** — illustrative exploitation command in a dark code block (red panel)
- **Remediation Steps** — fix instructions with platform-specific examples

The "What Could Happen" consequence table highlights your site's current grade row. CVEs include a red `⚠ KEV` badge when in the CISA Known Exploited Vulnerabilities catalog and a days-since-disclosure counter. Each attack chain is visualised as an inline SVG flowchart. Add `--attacker-pov` to get a purple banner and exploitability-sorted findings.

### Example Output (text)

```
########################################################################
  INQUISITION — Security Reconnaissance Report
########################################################################
  Target   : example.com
  Started  : 2026-03-14 12:00:00 UTC
  Finished : 2026-03-14 12:01:23 UTC (83.2s)
  Depth    : standard
  Mode     : safe

========================================================================
  EXECUTIVE SUMMARY
========================================================================
  Total findings: 12
    HIGH      : 2
    MEDIUM    : 5
    LOW       : 3
    INFO      : 2
  CVEs correlated  : 3
  Misconfigurations: 4

  Risk score : 58  |  Security grade : D
  (Grade scale: A+ = clean, A/B = minor issues, C = moderate risk,
   D = significant risk, F = critical exposure requiring immediate action)

========================================================================
  REMEDIATION PRIORITY MATRIX
========================================================================
  #    Severity   Category         Title
  ---- ---------- ---------------- --------------------------------------
  1    HIGH       tls              Deprecated TLS version: TLSv1.0
  2    HIGH       http_header      Content-Security-Policy missing
  ...

========================================================================
  DEEP ISSUE ANALYSIS
========================================================================
  [HIGH] Deprecated TLS version: TLSv1.0
  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
    TLS (Transport Layer Security) is the protocol that encrypts traffic
    between browsers and servers.  SSLv2, SSLv3, TLSv1.0, and TLSv1.1 are
    all formally deprecated by RFC 8996 (March 2021) because they contain
    unfixable cryptographic design flaws.

    Why it is a security problem:
      • POODLE (CVE-2014-3566): ...
      • BEAST (CVE-2011-3389): ...
  ...

========================================================================
  REMEDIATION GUIDE
========================================================================
  HIGH PRIORITY
  ...
  [HIGH] Deprecated TLS version: TLSv1.0
  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
    Step 1 — Identify your TLS termination point ...
    Step 2 — Update the TLS protocol configuration:
      nginx:  ssl_protocols TLSv1.2 TLSv1.3;
      Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3
  ...
```

---

## Modules Reference

Inquisition runs 9 specialised modules, beginning with crawler pre-discovery before the remaining modules run concurrently:

### 1. DNS Reconnaissance (`dns_recon`)
**What it does:** Resolves DNS records, enumerates subdomains, checks email security.

**Checks:**
- A/AAAA resolution and IP discovery
- Reverse DNS lookups
- Subdomain enumeration using a curated list of common prefixes (`www`, `mail`, `dev`, `staging`, `api`, `admin`, etc.)
- MX/NS/TXT record queries
- SPF record presence and enforcement-strength checks (`+all`, `?all`, `~all`, missing `all`)
- DMARC record detection and policy-strength checks (`p=none`, partial `pct`, weak subdomain policy)
- **DNS zone transfer (AXFR) attempts** — reveals entire zone if unrestricted
- **Subdomain takeover detection** — identifies dangling CNAME records on 24+ third-party services

**Severity:** CRITICAL for zone transfer success; HIGH for subdomain takeover

---

### 2. Port Scanning (`port_scan`)
**What it does:** TCP connection scanning with passive banner collection and service-specific risk analysis.

**Checks:**
- TCP connect-scan on configurable port ranges
- Passive banner reads for common text protocols that advertise first
- Service identification
- Enhanced risk flagging for:
  - **Telnet (port 23)** → HIGH — cleartext credentials
  - **SMB (port 445)** → HIGH — EternalBlue/WannaCry risk, MS17-010
  - **FTP (port 21)** → MEDIUM — cleartext auth, anonymous access
  - **VNC (port 5900)** → HIGH — weak auth risk
  - **Redis (port 6379)** → HIGH — unauthenticated access
  - **MongoDB (port 27017)** → HIGH — default no-auth exposure
  - **Elasticsearch (port 9200)** → HIGH — API exposed
  - **MySQL (port 3306)** → MEDIUM — brute-force risk
  - **PostgreSQL (port 5432)** → MEDIUM — misconfigured pg_hba.conf
  - **RDP (port 3389)** → MEDIUM — BlueKeep risk

**Severity:** Depends on port; Telnet/SMB are HIGH

---

### 3. TLS Analysis (`tls_analysis`)
**What it does:** Inspects TLS certificates and protocol configuration.

**Checks:**
- Protocol version detection (flags SSLv2, SSLv3, TLSv1.0, TLSv1.1)
- Active protocol-version enumeration and weak-cipher-family probing
- Negotiated cipher analysis (flags RC4, DES, NULL, EXPORT, anonymous ciphers if negotiated)
- Weak Diffie-Hellman parameter detection (Logjam-class) — forces a TLS 1.2 DHE handshake and grades the finite-field DH group size
- Certificate fingerprint (SHA-256)
- Self-signed certificate detection
- Certificate expiry and validity period
- Hostname mismatch in Subject Alternative Names (SAN)
- Certificate parsing for subject, issuer, expiry, and SAN fields
- Full chain validation against the system trust store
- Certificate Transparency (embedded SCT) presence
- OCSP revocation lookup

**Severity:** CRITICAL for expired/revoked certs; HIGH for legacy protocols/weak ciphers/export-grade DH

> **Note:** Chain validation, CT/SCT, and OCSP use the `cryptography` package (installed automatically). Weak-DH detection additionally shells out to the `openssl` CLI when present; if `openssl` is not on `PATH` that single check is skipped silently and the rest of the TLS analysis runs unaffected.

---

### 4. HTTP Headers Audit (`http_headers`)
**What it does:** Validates HTTP security headers and cookie configuration.

**Checks:**
- HSTS (Strict-Transport-Security)
- CSP (Content-Security-Policy)
- X-Content-Type-Options (MIME-sniffing)
- X-Frame-Options (clickjacking)
- Referrer-Policy
- Permissions-Policy
- Information disclosure headers (Server, X-Powered-By, X-AspNet-Version)
- Cookie flags: **Secure**, **HttpOnly**, **SameSite** (Strict/Lax/None)
- Header quality checks for weak HSTS max-age, missing `includeSubDomains` / `preload`, inactive HSTS preload status, permissive CSP sources, invalid defensive header values, broad Permissions-Policy, and cookie prefix rules
- HTTP-to-HTTPS redirect

**Severity:** MEDIUM for missing or weak HSTS/CSP; MEDIUM for insecure cookies

---

### 5. Technology Stack Detection (`tech_stack`)
**What it does:** Fingerprints CMS, frameworks, and server software.

**Detection methods:**
- Body signature matching (regex patterns in HTML)
- Header signature matching (Server, X-Powered-By, X-Generator)
- Path probing for known endpoints (wp-login.php, /administrator/, /phpmyadmin/, etc.)
- Crawler-discovered page signature checks

**Detected technologies:**
- CMS: WordPress, Joomla, Drupal, Shopify
- Frameworks: Laravel, Django, Ruby on Rails, Express.js, Next.js, Nuxt.js
- Languages: PHP, ASP.NET
- Servers: nginx, Apache, IIS, LiteSpeed
- Exposed files: `.env` (CRITICAL), `.git/HEAD` (HIGH)

**CPE correlation:** Detected technologies are matched against the NVD for CVE lookup.

**Severity:** INFO for detection; CRITICAL if `.env` or `.git` are accessible

---

### 6. Application Checks (`app_checks`)
**What it does:** Detects application-layer misconfigurations.

**Checks:**
- CORS wildcard (`Access-Control-Allow-Origin: *`)
- X-XSS-Protection disabled
- CORS preflight testing
- Mixed-content references on the HTTPS homepage and crawler-discovered pages
- Missing Subresource Integrity on third-party script/stylesheet assets
- **GraphQL introspection query** — tests if schema is enumerable
- **HTTP method inspection** — checks the `OPTIONS` `Allow` header for dangerous advertised methods such as TRACE, PUT, DELETE, and PATCH
- Path probing for:
  - phpinfo.php (HIGH)
  - Debug endpoints (HIGH)
  - ELMAH error logs / ASP.NET trace (HIGH)
  - Swagger UI / API documentation (LOW)
  - GraphQL endpoint (LOW)
  - Favicon, sitemap.xml, robots.txt (INFO)

**Severity:** HIGH for GraphQL introspection, TRACE, debug endpoints; MEDIUM for CORS/methods

---

### 7. WAF/CDN Detection (`waf_detection`)
**What it does:** Identifies protective layers in front of the target.

**Detects common products and edge layers via signatures:**
- **CDNs:** Cloudflare, AWS CloudFront, Akamai, Fastly, Vercel, Netlify
- **WAFs:** Imperva Incapsula, Sucuri, Cloudflare WAF
- **Cache layers:** Varnish, Akamai
- **Proxies/Gateways:** Kong, AWS API Gateway, Azure Front Door
- Detection via headers, cookies, response body markers

**Findings:**
- INFO if WAF/CDN found (confirms protection is in place)
- LOW if none found (recommends adding protective layer)

---

### 8. Content Discovery (`content_discovery`)
**What it does:** Finds administrative interfaces, backups, and sensitive files.

**Checks:**

*Always (QUICK/STANDARD/DEEP):*
- RFC 9116 security.txt validation
- robots.txt path disclosure analysis

*Standard/Deep only:*
- **Admin panels (30 checked):** Kibana, Grafana, Jenkins, Prometheus, Spring Boot Actuator, Jupyter, Portainer, RabbitMQ, Consul, Vault, pgAdmin, Adminer, MLflow, Celery Flower, Airflow, etc.
- **Backup files (24 checked):** `.env.bak`, `.env.prod`, `.sql`, `docker-compose.yml`, `backup.zip`, `.htpasswd`, `Dockerfile`, `.npmrc`, `web.config.bak`, etc.
- Crawler-discovered sensitive files and admin routes are fetched and confirmed when possible

**Severity:** CRITICAL for exposed `.env` and backups; HIGH for admin panels; MEDIUM for docker-compose.yml, Dockerfile; LOW for .DS_Store

---

## Misconfiguration Rules

The misconfiguration engine derives higher-level findings from raw module output using a curated rule set:

### TLS/Certificate
- ✗ Expired TLS certificate (CRITICAL)
- ✗ Certificate revoked per OCSP (CRITICAL)
- ✗ Self-signed certificate (MEDIUM)
- ✗ Certificate chain not trusted — incomplete/untrusted chain (MEDIUM)
- ✗ Legacy TLS enabled — TLS 1.0/1.1 (HIGH)
- ✗ Weak cipher suites (HIGH)
- ✗ Export-grade DH parameters — <1024-bit, Logjam (HIGH)
- ✗ Weak 1024-bit DH parameters (MEDIUM)
- ✗ No embedded Certificate Transparency SCTs (LOW)
- ✗ No OCSP responder advertised (LOW)
- ✗ Certificate date unparseable (MEDIUM)

### HTTP & Network
- ✗ HSTS not enabled (MEDIUM)
- ✗ CSP not configured (MEDIUM)
- ✗ Clickjacking protection absent — X-Frame-Options (LOW)
- ✗ Unencrypted HTTP served — no redirect to HTTPS (MEDIUM)
- ✗ Session cookies lack security flags (MEDIUM)
- ✗ Overly permissive CORS policy (MEDIUM)

### File & Configuration Exposure
- ✗ Environment file publicly accessible — `.env` (CRITICAL)
- ✗ Git repository exposed — `.git/` (HIGH)
- ✗ Database dumps exposed — `.sql` files (CRITICAL)
- ✗ Docker Compose config exposed (MEDIUM)
- ✗ Sensitive file publicly accessible (CRITICAL)

### Services & Protocols
- ✗ Telnet service exposed (HIGH)
- ✗ SMB exposed to internet (CRITICAL)
- ✗ Redis exposed to internet (HIGH)
- ✗ Elasticsearch exposed to internet (HIGH)
- ✗ RDP exposed to internet (MEDIUM)
- ✗ MongoDB exposed to internet (HIGH)
- ✗ phpMyAdmin accessible (HIGH)

### Application Layer
- ✗ PHP configuration page exposed — phpinfo (HIGH)
- ✗ Admin panel publicly accessible (HIGH/MEDIUM)
- ✗ GraphQL introspection enabled in production (MEDIUM)
- ✗ HTTP TRACE method enabled (MEDIUM)
- ✗ DNS zone transfer unrestricted (CRITICAL)
- ✗ Subdomain takeover via dangling CNAME (HIGH)

---

## Active Testing

> **This feature sends payloads to the target.** Only use it against targets you own or have explicit written authorisation to actively test.

By default, Inquisition is entirely **read-only**. The standard scan (without `--active`) sends only benign reconnaissance probes: DNS queries, TCP connects, HTTP `GET`/`OPTIONS` requests, TLS handshakes, CORS preflights, and similar non-mutating checks. No payloads, no injections, no brute-force.

`--active` enables a second phase that crosses this boundary. After the passive scan completes, Inquisition spawns an external vulnerability scanner — either **Nuclei** (default) or **OWASP ZAP** — which sends actual attack templates against the target to confirm real vulnerabilities rather than just infer them from configuration.

### What active testing does differently

| | Passive (default) | Active (`--active`) |
|---|---|---|
| What it sends | GET/HEAD/OPTIONS, DNS, TLS handshakes | CVE-based payload templates, WAF evasion probes, injection checks |
| Can it confirm a vuln is exploitable? | No — infers from config | Yes — receives a real response to a crafted probe |
| Side effects on the target | None | May trigger WAF alerts, appear in access logs, consume rate-limit quota |
| Needs explicit authorization | Yes (one prompt) | Yes (a second, separate prompt specifically for active scanning) |
| Finds | Misconfigurations, missing headers, weak crypto | Same as passive, plus exploitable injection points, exposed panels, template-matched CVEs |

### How Nuclei integration works

[Nuclei](https://github.com/projectdiscovery/nuclei) (ProjectDiscovery) is a template-driven vulnerability scanner. Each template describes a specific CVE or misconfiguration: the HTTP request to send, the pattern to match in the response, and the severity if it matches.

Inquisition shells out to the `nuclei` binary already on your `PATH`. It runs with these constraints to stay a controlled vulnerability check rather than a full attack:

- **Severity filter:** only `low`, `medium`, `high`, `critical` templates are run — informational noise is suppressed
- **Excluded tags:** `dos`, `intrusive`, `fuzz`, `brute-force` template categories are always excluded. This prevents denial-of-service payloads, brute-force login attempts, and aggressive fuzzing even if such templates are present in your local template library
- **Silent JSONL output:** results are returned as one JSON object per line and parsed directly into `Finding` objects — no intermediate files

The effective Nuclei command looks like:

```bash
nuclei -u https://example.com \
       -jsonl -silent \
       -severity low,medium,high,critical \
       -exclude-tags dos,intrusive,fuzz,brute-force \
       -timeout 10 \
       -disable-update-check
```

If `--auth-header` is set (e.g. `Authorization: Bearer <token>`), the header is forwarded to Nuclei via `-H` so authenticated surfaces are also tested.

#### Installing Nuclei

```bash
# macOS
brew install nuclei

# Linux
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Docker (alternative — the Inquisition container does not bundle Nuclei)
docker run --rm projectdiscovery/nuclei --version
```

Nuclei maintains its own template library at `~/.local/nuclei-templates/`. Run `nuclei -update-templates` periodically to get new CVE coverage.

### How OWASP ZAP integration works

[OWASP ZAP](https://www.zaproxy.org/) (Zed Attack Proxy) is a full web application security scanner. Inquisition uses its **baseline scan** mode (`zap-baseline.py`), which is the lighter, non-intrusive profile — it spiders and passively analyses the target, then runs a constrained set of active rules.

ZAP is invoked as:

```bash
zap-baseline.py -t https://example.com -J - -m <minutes> -I
```

Results are returned as a JSON report on stdout. Inquisition parses each alert, maps ZAP's risk codes to its own severity levels, and converts them into `Finding` objects. Informational alerts are suppressed.

If `--auth-header` or `--auth-cookie` is set, Inquisition configures ZAP's HTTP replacer extension to inject the credential on every request, so authenticated scan surfaces are covered.

#### Installing ZAP

```bash
# macOS
brew install --cask owasp-zap

# Or use the ZAP Docker image (includes zap-baseline.py)
docker pull ghcr.io/zaproxy/zaproxy:stable
```

### Choosing between Nuclei and ZAP

| | Nuclei | OWASP ZAP |
|---|---|---|
| Best for | CVE-specific template matching, API endpoints | Full web app scanning, spidering, authenticated sessions |
| Speed | Fast (seconds to a few minutes per target) | Slower (minutes; spider + active rules) |
| Output style | Template-per-finding, high precision | Alert-per-issue, broader coverage |
| Auth support | Single header (`--auth-header`) | Header + cookie via replacer |
| Requires | `nuclei` binary on `PATH` | `zap-baseline.py` on `PATH` (from ZAP install) |

Use Nuclei for a quick, targeted CVE sweep. Use ZAP when you need broader coverage of the authenticated application surface.

### Running an active scan

```bash
# Standard passive + active (Nuclei, default)
python inquisition.py example.com --active --yes

# Active scan with ZAP
python inquisition.py example.com --active --active-engine zap --yes

# Authenticated active scan (Bearer token)
python inquisition.py example.com --active \
  --auth-header "Authorization: Bearer eyJ..." --yes

# Save full HTML report including active findings
python inquisition.py example.com --active -o report.html --yes
```

Active findings appear in the report prefixed with `[active]` and are categorised as `vulnerability`. They pass through the same deduplication, KB enrichment, and attacker-context pipeline as passive findings.

### Authorization gate

Passive scanning starts immediately with no prompt — it is read-only reconnaissance and requires no interactive confirmation.

Active testing shows one authorization prompt before sending payloads. Pass `--yes` to suppress it in non-interactive environments (CI pipelines, cron jobs, scripts):

```bash
python inquisition.py example.com --active --yes
```

The `--yes` flag has no effect on passive-only scans.

---

## Examples

### Example 1: Basic Target Assessment

```
$ python inquisition.py example.com

[*] Starting scan of example.com (depth=standard)

  [+] dns_recon: 6 finding(s)
  [+] port_scan: 3 finding(s)
  [+] tls_analysis: 5 finding(s)
  [+] http_headers: 8 finding(s)
  [+] tech_stack: 2 finding(s)
  [+] app_checks: 4 finding(s)
  [+] waf_detection: 1 finding(s)
  [+] content_discovery: 2 finding(s)

[*] Correlating 3 CPE(s) with NVD...
  [+] cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*: 2 CVE(s)
  [+] cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*: 1 CVE(s)

[*] Removed 2 duplicate finding(s)
[*] 4 misconfiguration(s) detected

========================================================================
  INQUISITION — Security Reconnaissance Report
========================================================================
  Target   : example.com
  Started  : 2026-04-04 15:32:00 UTC
  Finished : 2026-04-04 15:32:47 UTC (47.2s)
  Depth    : standard
  Mode     : safe

========================================================================
  EXECUTIVE SUMMARY
========================================================================
  Total findings: 28
    CRITICAL : 1
    HIGH     : 4
    MEDIUM   : 10
    LOW      : 8
    INFO     : 5

  CVEs correlated  : 3
  Misconfigurations: 4

  Risk score : 72  |  Security grade : D
```

### Example 2: Save HTML Report

```bash
python inquisition.py example.com -o report.html --depth deep
# [*] Report saved to: report.html
```

The generated HTML report includes severity-coloured finding cards with collapsible "How an Attacker Exploits This" and "Attacker's Command (PoC)" panels; a consequence table showing your grade against real-world outcomes; a CVE table with CVSS scores, CISA KEV badges, and days-since-disclosure; attack chain SVG flowcharts; and zero external dependencies.

### Example 2a: Attacker's-Eye-View Report

```bash
python inquisition.py example.com --attacker-pov -o report.html
```

Findings are reordered by exploitability (easiest first), proof-of-concept commands are highlighted, kill chains are annotated, and a purple "Attacker's View" banner appears at the top.

### Example 3: JSON Export for Automation

```bash
python inquisition.py example.com -f json -o findings.json

jq '.findings[] | select(.severity=="CRITICAL")' findings.json
```

```json
{
  "title": "Environment file exposure",
  "category": "tech_stack",
  "severity": "critical",
  "evidence": "HTTP 200 at https://example.com/.env (247 bytes)",
  "impact": "Environment file may contain credentials and secrets",
  "remediation": "Block public access to .env files via web server config",
  "cpe": ""
}
```

### Example 4: Continuous Watch Mode with Notifications

```bash
inquisition --fleet-config fleet.yaml \
  --watch 3600 --watch-jitter 30 \
  --metrics-serve 9090 \
  --audit-log audit.jsonl --audit-max-age-days 30 --audit-backups 5 \
  --notify https://hooks.slack.com/... --notify-on regression
```

This runs continuously, serves Prometheus metrics on port 9090, rotates the audit log when it contains records older than 30 days, and posts a Slack message whenever a new or worsened finding appears.

---

## Legal & Safety

### Authorization

**Only use Inquisition against targets you own or have explicit written authorization to test.**

Unauthorized security scanning may violate computer fraud and abuse laws in your jurisdiction. Inquisition requires explicit authorization confirmation before each scan — use this to ensure you have proper permission.

### Safety by Design

By default, Inquisition is intentionally **read-only active reconnaissance:**

- ✅ No exploit payloads or weaponized techniques
- ✅ No authentication bypass attempts
- ✅ No injection, fuzzing, or enumeration of application logic
- ✅ No modifications to target systems
- ✅ No extraction of private data
- ✅ Passive scans start immediately — no prompt required

Optional `--active` mode is different: it shells out to Nuclei or OWASP ZAP and sends payload-based vulnerability probes after a second, explicit active-scan authorization prompt. DOS, brute-force, and fuzzing template categories are always excluded. Use it only where you have written permission for active testing. See [Active Testing](#active-testing-1) for the full explanation.

### Responsible Disclosure

If you discover a vulnerability on a system you own, consider:

1. **Check for security.txt** — Does the target publish security contact info per RFC 9116?
2. **Responsible disclosure process** — Give the organisation reasonable time to patch before public disclosure
3. **Bug bounty programmes** — Many organisations offer rewards for responsibly disclosed vulnerabilities

---

## License

MIT

---

## Contributing

Contributions are welcome. Please open an issue or pull request at the repository.

### Development Validation

Run the local checks before opening a pull request:

```bash
python -m pytest -q
python -m compileall -q .
python -m mypy .
python inquisition.py example.com --dry-run --format json --output /tmp/inquisition-dry-run.json
```

The test suite includes deterministic recorded HTTP/DNS/socket fixtures for network-facing modules; tests should not require live external targets.

The knowledge base (`modules/data/analysis_kb.json`) is the single source of truth for deep-dive content. Every entry must contain `analysis`, `remediation`, `attack_scenario`, `mitre_techniques`, and `poc_command`. The schema test (`test_analysis_kb.py`) verifies this — keep it green whenever adding or editing entries.

For bug reports or feature requests, provide:
- Description of the issue
- Steps to reproduce (if applicable)
- Expected vs. actual behaviour
- Scan output (sanitise any sensitive data)

---

**Last updated:** June 2026 — added MITRE ATT&CK tags, attack scenarios, PoC commands, CISA KEV enrichment, attack chain detection and SVG visualisation, consequence ladder, and `--attacker-pov` mode
