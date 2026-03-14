# inquisition

A read-only website fingerprinting and security reconnaissance tool. Identifies technologies, frameworks, open ports, TLS configuration, HTTP security headers, and known vulnerabilities on a target host — then produces a detailed analysis of every issue found, including why it is a problem and exactly what to do about it.

## Features

- **DNS reconnaissance** — A/AAAA records, reverse DNS, subdomain enumeration, SPF/DMARC checks
- **Port scanning** — TCP connect-scan across configurable port ranges with banner grabbing
- **TLS/SSL analysis** — protocol version, cipher suites, certificate validity and expiration
- **HTTP header audit** — missing security headers, information disclosure, insecure cookies
- **Technology detection** — CMS, frameworks, server software via body/header signatures and path probing
- **Application checks** — CORS, debug endpoints, exposed API docs, sensitive path exposure
- **CVE correlation** — CPE-based lookup against the NVD API
- **Misconfiguration detection** — 18 pattern-matched rules for common security weaknesses
- **Deep issue analysis** — per-finding explanation of what the vulnerability is, why it is dangerous, named CVEs, and real-world attack scenarios
- **Remediation guide** — per-finding step-by-step fix instructions with platform-specific configuration examples and verification commands
- **Risk score and security grade** — weighted numeric score and A+–F letter grade derived from all findings
- **Finding deduplication** — duplicate findings from overlapping module probes are collapsed automatically
- **Text, JSON, and HTML output** — HTML report is fully self-contained with collapsible deep-dive sections

## Requirements

- Python 3.10+
- pip

## Installation

```bash
git clone https://github.com/sparktron/inquisition.git
cd inquisition
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
./inquisition <target> [options]
```

The target is a **hostname or IP address** (e.g. `example.com` or `93.184.216.34`).

### Auto mode

Run a full deep assessment with no user interaction:

```bash
./inquisition --auto example.com
```

Auto mode sets scan depth to `deep` and suppresses the authorization prompt. Use this for scripted or unattended runs where you have pre-authorized the target.

### Basic scan

```bash
./inquisition example.com
```

Before sending any traffic, inquisition displays an authorization banner and asks you to confirm that you have permission to scan the target. Use `-y` to skip this prompt in automated workflows.

### Scan depth

```bash
# Quick — top ports only, basic checks
./inquisition example.com -d quick

# Standard (default) — balanced coverage
./inquisition example.com -d standard

# Deep — full port range, thorough probing
./inquisition example.com -d deep
```

| Depth | Ports scanned | Checks |
|---|---|---|
| `quick` | 5 core ports (22, 80, 443, 8080, 8443) | Basic checks only |
| `standard` | 20 well-known ports | Standard checks including path probing |
| `deep` | Full 1–1024 range | All checks, thorough probing |

### Output format

Three formats are supported. Format is inferred automatically from the output file extension when `--output` is used.

```bash
# Human-readable text (default)
./inquisition example.com -f text

# Self-contained HTML report
./inquisition example.com -f html

# Machine-readable JSON
./inquisition example.com -f json
```

### Saving reports to a file

Use `-o` / `--output` to write the report to a file. The file extension is used to infer the format when `--format` is not explicitly set.

```bash
# Save as HTML (format inferred from extension)
./inquisition example.com -o report.html

# Save as JSON
./inquisition example.com -o report.json

# Save as text with explicit format
./inquisition example.com -f text -o report.txt
```

### Brief mode

Suppress the deep-dive analysis and remediation sections for a more concise text report:

```bash
./inquisition example.com --brief
```

The executive summary, priority matrix, and detailed findings table are still included. Only the DEEP ISSUE ANALYSIS and REMEDIATION GUIDE sections are omitted.

### Safe mode

Safe mode (enabled by default) restricts all probes to read-only operations — no exploit payloads, no authentication bypass attempts, no injection. Disable it only when you have explicit authorization and understand the implications.

```bash
# Safe mode on (default)
./inquisition example.com --safe-mode

# Disable safe mode
./inquisition example.com --no-safe-mode
```

### Dry run

Preview the scan configuration without sending any network traffic:

```bash
./inquisition example.com --dry-run
```

### Concurrency and rate limiting

```bash
# Custom thread count (default: 10)
./inquisition example.com -t 5

# Minimum seconds between requests (default: 0.1)
./inquisition example.com --rate-limit 0.5

# Per-request timeout in seconds (default: 10)
./inquisition example.com --timeout 30
```

### Full options reference

| Flag | Default | Description |
|---|---|---|
| `target` | — | Hostname or IP to scan |
| `--auto` | off | Full deep assessment, no user interaction |
| `-d`, `--depth` | `standard` | Scan depth: `quick`, `standard`, `deep` |
| `-f`, `--format` | `text` | Output format: `text`, `json`, `html` |
| `-o`, `--output` | — | Write report to file (extension infers format) |
| `--brief` | off | Omit deep-dive analysis and remediation sections |
| `-t`, `--threads` | `10` | Max concurrent threads |
| `--safe-mode` / `--no-safe-mode` | on | Restrict to read-only probes |
| `--dry-run` | off | Preview without sending traffic |
| `--rate-limit` | `0.1` | Seconds between requests |
| `--timeout` | `10` | Per-request timeout (seconds) |
| `-y`, `--yes` | off | Skip authorization prompt |

## Report structure

Every completed scan produces the following sections:

| Section | Description |
|---|---|
| **Executive Summary** | Finding counts by severity, CVE count, misconfiguration count, risk score, and security grade (A+–F) |
| **Remediation Priority Matrix** | Ranked table of CRITICAL/HIGH/MEDIUM findings in severity order |
| **Detailed Findings** | Per-finding evidence, brief impact statement, quick fix, CPE, and recommended tools |
| **Deep Issue Analysis** | Multi-paragraph explanation of what each issue is, why it is dangerous, relevant CVEs, and real-world attack scenarios *(text/HTML only; omitted with `--brief`)* |
| **Remediation Guide** | Step-by-step fix instructions with configuration examples for common platforms and verification commands *(text/HTML only; omitted with `--brief`)* |
| **CVE Correlation** | CVEs matched to detected CPEs via the NVD API, with CVSS scores |
| **Misconfiguration Summary** | Higher-level pattern analysis derived from the raw findings |
| **Tool Reference** | Recommended open-source tools for deeper investigation by category |

### Risk score and grade

The risk score is a weighted sum of finding severities:

| Severity | Weight |
|---|---|
| CRITICAL | 40 |
| HIGH | 15 |
| MEDIUM | 5 |
| LOW | 1 |

| Grade | Score range | Meaning |
|---|---|---|
| A+ | 0 | No findings |
| A | 1–9 | Negligible — informational findings only |
| B | 10–24 | Minor — low-severity issues present |
| C | 25–49 | Moderate risk — medium issues need attention |
| D | 50–99 | Significant risk — high-severity issues present |
| F | 100+ | Critical exposure — immediate action required |

### HTML report

The HTML report is a self-contained single file (no external dependencies). Each finding is rendered as a severity-coloured card. Click **Issue Analysis** or **Remediation Steps** on any card to expand the full deep-dive content inline.

## Example output (text)

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

## Modules

| Module | What it checks |
|---|---|
| `dns_recon` | A/AAAA resolution, reverse DNS, subdomain enumeration, MX/NS/TXT records, SPF, DMARC |
| `port_scan` | TCP connect-scan with banner grabbing; flags Telnet, Redis, Elasticsearch, RDP, VNC |
| `tls_analysis` | Protocol version, cipher suite strength, certificate expiry, self-signed, hostname mismatch |
| `http_headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, leaky headers, cookie flags, HTTP→HTTPS redirect |
| `tech_stack` | WordPress, Joomla, Drupal, PHP, nginx, Apache, IIS, and more via body/header signatures; probes for `.env`, `.git`, `phpMyAdmin`, Apache mod_status |
| `app_checks` | CORS wildcard, XSS-Protection disabled, phpinfo, ELMAH, ASP.NET trace, debug endpoints, Swagger UI, GraphQL introspection |

## Misconfiguration rules

The misconfiguration engine derives higher-level findings from raw module output. Covered patterns:

- Expired TLS certificate
- Self-signed certificate
- Legacy TLS enabled (TLS 1.0 / 1.1)
- Weak TLS cipher suite
- HSTS not enabled
- CSP not configured
- Clickjacking protection absent (X-Frame-Options)
- Unencrypted HTTP served (no redirect)
- Session cookies lack security flags
- Overly permissive CORS policy
- PHP configuration page exposed
- Environment file publicly accessible (`.env`)
- Git repository exposed (`.git`)
- Redis exposed to internet
- Elasticsearch exposed to internet
- RDP exposed to internet
- Telnet service exposed
- phpMyAdmin accessible

## Legal

Only use this tool against targets you own or have explicit written authorization to test. Unauthorized scanning may violate computer fraud and abuse laws. The tool will prompt for authorization confirmation before each scan.

## License

MIT
