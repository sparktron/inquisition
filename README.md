# inquisition

A read-only website fingerprinting and security reconnaissance tool. Identifies technologies, frameworks, open ports, TLS configuration, HTTP security headers, and known vulnerabilities on a target host — then correlates findings against known CVEs.

## Features

- **DNS reconnaissance** — A/AAAA records, reverse DNS, subdomain enumeration, SPF/DMARC checks
- **Port scanning** — TCP connect-scan across configurable port ranges with banner grabbing
- **TLS/SSL analysis** — protocol version, cipher suites, certificate validity and expiration
- **HTTP header audit** — missing security headers, information disclosure, insecure cookies
- **Technology detection** — CMS, frameworks, server software via body/header signatures and path probing
- **Application checks** — CORS, debug endpoints, exposed API docs, sensitive path exposure
- **CVE correlation** — CPE-based lookup against the NVD API
- **Misconfiguration detection** — pattern-matched rules for common security weaknesses
- Text and JSON output formats

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

```bash
# Human-readable text (default)
./inquisition example.com -f text

# Machine-readable JSON
./inquisition example.com -f json

# Save JSON report to a file
./inquisition example.com -f json > report.json
```

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
| `-f`, `--format` | `text` | Output format: `text`, `json` |
| `-t`, `--threads` | `10` | Max concurrent threads |
| `--safe-mode` / `--no-safe-mode` | on | Restrict to read-only probes |
| `--dry-run` | off | Preview without sending traffic |
| `--rate-limit` | `0.1` | Seconds between requests |
| `--timeout` | `10` | Per-request timeout (seconds) |
| `-y`, `--yes` | off | Skip authorization prompt |

## Example output

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
  Misconfigurations: 2

========================================================================
  REMEDIATION PRIORITY MATRIX
========================================================================
  #    Severity   Category         Title
  ---- ---------- ---------------- --------------------------------------
  1    HIGH       tls              TLS 1.0 enabled
  2    HIGH       http_header      Content-Security-Policy missing
  ...
```

## Modules

| Module | What it does |
|---|---|
| `dns_recon` | Resolves A/AAAA, reverse DNS, subdomains, MX/NS/TXT, SPF/DMARC |
| `port_scan` | TCP connect-scan with banner grabbing, flags risky services |
| `tls_analysis` | TLS version, cipher strength, certificate chain and expiry |
| `http_headers` | Security header audit, leaky headers, cookie flags, HTTPS redirect |
| `tech_stack` | CMS/framework detection via signatures and path probing |
| `app_checks` | CORS, XSS protection, debug/API/swagger endpoint exposure |

## Legal

Only use this tool against targets you own or have explicit written authorization to test. Unauthorized scanning may violate computer fraud and abuse laws. The tool will prompt for authorization confirmation before each scan.

## License

MIT
