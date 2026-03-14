# inquisition

A website fingerprinting and security reconnaissance tool that identifies open ports, DNS records, TLS configuration, HTTP security headers, tech stack, and application-level issues — then correlates findings against known CVEs.

## Features

- **Port scanning** — probes common ports and identifies running services
- **DNS reconnaissance** — enumerates DNS records (A, MX, TXT, NS, etc.)
- **TLS analysis** — checks certificate validity, cipher suites, and protocol versions
- **HTTP header inspection** — flags missing or misconfigured security headers
- **Tech stack detection** — identifies web frameworks, CMS platforms, and JavaScript libraries
- **Application checks** — looks for exposed admin panels, sensitive paths, and common misconfigurations
- **CVE correlation** — maps detected software (via CPE) to known CVEs via the NVD
- **Misconfiguration analysis** — derives higher-level security issues from raw findings
- Output in plain text or JSON format

## Requirements

- Python 3.10+
- pip

## Installation

### From source

```bash
git clone https://github.com/sparktron/inquisition.git
cd inquisition
pip install -r requirements.txt
pip install -e .
```

### Using pip

```bash
pip install inquisition
```

## Usage

```
inquisition [-h] [-d {quick,standard,deep}] [-f {text,json}]
            [-t THREADS] [--safe-mode] [--no-safe-mode]
            [--dry-run] [--rate-limit RATE_LIMIT] [--timeout TIMEOUT]
            [-y]
            target
```

The `target` is a **hostname or IP address** (e.g. `example.com` or `93.184.216.34`).

### Basic scan

```bash
inquisition example.com
```

Before sending any traffic, inquisition displays an authorization banner and asks you to confirm that you have permission to scan the target. Use `-y` to skip this prompt in automated workflows.

### Scan depth

```bash
# Quick — top ports only, basic checks
inquisition example.com -d quick

# Standard (default) — balanced coverage
inquisition example.com -d standard

# Deep — full port range, thorough probing
inquisition example.com -d deep
```

### Output format

```bash
# Human-readable text (default)
inquisition example.com -f text

# Machine-readable JSON
inquisition example.com -f json

# Save JSON report to a file
inquisition example.com -f json > report.json
```

### Safe mode

Safe mode (enabled by default) restricts all probes to read-only operations — no exploit payloads, no authentication bypass attempts, no injection. Disable it only when you have explicit authorization and understand the implications.

```bash
# Safe mode on (default)
inquisition example.com --safe-mode

# Disable safe mode
inquisition example.com --no-safe-mode
```

### Dry run

Preview the scan configuration without sending any network traffic:

```bash
inquisition example.com --dry-run
```

### Concurrency and rate limiting

```bash
# Custom thread count (default: 10)
inquisition example.com -t 5

# Minimum seconds between requests (default: 0.1)
inquisition example.com --rate-limit 0.5

# Per-request timeout in seconds (default: 10)
inquisition example.com --timeout 30
```

### Skip authorization prompt

```bash
inquisition example.com -y
```

### Full options reference

| Flag | Default | Description |
|------|---------|-------------|
| `target` | — | Hostname or IP to scan |
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

## Legal

Only use this tool against targets you own or have explicit permission to test. Unauthorized scanning may violate computer fraud laws. The tool will prompt for authorization confirmation before each scan.

## License

MIT
