# inquisition

A read-only website fingerprinting and security reconnaissance tool. Identifies technologies, frameworks, open ports, TLS configuration, HTTP security headers, and known vulnerabilities on a target host.

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

- Python 3.8+
- `pip install -r requirements.txt`

## Installation

```bash
git clone https://github.com/sparktron/inquisition.git
cd inquisition
pip install -r requirements.txt
```

## Usage

```bash
./inquisition <target> [options]
```

The target is a hostname or IP address (e.g. `example.com` or `93.184.216.34`).

### Auto mode

Run a full deep assessment with no user interaction:

```bash
./inquisition --auto example.com
```

Auto mode sets scan depth to `deep` and suppresses the authorization prompt. Use this for scripted or unattended runs where you have pre-authorized the target.

### Standard scan

```bash
./inquisition example.com
```

Prompts for authorization confirmation, then runs a standard-depth scan.

### Options

```
positional arguments:
  target                Hostname or IP address to scan

options:
  --auto                Full deep assessment, no user interaction
  -d, --depth           Scan depth: quick | standard (default) | deep
  -f, --format          Output format: text (default) | json
  -t, --threads         Concurrent threads (default: 10)
  --rate-limit          Seconds between requests (default: 0.1)
  --timeout             Per-request timeout in seconds (default: 10)
  --dry-run             Simulate scan without sending network traffic
  -y, --yes             Skip the authorization prompt
  --no-safe-mode        Disable read-only restrictions (not recommended)
```

### Scan depths

| Depth | Ports scanned | Checks |
|---|---|---|
| `quick` | 5 core ports (22, 80, 443, 8080, 8443) | Basic checks only |
| `standard` | 20 well-known ports | Standard checks including path probing |
| `deep` | Full 1–1024 range | All checks, thorough probing |

### Examples

```bash
# Auto mode — full deep scan, no prompts
./inquisition --auto example.com

# Quick scan, skip auth prompt
./inquisition -d quick -y example.com

# Deep scan with JSON output
./inquisition -d deep -f json example.com

# Save report to file
./inquisition --auto example.com > report.txt

# Save JSON report
./inquisition --auto -f json example.com > report.json

# Dry run — no network traffic
./inquisition --dry-run example.com
```

## Output

Text output includes:

- Executive summary with severity breakdown
- Remediation priority matrix
- Detailed findings grouped by severity
- CVE correlation results
- Misconfiguration summary
- Tool reference table (Nmap, testssl.sh, Nuclei, WPScan, etc.)

JSON output contains the same data in structured form suitable for ingestion by other tools.

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

Only use this tool against targets you own or have explicit written authorization to test. Unauthorized scanning may violate computer fraud and abuse laws.

## License

MIT
