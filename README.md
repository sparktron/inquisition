# Inquisition

**A comprehensive, read-only security reconnaissance scanner for identifying misconfigurations, exposed services, and known vulnerabilities on authorised targets.**

Inquisition probes your target across DNS, network, TLS, HTTP, application layers—then generates a detailed analysis of every issue found, explaining *why* it matters and *exactly how* to fix it. Reports include risk scoring, remediation priority matrices, and deep-dive guidance with platform-specific configuration examples.

**Read-only active reconnaissance by design.** No exploit payloads, authentication bypasses, injection attacks, login attempts, or data-modifying requests are sent. Inquisition does send non-mutating reconnaissance probes such as DNS lookups, TCP connects, HTTP `GET`/`OPTIONS`, CORS preflights, and GraphQL introspection checks, so only scan targets you are authorized to assess.

> **Current review status:** Inquisition is a useful external reconnaissance baseline, but it is not yet a complete "all clear" security assurance tool. A June 2026 code review fixed the first correctness issues and tracks remaining coverage gaps in [ROADMAP.md](ROADMAP.md). Do not rely on reports alone for production security sign-off.

## Key Features

### Reconnaissance & Fingerprinting
- **DNS reconnaissance** — A/AAAA resolution, reverse DNS, subdomain enumeration, MX/NS/TXT records, SPF/DMARC presence and policy-strength checks, **DNS zone transfer (AXFR) detection**
- **Port scanning** — TCP connect-scan with banner grabbing; enhanced service detection for Telnet, SMB, VNC, Redis, Elasticsearch, MongoDB, MySQL, PostgreSQL, RDP
- **TLS/SSL analysis** — negotiated protocol/cipher, certificate validity/expiration, self-signed detection, hostname mismatch
- **WAF/CDN detection** — Signature-based detection for common protective layers including Cloudflare, AWS CloudFront, Akamai, Fastly, Imperva, and Sucuri
- **Technology stack detection** — WordPress, Joomla, Drupal, Laravel, Django, PHP, nginx, Apache, IIS, Node.js, and more via body/header signatures and path probing

### Security Headers & Application Layer
- **HTTP header audit** — HSTS policy and preload status, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, **SameSite cookie validation**, information disclosure headers
- **Application checks** — CORS misconfiguration, XSS-Protection disabled, mixed content, missing Subresource Integrity, **GraphQL introspection**, **HTTP method Allow-header inspection**, debug endpoints, exposed API docs
- **Content discovery** — **security.txt validation (RFC 9116)**, **robots.txt path leakage**, admin panels (Kibana, Grafana, Jenkins, Jupyter, Portainer, etc.), backup files, sensitive configs (`.env`, `docker-compose.yml`, `.htpasswd`)

### Vulnerability Analysis
- **CVE correlation** — CPE-based lookup against the National Vulnerability Database (NVD) with CVSS scoring and references
- **Subdomain takeover detection** — Identifies dangling CNAMEs pointing to unclaimed Heroku apps, GitHub Pages, S3 buckets, etc.
- **Misconfiguration detection** — 30+ pattern-matched rules for common security weaknesses (expired certs, legacy TLS, missing HSTS, exposed credentials, etc.)

### Reporting & Analysis
- **Deep issue analysis** — Multi-paragraph explanations of what each vulnerability is, why it's dangerous, named CVE references, and real-world attack scenarios
- **Remediation guidance** — Step-by-step fix instructions with platform-specific examples (nginx, Apache, IIS, Docker, Kubernetes, AWS, Azure)
- **Risk scoring & grading** — Weighted numeric score (0–∞) and security grade (A+ to F) derived from all findings
- **Priority matrix** — Ranked table of CRITICAL/HIGH/MEDIUM findings sorted by severity
- **Finding deduplication** — Overlapping probes automatically collapsed to eliminate noise
- **Text, JSON, and HTML output** — HTML reports are self-contained with collapsible sections for deep dives and remediation

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Report Structure](#report-structure)
5. [Modules Reference](#modules-reference)
6. [Misconfiguration Rules](#misconfiguration-rules)
7. [Examples](#examples)
8. [Legal & Safety](#legal--safety)
9. [License](#license)

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/sparktron/inquisition.git
cd inquisition
pip install -r requirements.txt

# Run a standard scan (live scans prompt unless --yes is supplied)
python inquisition.py example.com --yes

# Full deep scan
python inquisition.py example.com --depth deep --yes

# Save HTML report
python inquisition.py example.com -o report.html --yes
```

---

## Installation

### Requirements

- **Python 3.10+** (type hints, match statements)
- **pip** (package installer)
- Optional: **dnspython** (for advanced DNS queries like zone transfer attempts; installed by requirements.txt)

### Setup

```bash
# Clone the repository
git clone https://github.com/sparktron/inquisition.git
cd inquisition

# Install dependencies
pip install -r requirements.txt

# Run directly with Python (no installation)
python inquisition.py example.com --yes
```

**Note:** The source checkout can be run directly with `python inquisition.py`. When installed with `pip install .`, the `inquisition` console script is also available.

```bash
inquisition example.com --yes
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

# 6. Internal hostname on custom port (standard scan)
python inquisition.py internal.company.local --depth standard

# 7. Dry run (preview without sending traffic)
python inquisition.py example.com --dry-run

# 8. JSON for automated parsing
python inquisition.py example.com -f json -o findings.json

# 9. Slower scanning to avoid rate-limit triggers
python inquisition.py example.com --rate-limit 0.5 --timeout 15

# 10. Custom port list (must use custom ports, not depth defaults)
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

Inquisition supports three output formats:

```bash
python inquisition.py example.com -f text    # Human-readable (default)
python inquisition.py example.com -f html    # Self-contained HTML with collapsible sections
python inquisition.py example.com -f json    # Machine-readable JSON for parsing/integration
```

When using `--output`, the format is inferred from the file extension:

```bash
python inquisition.py example.com -o report.html   # → HTML format
python inquisition.py example.com -o report.json   # → JSON format
python inquisition.py example.com -o report.txt    # → Text format
```

### Options Reference

#### Target & Scope
| Option | Type | Default | Description |
|---|---|---|---|
| `target` | string | *required* | Hostname, IP address, or internal DNS name |
| `-d`, `--depth` | `quick` \| `standard` \| `deep` | `standard` | Scan depth: controls ports and path probing |
| `--ports` | list of ints | 20 well-known | Override default ports (e.g. `--ports 22 80 443 8080`) |

#### Output & Reporting
| Option | Type | Default | Description |
|---|---|---|---|
| `-f`, `--format` | `text` \| `json` \| `html` | `text` | Report output format |
| `-o`, `--output` | path | stdout | Write report to file (extension infers format) |
| `--brief` | flag | off | Omit deep-dive analysis and remediation sections |

#### Concurrency & Timing
| Option | Type | Default | Description |
|---|---|---|---|
| `-t`, `--threads` | int | 10 | Max concurrent threads per module |
| `--rate-limit` | float (seconds) | 0.1 | Minimum delay between requests within a module |
| `--timeout` | float (seconds) | 10.0 | Per-request timeout for HTTP, TLS, DNS, and API operations |
| `--connect-timeout` | float (seconds) | 2.0 | TCP connect timeout for port scanning |

#### Testing & Debugging
| Option | Type | Default | Description |
|---|---|---|---|
| `--dry-run` | flag | off | Preview scan without sending any traffic |
| `--yes`, `--i-am-authorized` | flag | off | Confirm authorization and skip the interactive live-scan prompt |
| `-v`, `--verbose` | flag | off | Enable debug logging to stderr |

#### Active Testing
| Option | Type | Default | Description |
|---|---|---|---|
| `--active` | flag | off | Enable payload-based active scanning after the explicit active-scan authorization prompt |
| `--active-engine` | `nuclei` \| `zap` | `nuclei` | Active scanner engine to run when `--active` is set |
| `--auth-header` | string | empty | Header injected into HTTP modules and active engines, e.g. `Authorization: Bearer <token>` |
| `--auth-cookie` | string | empty | Cookie header injected into HTTP modules and active engines, e.g. `session=<value>` |

### Safety

**Inquisition is safe by design:**

- ✅ All probes are **read-only active checks** — no exploit payloads, no login attempts, no injection, and no data-modifying requests
- ✅ **Rate limiting** to avoid overwhelming targets (default 0.1s between requests)
- ✅ **Timeout controls** to gracefully handle slow/hanging connections
- ✅ **Dry-run mode** (`--dry-run`) previews what would be scanned without sending any traffic

---

## Report Structure

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

---

## Modules Reference

Inquisition runs 8 specialised modules concurrently, each with a specific focus:

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
- Negotiated cipher analysis (flags RC4, DES, NULL, EXPORT, anonymous ciphers if negotiated)
- Certificate fingerprint (SHA-256)
- Self-signed certificate detection
- Certificate expiry and validity period
- Hostname mismatch in Subject Alternative Names (SAN)
- Certificate parsing for subject, issuer, expiry, and SAN fields

**Severity:** CRITICAL for expired certs; HIGH for legacy protocols/weak ciphers

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
- Header quality checks for weak HSTS max-age, missing `includeSubDomains` /
  `preload`, inactive HSTS preload status, permissive CSP sources, invalid
  defensive header values, broad Permissions-Policy, and cookie prefix rules
- HTTP-to-HTTPS redirect

**Severity:** MEDIUM for missing or weak HSTS/CSP; MEDIUM for insecure cookies

---

### 5. Technology Stack Detection (`tech_stack`)
**What it does:** Fingerprints CMS, frameworks, and server software.

**Detection methods:**
- Body signature matching (regex patterns in HTML)
- Header signature matching (Server, X-Powered-By, X-Generator)
- Path probing for known endpoints (wp-login.php, /administrator/, /phpmyadmin/, etc.)

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
- Mixed-content references on the HTTPS homepage
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

**Severity:** CRITICAL for exposed `.env` and backups; HIGH for admin panels; MEDIUM for docker-compose.yml, Dockerfile; LOW for .DS_Store

---

## Misconfiguration Rules

The misconfiguration engine derives higher-level findings from raw module output using a curated rule set:

### TLS/Certificate
- ✗ Expired TLS certificate (CRITICAL)
- ✗ Self-signed certificate (MEDIUM)
- ✗ Legacy TLS enabled — TLS 1.0/1.1 (HIGH)
- ✗ Weak cipher suites (HIGH)
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

## Risk Scoring & Security Grade

### Scoring Formula

Each finding is weighted by severity:

| Severity | Weight |
|---|---|
| CRITICAL | 40 |
| HIGH | 15 |
| MEDIUM | 5 |
| LOW | 1 |
| INFO | 0 |

**Risk Score = Sum of (finding count × severity weight)**

### Security Grade

| Grade | Score | Assessment |
|---|---|---|
| **A+** | 0 | No findings — clean bill of health |
| **A** | 1–9 | Negligible — informational findings only |
| **B** | 10–24 | Minor — low-severity issues present |
| **C** | 25–49 | Moderate — medium-severity issues require attention |
| **D** | 50–99 | Significant risk — high-severity issues present |
| **F** | 100+ | Critical — immediate action required; high-risk exposure |

---

## Report Sections

Every scan generates the following sections (unless `--brief` is used):

| Section | Content |
|---|---|
| **Executive Summary** | Finding counts by severity, CVE count, misconfiguration count, risk score, security grade |
| **Remediation Priority Matrix** | Ranked CRITICAL → HIGH → MEDIUM findings for quick triage |
| **Detailed Findings** | Per-finding evidence, impact, quick fix, CPE, recommended tools |
| **Deep Issue Analysis** | Multi-paragraph explanation: what is the vulnerability, why is it dangerous, real-world attacks, named CVEs *(omitted with `--brief`)* |
| **Remediation Guide** | Step-by-step fix instructions with platform-specific examples (nginx, Apache, IIS, Docker, K8s, AWS, Azure) *(omitted with `--brief`)* |
| **CVE Correlation** | CVEs matched to detected CPEs via NVD API, with CVSS scores and references |
| **Misconfiguration Summary** | Higher-level patterns derived from findings |
| **Tool Reference** | Recommended open-source tools for deeper investigation by category |
| **Scan Metadata** | Scan duration, configuration, and any errors encountered |

---

## Examples

### Example 1: Basic Target Assessment

```bash
$ python inquisition.py example.com

[*] Inquisition Security Reconnaissance Scanner

 ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
 ┃  AUTHORIZATION REQUIRED                                              ┃
 ┃  Do you have permission to scan: example.com?                        ┃
 ┃  This tool is designed for authorised security testing only.        ┃
 ┃  Unauthorised scanning may violate laws.                             ┃
 ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Confirm [y/n]: y

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
$ python inquisition.py example.com -o report.html --depth deep

[*] Starting scan of example.com (depth=deep)
...
[*] Report saved to: report.html
```

The generated HTML report includes:
- Severity-coloured finding cards
- Collapsible "Issue Analysis" and "Remediation Steps" sections
- CVE table with CVSS scores
- No external dependencies (fully self-contained)

### Example 3: JSON Export for Automation

```bash
$ python inquisition.py example.com -f json -o findings.json

$ jq '.findings[] | select(.severity=="CRITICAL")' findings.json

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
- ✅ Live scans require interactive authorization or `--yes` / `--i-am-authorized`

Optional `--active` mode is different: it shells out to Nuclei or OWASP ZAP and
may send payload-based vulnerability probes after a second, explicit active-scan
authorization prompt. Use it only where you have written permission for active
testing.

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

### Development validation

Run the local checks before opening a pull request:

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
python -m mypy .
python inquisition.py example.com --dry-run --format json --output /tmp/inquisition-dry-run.json
```

The test suite includes deterministic recorded HTTP/DNS/socket fixtures for
network-facing modules; tests should not require live external targets.

Deep remediation text is stored as structured package data in
`modules/data/analysis_kb.json` and loaded through `analysis_kb.py`. Keep the
schema test passing whenever adding or editing knowledge-base entries.

For bug reports or feature requests, provide:
- Description of the issue
- Steps to reproduce (if applicable)
- Expected vs. actual behaviour
- Scan output (sanitise any sensitive data)

---

**Last updated:** April 2026
