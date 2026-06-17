"""Module 8 — Content discovery: security.txt, robots.txt, backup files, and admin panels.

Probes for:
- /.well-known/security.txt  (RFC 9116 — security contact disclosure)
- /robots.txt                (disallowed paths leak internal structure)
- Backup / configuration files that should never be publicly accessible
- Exposed admin panels for common DevOps & monitoring tools
"""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re
from urllib.parse import urlparse

from models import Confidence, Finding, FindingCategory, ScanDepth, Severity
from modules.base import BaseModule
from modules.http_client import HttpRequestException, HttpResponse


# ---------------------------------------------------------------------------
# Admin / management panel paths
# (path, label, severity, impact_hint)
# ---------------------------------------------------------------------------
_ADMIN_PANELS: list[tuple[str, str, Severity, str]] = [
    ("/kibana",             "Kibana dashboard",               Severity.HIGH,
     "Elasticsearch data visualization — full index browsing possible"),
    ("/app/kibana",         "Kibana dashboard",               Severity.HIGH,
     "Elasticsearch data visualization — full index browsing possible"),
    ("/_plugin/kibana",     "AWS OpenSearch Kibana",          Severity.HIGH,
     "Managed Kibana on AWS OpenSearch — data access without auth"),
    ("/grafana",            "Grafana dashboard",              Severity.HIGH,
     "Metric/log dashboards may expose internal topology and secrets"),
    ("/prometheus",         "Prometheus metrics",             Severity.MEDIUM,
     "Internal service metrics and endpoint discovery exposed"),
    ("/metrics",            "Prometheus /metrics endpoint",   Severity.MEDIUM,
     "Raw Prometheus metrics may expose internal service names and counts"),
    ("/actuator",           "Spring Boot Actuator",           Severity.HIGH,
     "Management endpoints may expose env vars, heap dumps, and beans"),
    ("/actuator/env",       "Spring Boot /actuator/env",      Severity.CRITICAL,
     "Full environment variables including credentials exposed"),
    ("/actuator/heapdump",  "Spring Boot heap dump",          Severity.CRITICAL,
     "JVM heap dump download — may contain in-memory secrets"),
    ("/jenkins",            "Jenkins CI",                     Severity.HIGH,
     "Build server admin access — pipeline secrets and source code"),
    ("/jenkins/script",     "Jenkins Groovy script console",  Severity.CRITICAL,
     "Remote code execution on build server via Groovy"),
    ("/gitlab",             "GitLab",                         Severity.HIGH,
     "Source code management — repo and CI/CD exposure"),
    ("/sonarqube",          "SonarQube",                      Severity.MEDIUM,
     "Code quality server — static analysis results and project lists"),
    ("/portainer",          "Portainer Docker UI",            Severity.CRITICAL,
     "Docker container management — full host control possible"),
    ("/traefik",            "Traefik dashboard",              Severity.MEDIUM,
     "Reverse proxy routing rules and backend topology exposed"),
    ("/traefik/dashboard/", "Traefik dashboard",              Severity.MEDIUM,
     "Reverse proxy routing rules and backend topology exposed"),
    ("/rabbitmq",           "RabbitMQ management UI",         Severity.HIGH,
     "Message broker admin — queue inspection and message injection"),
    ("/rabbitmq/",          "RabbitMQ management UI",         Severity.HIGH,
     "Message broker admin — queue inspection and message injection"),
    ("/consul",             "HashiCorp Consul UI",            Severity.HIGH,
     "Service mesh key-value store — secrets and service discovery"),
    ("/vault",              "HashiCorp Vault",                Severity.CRITICAL,
     "Secret management server — credential exfiltration risk"),
    ("/pgadmin",            "pgAdmin (PostgreSQL)",           Severity.HIGH,
     "Database administration interface exposed"),
    ("/adminer",            "Adminer database UI",            Severity.HIGH,
     "Multi-database admin tool — full DB access possible"),
    ("/flower",             "Celery Flower task monitor",     Severity.MEDIUM,
     "Task queue monitoring — may show job arguments containing secrets"),
    ("/airflow",            "Apache Airflow",                 Severity.HIGH,
     "Workflow orchestrator — DAG code and connection credentials exposed"),
    ("/notebook",           "Jupyter Notebook",               Severity.CRITICAL,
     "Interactive Python execution — arbitrary code on server"),
    ("/jupyter",            "Jupyter Lab/Notebook",           Severity.CRITICAL,
     "Interactive Python execution — arbitrary code on server"),
    ("/mlflow",             "MLflow tracking server",         Severity.MEDIUM,
     "ML experiment tracking — model artifacts and parameters exposed"),
]

# ---------------------------------------------------------------------------
# Backup / sensitive config file paths
# ---------------------------------------------------------------------------
_BACKUP_PATHS: list[tuple[str, str, Severity]] = [
    ("/backup.zip",         "Backup archive",          Severity.CRITICAL),
    ("/backup.tar.gz",      "Backup archive",          Severity.CRITICAL),
    ("/backup.sql",         "SQL database dump",       Severity.CRITICAL),
    ("/db.sql",             "SQL database dump",       Severity.CRITICAL),
    ("/dump.sql",           "SQL database dump",       Severity.CRITICAL),
    ("/database.sql",       "SQL database dump",       Severity.CRITICAL),
    ("/wp-config.php.bak",  "WordPress config backup", Severity.CRITICAL),
    ("/wp-config.php~",     "WordPress config backup", Severity.CRITICAL),
    ("/config.php.bak",     "PHP config backup",       Severity.HIGH),
    ("/.env.bak",           ".env backup",             Severity.CRITICAL),
    ("/.env.old",           ".env backup",             Severity.CRITICAL),
    ("/.env.prod",          "Production .env file",    Severity.CRITICAL),
    ("/.env.production",    "Production .env file",    Severity.CRITICAL),
    ("/Dockerfile",         "Dockerfile exposed",      Severity.MEDIUM),
    ("/docker-compose.yml", "Docker Compose config",   Severity.MEDIUM),
    ("/docker-compose.yaml","Docker Compose config",   Severity.MEDIUM),
    ("/.DS_Store",          "macOS .DS_Store file",    Severity.LOW),
    ("/web.config.bak",     "IIS web.config backup",   Severity.HIGH),
    ("/configuration.php.bak","Joomla config backup",  Severity.HIGH),
    ("/settings.py.bak",    "Django settings backup",  Severity.HIGH),
    ("/config.yml",         "Application config YAML", Severity.MEDIUM),
    ("/config.yaml",        "Application config YAML", Severity.MEDIUM),
    ("/.npmrc",             ".npmrc with registry tokens", Severity.HIGH),
    ("/.htpasswd",          ".htpasswd credentials",   Severity.CRITICAL),
    ("/.htaccess",          ".htaccess rules exposed",  Severity.LOW),
]

_DISCOVERED_FILE_PATTERNS: tuple[tuple[re.Pattern[str], str, Severity], ...] = (
    (re.compile(r"/\.env(?:[./_-]|$)", re.IGNORECASE), "environment file", Severity.CRITICAL),
    (re.compile(r"/\.git/(?:HEAD|config|index)$", re.IGNORECASE), "Git repository metadata", Severity.HIGH),
    (re.compile(r"\.(?:sql|sqlite|db)(?:$|[?#])", re.IGNORECASE), "database dump", Severity.CRITICAL),
    (re.compile(r"\.(?:zip|tar|tgz|tar\.gz|7z|bak|old)(?:$|[?#])", re.IGNORECASE), "backup artifact", Severity.HIGH),
    (re.compile(r"/(?:config|settings)\.(?:ya?ml|json|php|py)(?:$|[?#])", re.IGNORECASE), "configuration file", Severity.HIGH),
)
_MAX_DISCOVERED_CONTENT_URLS = 40


class ContentDiscoveryModule(BaseModule):
    name = "content_discovery"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target

        if self.config.dry_run:
            findings.append(Finding(
                title="Content discovery (dry-run)",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=(
                    f"Would probe {target} for security.txt, robots.txt, "
                    f"{len(_ADMIN_PANELS)} admin panels, {len(_BACKUP_PATHS)} backup paths"
                ),
            ))
            return findings

        base_url = self._resolve_base(target)
        if not base_url:
            return findings

        # Always check these
        self._check_security_txt(base_url, target, findings)
        self._check_robots_txt(base_url, findings)

        # Path probing — standard and deep only
        if self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            self._check_admin_panels(base_url, findings)
            self._check_backup_files(base_url, findings)
            self._check_discovered_urls(findings)

        return findings

    # -----------------------------------------------------------------------

    def _resolve_base(self, target: str) -> str | None:
        """Return the first reachable base URL (https first, then http)."""
        for scheme in ("https", "http"):
            self._rate_limit()
            try:
                self.http.get(
                    f"{scheme}://{target}/",
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=True,
                    use_cache=True,
                )
                return f"{scheme}://{target}"
            except HttpRequestException:
                continue
        return None

    def _get(self, url: str) -> HttpResponse | None:
        self._rate_limit()
        try:
            return self.http.get(
                url,
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=False,
            )
        except HttpRequestException:
            return None

    def _check_security_txt(self, base_url: str, target: str, findings: list[Finding]) -> None:
        """Probe /.well-known/security.txt and /security.txt (RFC 9116)."""
        for path in ("/.well-known/security.txt", "/security.txt"):
            resp = self._get(f"{base_url}{path}")
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text[:5000]
            # Validate minimal RFC 9116 fields
            contact_match = re.search(r"^Contact:\s*(.+)$", body, re.IGNORECASE | re.MULTILINE)
            expires_match = re.search(r"^Expires:\s*(.+)$", body, re.IGNORECASE | re.MULTILINE)
            if contact_match:
                issues: list[str] = []
                severity = Severity.INFO
                remediation = ""

                contact = contact_match.group(1).strip()
                if not re.match(r"^(https?|mailto|tel):", contact, re.IGNORECASE):
                    issues.append("Contact value is not a URI")

                expires_status = "missing"
                if expires_match:
                    expires_raw = expires_match.group(1).strip()
                    try:
                        expires_at = parsedate_to_datetime(expires_raw)
                        if expires_at.tzinfo is None:
                            expires_at = expires_at.replace(tzinfo=timezone.utc)
                        if expires_at <= datetime.now(timezone.utc):
                            expires_status = f"expired ({expires_raw})"
                            issues.append("Expires is in the past")
                        else:
                            expires_status = f"valid until {expires_raw}"
                    except (TypeError, ValueError):
                        expires_status = f"malformed ({expires_raw})"
                        issues.append("Expires value is malformed")
                else:
                    issues.append("Expires field is missing")

                if path != "/.well-known/security.txt":
                    issues.append("served from non-canonical /security.txt path")

                if issues:
                    severity = Severity.LOW
                    remediation = (
                        "Publish a valid /.well-known/security.txt with Contact and "
                        "a future Expires timestamp formatted per RFC 9116."
                    )

                pgp_key = bool(re.search(r"^Encryption:", body, re.IGNORECASE | re.MULTILINE))
                findings.append(Finding(
                    title="security.txt present" if not issues else "security.txt needs attention",
                    category=FindingCategory.APPLICATION,
                    severity=severity,
                    evidence=(
                        f"Found at {base_url}{path}. "
                        f"Contact: {contact}, Expires: {expires_status}, "
                        f"Encryption key: {'yes' if pgp_key else 'no'}"
                        + (f", Issues: {', '.join(issues)}" if issues else "")
                    ),
                    impact="Security contact is publicly disclosed — aids responsible disclosure",
                    remediation=remediation,
                ))
                return
        # Not found
        findings.append(Finding(
            title="security.txt not found",
            category=FindingCategory.APPLICATION,
            severity=Severity.LOW,
            evidence=f"Neither /.well-known/security.txt nor /security.txt returned HTTP 200 on {target}",
            impact="Security researchers have no published contact for responsible disclosure",
            remediation=(
                "Create /.well-known/security.txt per RFC 9116. "
                "Minimum fields: Contact, Expires. "
                "See https://securitytxt.org/ for a generator."
            ),
        ))

    def _check_robots_txt(self, base_url: str, findings: list[Finding]) -> None:
        """Fetch /robots.txt and flag disallowed paths that hint at internal endpoints."""
        resp = self._get(f"{base_url}/robots.txt")
        if resp is None or resp.status_code != 200:
            return

        body = resp.text[:10_000]
        disallowed = re.findall(r"^Disallow:\s*(.+)$", body, re.IGNORECASE | re.MULTILINE)
        disallowed = [d.strip() for d in disallowed if d.strip() and d.strip() != "/"]

        if not disallowed:
            findings.append(Finding(
                title="robots.txt present (no sensitive paths)",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=f"robots.txt found at {base_url}/robots.txt with no notable Disallow entries",
            ))
            return

        # Flag paths that suggest admin/dev/internal areas
        sensitive_patterns = [
            r"/admin", r"/dashboard", r"/internal", r"/staging",
            r"/dev", r"/test", r"/backup", r"/config", r"/api",
            r"/manage", r"\.json$", r"\.xml$", r"\.log$", r"\.bak$",
        ]
        sensitive = [
            path for path in disallowed
            if any(re.search(pat, path, re.IGNORECASE) for pat in sensitive_patterns)
        ]

        evidence_paths = ", ".join(disallowed[:30])
        if len(disallowed) > 30:
            evidence_paths += f" … (+{len(disallowed) - 30} more)"

        sev = Severity.INFO
        impact = ""
        remediation = ""
        if sensitive:
            sev = Severity.LOW
            impact = (
                f"Disallowed paths reveal internal structure: "
                f"{', '.join(sensitive[:10])}"
            )
            remediation = (
                "Do not rely on robots.txt for security — it is publicly readable. "
                "Protect sensitive paths with authentication and server-level ACLs."
            )

        findings.append(Finding(
            title="robots.txt discloses internal paths",
            category=FindingCategory.APPLICATION,
            severity=sev,
            evidence=f"{len(disallowed)} Disallow path(s): {evidence_paths}",
            impact=impact,
            remediation=remediation,
        ))

    @staticmethod
    def _status_confidence(status_code: int) -> Confidence:
        """How sure we are a resource really exists, given its status code.

        A 200 is a confirmed hit. An auth wall (401/403) strongly implies a real
        protected resource. A redirect (301/302) is weaker — it can be a generic
        catch-all rather than the specific resource.
        """
        if status_code == 200:
            return Confidence.CONFIRMED
        if status_code in (401, 403):
            return Confidence.HIGH
        return Confidence.MEDIUM

    def _check_admin_panels(self, base_url: str, findings: list[Finding]) -> None:
        seen: set[str] = set()
        for path, label, sev, impact in _ADMIN_PANELS:
            if label in seen:
                continue
            resp = self._get(f"{base_url}{path}")
            if resp is None:
                continue
            if resp.status_code in (200, 302, 301, 401, 403):
                # 401/403 still confirms the panel exists
                seen.add(label)
                actual_sev = sev if resp.status_code == 200 else Severity.MEDIUM
                status_note = (
                    "accessible (HTTP 200)" if resp.status_code == 200
                    else f"present but protected (HTTP {resp.status_code})"
                )
                findings.append(Finding(
                    title=f"Admin panel {status_note}: {label}",
                    category=FindingCategory.APPLICATION,
                    severity=actual_sev,
                    evidence=f"HTTP {resp.status_code} at {base_url}{path}",
                    confidence=self._status_confidence(resp.status_code),
                    impact=impact,
                    remediation=(
                        f"Restrict {label} to trusted IPs or a VPN. "
                        "Enable authentication if not already present. "
                        "Do not expose management interfaces on the public internet."
                    ),
                ))

    def _check_backup_files(self, base_url: str, findings: list[Finding]) -> None:
        for path, label, sev in _BACKUP_PATHS:
            resp = self._get(f"{base_url}{path}")
            if resp is None or resp.status_code != 200:
                continue
            # Skip tiny "not found" pages disguised as 200
            if len(resp.content) < 10:
                continue
            findings.append(Finding(
                title=f"Sensitive file exposed: {path}",
                category=FindingCategory.APPLICATION,
                severity=sev,
                evidence=f"HTTP 200 at {base_url}{path} ({len(resp.content)} bytes) — {label}",
                impact=f"{label} is publicly accessible — may contain credentials, source code, or secrets",
                remediation=(
                    f"Remove {path} from the web root immediately. "
                    "Add a web-server rule to deny access to backup/config file patterns. "
                    "Audit git history and logs for prior exposure."
                ),
            ))

    def _check_discovered_urls(self, findings: list[Finding]) -> None:
        checked = 0
        seen: set[str] = set()
        for url in self.config.discovered_urls:
            if checked >= _MAX_DISCOVERED_CONTENT_URLS:
                break
            if url in seen:
                continue
            seen.add(url)
            parsed_path = urlparse(url).path or "/"
            file_match = self._discovered_file_match(url)
            admin_match = self._discovered_admin_match(parsed_path)
            if file_match is None and admin_match is None:
                continue

            resp = self._get(url)
            checked += 1
            if resp is None or resp.status_code not in (200, 301, 302, 401, 403):
                continue

            if file_match is not None and resp.status_code == 200 and len(resp.content) >= 10:
                label, severity = file_match
                findings.append(Finding(
                    title=f"Discovered sensitive file exposed: {parsed_path}",
                    category=FindingCategory.APPLICATION,
                    severity=severity,
                    evidence=f"HTTP 200 at {url} ({len(resp.content)} bytes) — discovered {label}",
                    impact=f"{label} is publicly accessible and may contain secrets or internal data",
                    remediation=(
                        "Remove the file from the web root, deny access to backup/config patterns, "
                        "and rotate any exposed credentials."
                    ),
                    metadata={"url": url},
                ))
                continue

            if admin_match is not None:
                label, severity, impact = admin_match
                actual_sev = severity if resp.status_code == 200 else Severity.MEDIUM
                status_note = (
                    "accessible (HTTP 200)" if resp.status_code == 200
                    else f"present but protected (HTTP {resp.status_code})"
                )
                findings.append(Finding(
                    title=f"Discovered admin route {status_note}: {parsed_path}",
                    category=FindingCategory.APPLICATION,
                    severity=actual_sev,
                    evidence=f"HTTP {resp.status_code} at {url}",
                    confidence=self._status_confidence(resp.status_code),
                    impact=impact,
                    remediation=(
                        f"Confirm {label} is intended to be public. Prefer VPN/IP allowlists "
                        "for management routes and remove them from public sitemaps/robots."
                    ),
                    metadata={"url": url},
                ))

    @staticmethod
    def _discovered_file_match(url: str) -> tuple[str, Severity] | None:
        for pattern, label, severity in _DISCOVERED_FILE_PATTERNS:
            if pattern.search(url):
                return label, severity
        return None

    @staticmethod
    def _discovered_admin_match(path: str) -> tuple[str, Severity, str] | None:
        normalized = path.rstrip("/") or "/"
        for admin_path, label, severity, impact in _ADMIN_PANELS:
            admin_normalized = admin_path.rstrip("/") or "/"
            if normalized == admin_normalized or normalized.startswith(f"{admin_normalized}/"):
                return label, severity, impact
        return None
