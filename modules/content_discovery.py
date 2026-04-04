"""Module 8 — Content discovery: security.txt, robots.txt, backup files, and admin panels.

Probes for:
- /.well-known/security.txt  (RFC 9116 — security contact disclosure)
- /robots.txt                (disallowed paths leak internal structure)
- Backup / configuration files that should never be publicly accessible
- Exposed admin panels for common DevOps & monitoring tools
"""

from __future__ import annotations

import re

import requests

from models import Finding, FindingCategory, ScanDepth, Severity
from modules.base import BaseModule


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

        return findings

    # -----------------------------------------------------------------------

    def _resolve_base(self, target: str) -> str | None:
        """Return the first reachable base URL (https first, then http)."""
        for scheme in ("https", "http"):
            self._rate_limit()
            try:
                requests.get(
                    f"{scheme}://{target}/",
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
                )
                return f"{scheme}://{target}"
            except requests.RequestException:
                continue
        return None

    def _get(self, url: str) -> requests.Response | None:
        self._rate_limit()
        try:
            return requests.get(
                url,
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
            )
        except requests.RequestException:
            return None

    def _check_security_txt(self, base_url: str, target: str, findings: list[Finding]) -> None:
        """Probe /.well-known/security.txt and /security.txt (RFC 9116)."""
        for path in ("/.well-known/security.txt", "/security.txt"):
            resp = self._get(f"{base_url}{path}")
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text[:5000]
            # Validate minimal RFC 9116 fields
            has_contact = bool(re.search(r"^Contact:", body, re.IGNORECASE | re.MULTILINE))
            has_expires = bool(re.search(r"^Expires:", body, re.IGNORECASE | re.MULTILINE))
            if has_contact:
                pgp_key = bool(re.search(r"^Encryption:", body, re.IGNORECASE | re.MULTILINE))
                findings.append(Finding(
                    title="security.txt present",
                    category=FindingCategory.APPLICATION,
                    severity=Severity.INFO,
                    evidence=(
                        f"Found at {base_url}{path}. "
                        f"Has Contact: yes, Expires: {'yes' if has_expires else 'NO'}, "
                        f"Encryption key: {'yes' if pgp_key else 'no'}"
                    ),
                    impact="Security contact is publicly disclosed — aids responsible disclosure",
                    remediation=(
                        "Keep security.txt updated. "
                        "Ensure Expires field is in the future. "
                        "Add an Encryption field pointing to a PGP key for confidential reports."
                    ) if not has_expires else "",
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
