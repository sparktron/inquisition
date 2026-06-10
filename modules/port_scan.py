"""Module 2 — TCP port scanning (connect-scan only, no raw packets)."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from models import Finding, FindingCategory, ScanDepth, Severity
from modules.base import BaseModule

if TYPE_CHECKING:
    pass

# Well-known service names for common ports
_SERVICE_HINTS: dict[int, str] = {
    # Network services
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    110: "POP3", 143: "IMAP", 445: "SMB",
    993: "IMAPS", 995: "POP3S",
    # Web services
    80: "HTTP", 443: "HTTPS",
    3000: "Node.js/Rails", 3001: "Node.js/Rails", 3002: "Node.js", 3003: "Node.js",
    4200: "Angular", 5000: "Flask/Django", 5173: "Vite",
    8000: "HTTP", 8001: "HTTP", 8008: "HTTP", 8080: "HTTP-Alt", 8081: "HTTP-Alt",
    8082: "HTTP-Alt", 8083: "HTTP-Alt", 8088: "HTTP-Alt", 8090: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt/Jupyter", 9000: "HTTP", 9090: "HTTP",
    # Databases
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    # Enterprise servers
    7001: "WebLogic", 7474: "Neo4j", 8010: "Tomcat", 8086: "InfluxDB",
    8161: "ActiveMQ", 8686: "GlassFish", 9200: "Elasticsearch", 9300: "Elasticsearch-Node",
    # Other services
    2375: "Docker", 2376: "Docker-Secure", 3389: "RDP", 5005: "JDebug", 5555: "ADB",
    5900: "VNC", 5984: "CouchDB", 6443: "Kubernetes", 10250: "Kubelet",
}

# Comprehensive web server ports for deep scans
# Includes: standard HTTP/HTTPS, common app server ports, development frameworks,
# cloud platforms, containerization, monitoring, and enterprise application servers
_WEBSERVER_PORTS = (
    # Standard web
    80, 443,
    # HTTP alternates (common web servers and proxies)
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8099, 8888, 8889,
    # HTTPS alternates
    8443, 8444, 8445, 8446, 8447, 8448, 8449, 8453, 8454,
    # High-number HTTP ports
    9000, 9001, 9090, 9091, 9099, 9443, 9999,
    # JavaScript/Node.js frameworks
    3000, 3001, 3002, 3003, 3004, 3005,
    # More app server ports
    4000, 4200, 4443, 4567, 5000, 5005, 5173, 5174, 5432, 5443, 5500, 5555, 5600,
    6000, 6001, 6080, 6443, 6545, 6789, 6969,
    7000, 7001, 7080, 7175, 7547, 7777, 7778, 7779,
    # Enterprise app servers (Tomcat, JBoss, WebLogic, etc.)
    8010, 8020, 8025, 8030, 8040, 8050, 8060, 8070, 8160, 8161, 8200,
    # Container and cloud platforms
    2375, 2376,  # Docker
    6443,        # Kubernetes API
    8042, 8088,  # Hadoop YARN
    8480, 8481,  # JBoss
    9200, 9300,  # Elasticsearch
    # Databases (sometimes exposed as web services)
    3306,        # MySQL
    5432,        # PostgreSQL
    6379,        # Redis
    27017, 27018, 27019, 27020,  # MongoDB
    # Monitoring and admin panels
    8161, 8162,  # ActiveMQ
    8686, 8687,  # GlassFish
    9999,        # Various admin panels
    # Miscellaneous services
    1080, 1433, 1521, 1944, 2181, 3128, 3389, 5005, 5555, 5900, 5984, 6379, 7474,
    7687, 8012, 8020, 8086, 8140, 8500, 8834, 9042, 9160, 9300, 9999, 10000, 10250,
)

# Extended port list for deep scans (all well-known ports 1-1024 + webserver high ports)
_DEEP_PORTS = tuple(sorted(set(
    tuple(range(1, 1025)) + _WEBSERVER_PORTS
)))

_BANNER_PROBE_PORTS = {
    21, 22, 25, 110, 143, 587, 993, 995,
}


class PortScanModule(BaseModule):
    name = "port_scan"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target

        # Custom ports supplied via --ports always override depth defaults.
        _default_ports: tuple[int, ...] = (
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
        )
        ports: tuple[int, ...]
        if self.config.ports != _default_ports:
            # User explicitly specified ports — honour them regardless of depth
            ports = self.config.ports
        elif self.config.depth == ScanDepth.DEEP:
            ports = _DEEP_PORTS
        elif self.config.depth == ScanDepth.QUICK:
            ports = (22, 80, 443, 8080, 8443)
        else:
            ports = self.config.ports

        if self.config.dry_run:
            findings.append(Finding(
                title="Port scan (dry-run)",
                category=FindingCategory.PORT,
                severity=Severity.INFO,
                evidence=f"Would scan {len(ports)} ports on {target}",
            ))
            return findings

        open_ports: list[tuple[int, str]] = []

        def _probe(port: int) -> tuple[int, bool, str]:
            banner = ""
            try:
                self._rate_limit()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.config.connect_timeout)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        if port in _BANNER_PROBE_PORTS:
                            try:
                                banner = sock.recv(1024).decode(errors="replace").strip()
                            except (socket.timeout, OSError):
                                pass
                        return port, True, banner
            except OSError:
                pass
            return port, False, ""

        with ThreadPoolExecutor(max_workers=self.config.max_threads) as pool:
            futures = {pool.submit(_probe, p): p for p in ports}
            for future in as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    service = _SERVICE_HINTS.get(port, "unknown")
                    open_ports.append((port, service))
                    evidence = f"Port {port}/{service} is open"
                    if banner:
                        evidence += f" — banner: {banner[:200]}"

                    severity = Severity.INFO
                    remediation = ""
                    impact = ""

                    # Flag risky services
                    if port == 23:
                        severity = Severity.HIGH
                        impact = "Telnet transmits credentials in cleartext"
                        remediation = "Disable Telnet and use SSH instead"
                    elif port == 21:
                        severity = Severity.MEDIUM
                        impact = "FTP transmits credentials in cleartext; anonymous access may be enabled"
                        remediation = "Disable FTP; use SFTP/FTPS instead. If required, disable anonymous login"
                    elif port == 445:
                        severity = Severity.HIGH
                        impact = "SMB exposed — EternalBlue/WannaCry exploitation risk if unpatched"
                        remediation = "Block SMB (445) at the firewall; apply MS17-010 patch; disable SMBv1"
                    elif port == 5900:
                        severity = Severity.HIGH
                        impact = "VNC exposed — remote desktop access with potentially weak auth"
                        remediation = "Restrict VNC to localhost or VPN; enable strong password/NLA"
                    elif port in (6379, 9200):
                        severity = Severity.HIGH
                        impact = f"{service} exposed to the internet — unauthenticated data access possible"
                        remediation = f"Restrict {service} to localhost or private network; enable authentication"
                    elif port == 27017:
                        severity = Severity.HIGH
                        impact = "MongoDB exposed — unauthenticated access may allow full DB read/write"
                        remediation = "Bind MongoDB to localhost; enable --auth; block port 27017 at firewall"
                    elif port == 5432:
                        severity = Severity.MEDIUM
                        impact = "PostgreSQL exposed to internet — brute-force / misconfigured pg_hba.conf risk"
                        remediation = "Restrict PostgreSQL to trusted IPs; enforce strong passwords and SSL"
                    elif port == 3306:
                        severity = Severity.MEDIUM
                        impact = "MySQL exposed to internet — brute-force and data exfiltration risk"
                        remediation = "Restrict MySQL to localhost or trusted IPs; disable root remote login"
                    elif port == 3389:
                        severity = Severity.MEDIUM
                        impact = "RDP exposed — brute-force / BlueKeep (CVE-2019-0708) risk"
                        remediation = "Restrict RDP access via VPN or firewall rules; enable NLA; patch BlueKeep"
                    elif port in (8080, 8443):
                        severity = Severity.LOW
                        impact = f"Alternate HTTP/S port {port} open — may expose dev server or admin panel"
                        remediation = "Verify this port intentionally serves traffic; restrict if it is a debug/dev endpoint"

                    findings.append(Finding(
                        title=f"Open port: {port}/{service}",
                        category=FindingCategory.PORT,
                        severity=severity,
                        evidence=evidence,
                        impact=impact,
                        remediation=remediation,
                    ))

        if not open_ports:
            findings.append(Finding(
                title="No open ports detected",
                category=FindingCategory.PORT,
                severity=Severity.INFO,
                evidence=f"Scanned {len(ports)} ports — none responded",
            ))

        return findings
