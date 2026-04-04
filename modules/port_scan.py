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
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch",
}

# Extended port list for deep scans
_DEEP_PORTS = tuple(range(1, 1025))


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
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.config.timeout)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        # Attempt banner grab (safe, read-only)
                        try:
                            sock.sendall(b"\r\n")
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
