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

        ports: tuple[int, ...]
        if self.config.depth == ScanDepth.DEEP:
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
                    elif port in (6379, 9200):
                        severity = Severity.HIGH
                        impact = f"{service} exposed to the internet — potential data leak"
                        remediation = f"Restrict {service} to localhost or private network"
                    elif port == 3389:
                        severity = Severity.MEDIUM
                        impact = "RDP exposed — brute-force / BlueKeep risk"
                        remediation = "Restrict RDP access via VPN or firewall rules"

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
