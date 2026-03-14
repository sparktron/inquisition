"""Module 1 — DNS reconnaissance."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

from inquisition.models import Finding, FindingCategory, Severity
from inquisition.modules.base import BaseModule

if TYPE_CHECKING:
    pass

# Common subdomains to probe in deeper scans
_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "blog", "dev", "staging", "api", "admin", "vpn", "cdn", "app",
]


def _safe_dns_resolve(hostname: str, timeout: float) -> list[str]:
    """Resolve a hostname, returning IP addresses or an empty list on failure."""
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({r[4][0] for r in results})
    except (socket.gaierror, socket.timeout, OSError):
        return []


class DnsReconModule(BaseModule):
    name = "dns_recon"

    def run(self) -> list[Finding]:
        from inquisition.models import ScanDepth

        findings: list[Finding] = []
        target = self.config.target

        if self.config.dry_run:
            findings.append(Finding(
                title="DNS resolution (dry-run)",
                category=FindingCategory.DNS,
                severity=Severity.INFO,
                evidence=f"Would resolve {target} and check common subdomains",
            ))
            return findings

        # --- A / AAAA resolution ---
        self._rate_limit()
        ips = _safe_dns_resolve(target, self.config.timeout)
        if ips:
            findings.append(Finding(
                title="DNS A/AAAA records",
                category=FindingCategory.DNS,
                severity=Severity.INFO,
                evidence=f"{target} resolves to: {', '.join(sorted(ips))}",
            ))
        else:
            findings.append(Finding(
                title="DNS resolution failed",
                category=FindingCategory.DNS,
                severity=Severity.MEDIUM,
                evidence=f"Could not resolve {target}",
                impact="Target may be unreachable or hostname is invalid",
            ))
            return findings

        # --- Reverse DNS ---
        for ip in ips:
            self._rate_limit()
            try:
                hostname_rev = socket.gethostbyaddr(ip)[0]
                findings.append(Finding(
                    title="Reverse DNS",
                    category=FindingCategory.DNS,
                    severity=Severity.INFO,
                    evidence=f"{ip} -> {hostname_rev}",
                ))
            except (socket.herror, socket.gaierror, OSError):
                pass

        # --- Subdomain enumeration (standard + deep) ---
        if self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            for sub in _COMMON_SUBDOMAINS:
                fqdn = f"{sub}.{target}"
                self._rate_limit()
                sub_ips = _safe_dns_resolve(fqdn, self.config.timeout)
                if sub_ips:
                    findings.append(Finding(
                        title=f"Subdomain found: {fqdn}",
                        category=FindingCategory.DNS,
                        severity=Severity.INFO,
                        evidence=f"{fqdn} -> {', '.join(sorted(sub_ips))}",
                    ))

        # --- MX / NS via dnspython (optional) ---
        try:
            import dns.resolver  # type: ignore[import-untyped]

            for qtype in ("MX", "NS", "TXT"):
                self._rate_limit()
                try:
                    answers = dns.resolver.resolve(target, qtype, lifetime=self.config.timeout)
                    records = [str(r) for r in answers]
                    findings.append(Finding(
                        title=f"DNS {qtype} records",
                        category=FindingCategory.DNS,
                        severity=Severity.INFO,
                        evidence=f"{qtype}: {', '.join(records)}",
                    ))
                    # Check for SPF / DMARC in TXT
                    if qtype == "TXT":
                        all_txt = " ".join(records).lower()
                        if "v=spf1" not in all_txt:
                            findings.append(Finding(
                                title="Missing SPF record",
                                category=FindingCategory.MISCONFIGURATION,
                                severity=Severity.MEDIUM,
                                evidence=f"No SPF TXT record found for {target}",
                                impact="Email spoofing may be possible",
                                remediation="Add an SPF TXT record to the domain",
                            ))
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass

            # DMARC check
            self._rate_limit()
            try:
                dmarc = dns.resolver.resolve(f"_dmarc.{target}", "TXT", lifetime=self.config.timeout)
                findings.append(Finding(
                    title="DMARC record found",
                    category=FindingCategory.DNS,
                    severity=Severity.INFO,
                    evidence=f"DMARC: {', '.join(str(r) for r in dmarc)}",
                ))
            except Exception:
                findings.append(Finding(
                    title="Missing DMARC record",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    evidence=f"No DMARC record at _dmarc.{target}",
                    impact="Email spoofing / phishing risk",
                    remediation="Add a DMARC TXT record at _dmarc.<domain>",
                ))
        except ImportError:
            pass  # dnspython not installed — skip advanced DNS

        return findings
