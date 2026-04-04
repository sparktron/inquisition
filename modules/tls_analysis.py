"""Module 3 — TLS / SSL analysis."""

from __future__ import annotations

import hashlib
import ssl
import socket
from datetime import datetime, timezone
from typing import Any

from models import Finding, FindingCategory, Severity
from modules.base import BaseModule


def _get_cert_info(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Connect with TLS and return the peer certificate dict, or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even invalid certs
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return {
                    "peer_cert": tls.getpeercert(binary_form=False),
                    "peer_cert_der": tls.getpeercert(binary_form=True),
                    "version": tls.version(),
                    "cipher": tls.cipher(),
                }
    except (ssl.SSLError, socket.error, OSError):
        return None


class TlsAnalysisModule(BaseModule):
    name = "tls_analysis"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target

        if self.config.dry_run:
            findings.append(Finding(
                title="TLS analysis (dry-run)",
                category=FindingCategory.TLS,
                severity=Severity.INFO,
                evidence=f"Would perform TLS handshake with {target}:443",
            ))
            return findings

        self._rate_limit()
        info = _get_cert_info(target, 443, self.config.timeout)

        if info is None:
            findings.append(Finding(
                title="TLS handshake failed",
                category=FindingCategory.TLS,
                severity=Severity.MEDIUM,
                evidence=f"Could not establish TLS connection to {target}:443",
                impact="Site may not support HTTPS or port 443 is closed",
            ))
            return findings

        # --- Protocol version ---
        version: str = info["version"] or "unknown"
        findings.append(Finding(
            title=f"TLS version: {version}",
            category=FindingCategory.TLS,
            severity=Severity.INFO,
            evidence=f"Negotiated protocol: {version}",
        ))
        if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(Finding(
                title=f"Deprecated TLS version: {version}",
                category=FindingCategory.TLS,
                severity=Severity.HIGH,
                evidence=f"Server negotiated {version}",
                impact="Known vulnerabilities (POODLE, BEAST, etc.)",
                remediation="Disable protocols older than TLS 1.2",
            ))

        # --- Cipher suite ---
        cipher_info: tuple[str, str, int] | None = info["cipher"]
        if cipher_info:
            cipher_name, _, key_bits = cipher_info
            findings.append(Finding(
                title=f"Cipher: {cipher_name}",
                category=FindingCategory.TLS,
                severity=Severity.INFO,
                evidence=f"Cipher: {cipher_name}, key bits: {key_bits}",
            ))
            weak_markers = ("RC4", "DES", "NULL", "EXPORT", "anon")
            if any(m in cipher_name.upper() for m in weak_markers):
                findings.append(Finding(
                    title=f"Weak cipher suite: {cipher_name}",
                    category=FindingCategory.TLS,
                    severity=Severity.HIGH,
                    evidence=f"Weak cipher negotiated: {cipher_name}",
                    impact="Traffic may be decryptable",
                    remediation="Disable weak cipher suites in server configuration",
                ))

        # --- Certificate analysis ---
        cert: dict[str, Any] | None = info.get("peer_cert")
        cert_der: bytes | None = info.get("peer_cert_der")

        if cert_der:
            sha256 = hashlib.sha256(cert_der).hexdigest()
            findings.append(Finding(
                title="Certificate fingerprint",
                category=FindingCategory.TLS,
                severity=Severity.INFO,
                evidence=f"SHA-256: {sha256}",
            ))

        if cert:
            # Subject / issuer
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            cn = subject.get("commonName", "N/A")
            issuer_cn = issuer.get("commonName", "N/A")
            findings.append(Finding(
                title=f"Certificate CN: {cn}",
                category=FindingCategory.TLS,
                severity=Severity.INFO,
                evidence=f"Subject CN={cn}, Issuer CN={issuer_cn}",
            ))

            # Self-signed check
            if subject == issuer:
                findings.append(Finding(
                    title="Self-signed certificate",
                    category=FindingCategory.TLS,
                    severity=Severity.MEDIUM,
                    evidence="Certificate subject and issuer are identical",
                    impact="Browsers will show security warnings",
                    remediation="Use a certificate from a trusted CA",
                ))

            # Expiration
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    if days_left < 0:
                        findings.append(Finding(
                            title="Certificate EXPIRED",
                            category=FindingCategory.TLS,
                            severity=Severity.CRITICAL,
                            evidence=f"Expired {abs(days_left)} days ago ({not_after})",
                            impact="Browsers will block access; MITM risk",
                            remediation="Renew the certificate immediately",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title="Certificate expiring soon",
                            category=FindingCategory.TLS,
                            severity=Severity.MEDIUM,
                            evidence=f"Expires in {days_left} days ({not_after})",
                            impact="Service disruption if not renewed",
                            remediation="Renew the certificate before expiration",
                        ))
                    else:
                        findings.append(Finding(
                            title="Certificate validity",
                            category=FindingCategory.TLS,
                            severity=Severity.INFO,
                            evidence=f"Valid for {days_left} more days (until {not_after})",
                        ))
                except ValueError:
                    findings.append(Finding(
                        title="Certificate date unparseable",
                        category=FindingCategory.TLS,
                        severity=Severity.MEDIUM,
                        evidence=f"notAfter field has unexpected format: {not_after!r}",
                        impact="Cannot verify certificate expiry — manual inspection required",
                        remediation="Inspect the certificate manually with: openssl s_client -connect host:443 | openssl x509 -noout -dates",
                    ))

            # SAN check
            san = cert.get("subjectAltName", ())
            san_names = [v for t, v in san if t == "DNS"]
            if san_names:
                findings.append(Finding(
                    title="Subject Alternative Names",
                    category=FindingCategory.TLS,
                    severity=Severity.INFO,
                    evidence=f"SANs: {', '.join(san_names)}",
                ))
            if target not in san_names and f"*.{'.'.join(target.split('.')[1:])}" not in san_names:
                findings.append(Finding(
                    title="Hostname not in certificate SAN",
                    category=FindingCategory.TLS,
                    severity=Severity.MEDIUM,
                    evidence=f"{target} not listed in SANs: {san_names}",
                    impact="Certificate mismatch warning in browsers",
                    remediation="Reissue certificate to include the target hostname",
                ))

        return findings
