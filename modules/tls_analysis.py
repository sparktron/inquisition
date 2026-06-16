"""Module 3 — TLS / SSL analysis."""

from __future__ import annotations

import hashlib
import os
import ssl
import socket
import tempfile
import warnings
import _ssl
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, cast

from models import Finding, FindingCategory, Severity
from modules.base import BaseModule
from tls_chain import analyze_scts, check_ocsp, fetch_verified_chain, probe_dh_parameters


def _get_cert_info(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Connect with TLS and return the peer certificate dict, or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even invalid certs
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert_der = tls.getpeercert(binary_form=True)
                return {
                    "peer_cert": _decode_cert_der(cert_der) if cert_der else {},
                    "peer_cert_der": cert_der,
                    "version": tls.version(),
                    "cipher": tls.cipher(),
                }
    except (ssl.SSLError, socket.error, OSError):
        return None


def _decode_cert_der(cert_der: bytes) -> dict[str, Any]:
    """Decode DER certificate bytes into the dict shape returned by SSLSocket."""
    tmp_name = ""
    try:
        pem = ssl.DER_cert_to_PEM_cert(cert_der)
        with tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False) as tmp:
            tmp.write(pem)
            tmp_name = tmp.name
        decode_cert = cast(Callable[[str], dict[str, Any]], getattr(_ssl, "_test_decode_cert"))
        return decode_cert(tmp_name)
    except (OSError, ValueError, ssl.SSLError):
        return {}
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


# Protocols to actively probe. SSLv2/SSLv3 are omitted because modern OpenSSL
# builds refuse to even attempt them, which would make a negative result
# meaningless rather than informative.
_PROBE_PROTOCOLS: list[tuple[str, ssl.TLSVersion]] = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

_DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1"}

# OpenSSL cipher-selection strings for known-weak families. The scanner's own
# OpenSSL may refuse to offer some of these (set_ciphers raises) — in that case
# the family simply cannot be tested and nothing is reported for it.
_WEAK_CIPHER_PROBES: list[tuple[str, str]] = [
    ("RC4", "RC4"),
    ("3DES/DES", "3DES:DES"),
    ("NULL", "NULL"),
    ("EXPORT", "EXPORT"),
]


def _supports_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    """Return True if the server completes a handshake pinned to ``version``."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, OSError):
        # This OpenSSL build cannot pin that version — treat as untestable.
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def _accepts_cipher(host: str, port: int, openssl_cipher: str, timeout: float) -> bool:
    """Return True if the server completes a handshake using ``openssl_cipher``."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # Weak ciphers exist only in TLS 1.2 and earlier.
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, OSError):
        pass
    try:
        ctx.set_ciphers(openssl_cipher)
    except ssl.SSLError:
        # The scanner's OpenSSL won't offer this family — cannot test it.
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


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
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ssl.match_hostname(cert, target)
            except ssl.CertificateError as exc:
                findings.append(Finding(
                    title="Hostname not in certificate SAN",
                    category=FindingCategory.TLS,
                    severity=Severity.MEDIUM,
                    evidence=f"{target} does not match certificate names: {exc}",
                    impact="Certificate mismatch warning in browsers",
                    remediation="Reissue certificate to include the target hostname",
                ))
        elif cert_der:
            findings.append(Finding(
                title="Certificate parse failed",
                category=FindingCategory.TLS,
                severity=Severity.MEDIUM,
                evidence="Certificate bytes were retrieved but could not be parsed",
                impact="Certificate validity, expiration, and hostname matching could not be verified",
                remediation="Inspect the certificate manually with: openssl s_client -connect host:443 | openssl x509 -noout -text",
            ))

        # --- Active protocol & weak-cipher enumeration ---
        # The handshake above reports only the single negotiated protocol/cipher.
        # These probes actively test what the server is *willing* to accept.
        self._enumerate_protocols(target, findings)
        self._probe_weak_ciphers(target, findings)

        # --- Chain validation, Certificate Transparency, OCSP revocation ---
        self._check_chain_ct_ocsp(target, cert_der, findings)

        # --- Diffie-Hellman key-exchange parameter strength ---
        self._check_dh_parameters(target, findings)

        return findings

    def _check_dh_parameters(self, target: str, findings: list[Finding]) -> None:
        """Flag weak finite-field DH groups (Logjam-class) via a forced DHE handshake."""
        self._rate_limit()
        dh = probe_dh_parameters(target, 443, self.config.timeout)
        if not dh.tested or dh.kex_type.upper() != "DH" or dh.bits <= 0:
            # Untestable, or server uses ECDHE/TLS 1.3 — no finite-field DH weakness.
            return

        if dh.bits < 1024:
            findings.append(Finding(
                title=f"Export-grade DH parameters: {dh.bits}-bit",
                category=FindingCategory.TLS,
                severity=Severity.HIGH,
                evidence=f"Server completed a TLS 1.2 DHE handshake with a {dh.bits}-bit DH group",
                impact="Sub-1024-bit DH is trivially broken (Logjam); ephemeral keys offer no real protection",
                remediation="Disable export/weak DHE cipher suites; use 2048-bit+ DH groups or prefer ECDHE",
            ))
        elif dh.bits == 1024:
            findings.append(Finding(
                title="Weak 1024-bit DH parameters",
                category=FindingCategory.TLS,
                severity=Severity.MEDIUM,
                evidence="Server completed a TLS 1.2 DHE handshake with a 1024-bit DH group",
                impact="1024-bit DH is within reach of well-resourced attackers (Logjam precomputation)",
                remediation="Use a 2048-bit+ DH group (or custom dhparam) or prefer ECDHE cipher suites",
            ))
        elif dh.bits < 2048:
            findings.append(Finding(
                title=f"Undersized DH parameters: {dh.bits}-bit",
                category=FindingCategory.TLS,
                severity=Severity.LOW,
                evidence=f"Server completed a TLS 1.2 DHE handshake with a {dh.bits}-bit DH group",
                impact="DH groups below 2048 bits fall short of current strength recommendations",
                remediation="Use a 2048-bit+ DH group or prefer ECDHE cipher suites",
            ))
        else:
            findings.append(Finding(
                title=f"DH parameters: {dh.bits}-bit",
                category=FindingCategory.TLS,
                severity=Severity.INFO,
                evidence=f"Server offers finite-field DHE with a {dh.bits}-bit group",
            ))

    def _check_chain_ct_ocsp(
        self, target: str, leaf_der: bytes | None, findings: list[Finding]
    ) -> None:
        """Validate the full chain against trusted CAs, then check CT and OCSP.

        Uses a separate, trust-store-verified handshake (the primary handshake
        deliberately disables verification so it can inspect broken certs). The
        verified chain also supplies the issuer certificate needed for OCSP.
        """
        self._rate_limit()
        chain = fetch_verified_chain(target, 443, self.config.timeout)

        if chain.untested:
            # Could not perform the verified handshake at all (network error).
            # The primary handshake already reported connectivity; stay quiet.
            return

        if chain.verified:
            findings.append(Finding(
                title="Certificate chain trusted",
                category=FindingCategory.TLS,
                severity=Severity.INFO,
                evidence=f"Chain of {chain.chain_length} certificate(s) validates against the system trust store",
            ))
        else:
            findings.append(Finding(
                title="Certificate chain not trusted",
                category=FindingCategory.TLS,
                severity=Severity.MEDIUM,
                evidence=f"Verified handshake failed: {chain.error}",
                impact="Browsers will warn or block; often an incomplete intermediate chain, expired, or untrusted CA",
                remediation="Serve the full intermediate chain and use a certificate from a publicly trusted CA",
            ))

        # Prefer the verified leaf; fall back to the primary handshake's leaf.
        verified_leaf = chain.chain_der[0] if chain.chain_der else None
        sct_target = verified_leaf or leaf_der
        if sct_target is not None:
            sct = analyze_scts(sct_target)
            if sct.present:
                findings.append(Finding(
                    title="Certificate Transparency SCTs present",
                    category=FindingCategory.TLS,
                    severity=Severity.INFO,
                    evidence=f"Certificate embeds {sct.count} signed certificate timestamp(s)",
                ))
            elif not sct.error:
                findings.append(Finding(
                    title="No embedded Certificate Transparency SCTs",
                    category=FindingCategory.TLS,
                    severity=Severity.LOW,
                    evidence="Certificate carries no embedded SCT extension",
                    impact="CT helps detect mis-issued certificates; absence weakens that signal. "
                           "Note: SCTs may still be delivered via OCSP stapling or a TLS extension, so this is not conclusive",
                    remediation="Use a CA that embeds SCTs, or confirm SCTs are delivered via stapling/TLS extension",
                ))

        # OCSP needs both the leaf and its issuer from the verified chain.
        if len(chain.chain_der) >= 2:
            ocsp = check_ocsp(chain.chain_der[0], chain.chain_der[1], self.config.timeout)
            if ocsp.status == "revoked":
                findings.append(Finding(
                    title="Certificate REVOKED (OCSP)",
                    category=FindingCategory.TLS,
                    severity=Severity.CRITICAL,
                    evidence=ocsp.detail,
                    impact="A revoked certificate must not be trusted; the endpoint may be compromised or misissued",
                    remediation="Replace the certificate immediately and investigate why it was revoked",
                ))
            elif ocsp.status == "good":
                findings.append(Finding(
                    title="OCSP: certificate not revoked",
                    category=FindingCategory.TLS,
                    severity=Severity.INFO,
                    evidence=ocsp.detail,
                ))
            elif ocsp.status == "no_responder":
                findings.append(Finding(
                    title="No OCSP responder advertised",
                    category=FindingCategory.TLS,
                    severity=Severity.LOW,
                    evidence=ocsp.detail,
                    impact="Clients cannot check revocation via OCSP; OCSP stapling cannot be relied upon",
                    remediation="Use a certificate whose AIA advertises an OCSP responder and enable OCSP stapling",
                ))

    def _enumerate_protocols(self, target: str, findings: list[Finding]) -> None:
        """Actively probe which TLS protocol versions the server accepts."""
        supported: list[str] = []
        for label, version in _PROBE_PROTOCOLS:
            self._rate_limit()
            if _supports_protocol(target, 443, version, self.config.timeout):
                supported.append(label)

        if not supported:
            return

        findings.append(Finding(
            title="TLS protocols supported",
            category=FindingCategory.TLS,
            severity=Severity.INFO,
            evidence=f"Server accepted handshakes for: {', '.join(supported)}",
        ))

        for label in supported:
            if label in _DEPRECATED_PROTOCOLS:
                findings.append(Finding(
                    title=f"Deprecated TLS protocol enabled: {label}",
                    category=FindingCategory.TLS,
                    severity=Severity.HIGH,
                    evidence=f"Server completed a {label} handshake",
                    impact="Legacy protocols are vulnerable to POODLE/BEAST and weaken the endpoint for every client",
                    remediation="Disable TLS 1.0 and 1.1; require TLS 1.2 or higher",
                ))

        if "TLSv1.2" not in supported:
            findings.append(Finding(
                title="TLS 1.2 not supported",
                category=FindingCategory.TLS,
                severity=Severity.MEDIUM,
                evidence="Server did not complete a TLS 1.2 handshake",
                impact="Clients unable to use TLS 1.3 may be pushed onto deprecated protocols or fail to connect",
                remediation="Enable TLS 1.2 (and ideally TLS 1.3)",
            ))

        if "TLSv1.3" not in supported:
            findings.append(Finding(
                title="TLS 1.3 not supported",
                category=FindingCategory.TLS,
                severity=Severity.LOW,
                evidence="Server did not complete a TLS 1.3 handshake",
                impact="Missing the fastest, most secure protocol (forward secrecy by default, fewer downgrade vectors)",
                remediation="Enable TLS 1.3 in the server or TLS-termination configuration",
            ))

    def _probe_weak_ciphers(self, target: str, findings: list[Finding]) -> None:
        """Actively probe whether the server accepts known-weak cipher families."""
        for label, cipher_str in _WEAK_CIPHER_PROBES:
            self._rate_limit()
            if _accepts_cipher(target, 443, cipher_str, self.config.timeout):
                findings.append(Finding(
                    title=f"Weak cipher family accepted: {label}",
                    category=FindingCategory.TLS,
                    severity=Severity.HIGH,
                    evidence=f"Server completed a handshake using a {label} cipher",
                    impact="Weak ciphers can be brute-forced or downgraded, exposing supposedly encrypted traffic",
                    remediation=f"Disable {label} cipher suites in the server TLS configuration",
                ))
