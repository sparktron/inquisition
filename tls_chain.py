"""TLS chain validation, OCSP revocation, and Certificate Transparency checks.

These are the cryptography-backed depth checks that complement the stdlib
handshake analysis in ``modules/tls_analysis.py``. Network entry points are
module-level so tests can patch them; certificate parsing is pure and can be
exercised with fixture certificates.
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
import _ssl
from dataclasses import dataclass, field
from typing import Any, Callable, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID


@dataclass(frozen=True)
class ChainResult:
    """Outcome of a trust-store-verified handshake."""

    verified: bool
    chain_length: int = 0
    error: str = ""
    untested: bool = False
    chain_der: tuple[bytes, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SctResult:
    """Embedded Certificate Transparency SCT inspection."""

    present: bool
    count: int = 0
    error: str = ""


@dataclass(frozen=True)
class OcspResult:
    """OCSP revocation lookup result."""

    status: str  # good | revoked | unknown | no_responder | error
    detail: str = ""


@dataclass(frozen=True)
class DhResult:
    """Ephemeral key-exchange group inspection for a forced TLS 1.2 DHE handshake."""

    tested: bool          # False when the probe could not run (no openssl, etc.)
    kex_type: str = ""    # "DH" (finite-field), "ECDH", "X25519", … or "" if none
    bits: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------


def fetch_verified_chain(host: str, port: int, timeout: float) -> ChainResult:
    """Perform a trust-store-verified handshake and capture the certificate chain.

    ``verified`` is True only when the chain validates against the system trust
    store (complete chain, trusted root, in-date, hostname match). When the
    handshake itself cannot be attempted (port closed, network error) the result
    is marked ``untested`` so callers can stay quiet instead of reporting a
    spurious trust failure.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                chain = _extract_chain_der(tls)
                return ChainResult(
                    verified=True,
                    chain_length=len(chain),
                    chain_der=tuple(chain),
                )
    except ssl.SSLCertVerificationError as exc:
        return ChainResult(verified=False, error=_short(str(exc)))
    except (ssl.SSLError, OSError) as exc:
        return ChainResult(verified=False, error=_short(str(exc)), untested=True)


def _extract_chain_der(tls: ssl.SSLSocket) -> list[bytes]:
    """Return DER bytes for each cert in the verified chain (leaf first).

    Prefers the verified chain exposed by the underlying ``_ssl`` object (so the
    issuer is available for OCSP); falls back to the single peer certificate on
    interpreters that do not expose it.
    """
    sslobj = getattr(tls, "_sslobj", None)
    getter = getattr(sslobj, "get_verified_chain", None)
    if getter is not None:
        try:
            return [cert.public_bytes(_ssl.ENCODING_DER) for cert in getter()]
        except (ValueError, OSError, AttributeError):
            pass
    der = tls.getpeercert(binary_form=True)
    return [der] if der else []


# ---------------------------------------------------------------------------
# Certificate Transparency (embedded SCTs)
# ---------------------------------------------------------------------------


def analyze_scts(leaf_der: bytes) -> SctResult:
    """Inspect a leaf certificate for embedded Certificate Transparency SCTs."""
    try:
        cert = x509.load_der_x509_certificate(leaf_der)
    except ValueError as exc:
        return SctResult(present=False, error=_short(str(exc)))
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        )
    except x509.ExtensionNotFound:
        return SctResult(present=False)
    try:
        count = len(list(cast(Any, ext.value)))
    except TypeError:
        count = 0
    return SctResult(present=True, count=count)


# ---------------------------------------------------------------------------
# OCSP revocation
# ---------------------------------------------------------------------------


def check_ocsp(leaf_der: bytes, issuer_der: bytes, timeout: float) -> OcspResult:
    """Query the certificate's OCSP responder for its revocation status."""
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
        issuer = x509.load_der_x509_certificate(issuer_der)
    except ValueError as exc:
        return OcspResult("error", _short(str(exc)))

    url = _ocsp_url(leaf)
    if not url:
        return OcspResult("no_responder", "Certificate has no OCSP responder URL in its AIA extension")

    try:
        builder = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1())
        request_der = builder.build().public_bytes(serialization.Encoding.DER)
    except Exception as exc:  # cryptography may reject unusual cert pairs
        return OcspResult("error", f"Could not build OCSP request: {_short(str(exc))}")

    try:
        raw = _post_ocsp(url, request_der, timeout)
    except (urllib.error.URLError, OSError) as exc:
        return OcspResult("error", f"OCSP request failed: {_short(str(exc))}")

    try:
        response = ocsp.load_der_ocsp_response(raw)
    except ValueError as exc:
        return OcspResult("error", f"Malformed OCSP response: {_short(str(exc))}")

    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return OcspResult("unknown", f"OCSP responder returned {response.response_status.name}")

    status = response.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return OcspResult("good", "OCSP responder reports the certificate is valid (not revoked)")
    if status == ocsp.OCSPCertStatus.REVOKED:
        when = getattr(response, "revocation_time_utc", None) or getattr(response, "revocation_time", "")
        return OcspResult("revoked", f"OCSP responder reports the certificate was REVOKED ({when})")
    return OcspResult("unknown", "OCSP responder reports an unknown certificate status")


def _ocsp_url(cert: x509.Certificate) -> str:
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return ""
    for desc in cast(Any, aia):
        if desc.access_method == AuthorityInformationAccessOID.OCSP:
            return str(getattr(desc.access_location, "value", ""))
    return ""


def _post_ocsp(url: str, request_der: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(
        url,
        data=request_der,
        headers={
            "Content-Type": "application/ocsp-request",
            "Accept": "application/ocsp-response",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 (scheme is from cert AIA)
        return cast(bytes, resp.read())


# ---------------------------------------------------------------------------
# Diffie-Hellman key-exchange parameter strength
# ---------------------------------------------------------------------------

# Python's ssl module does not expose the size of the negotiated ephemeral DH
# group, so we force a finite-field DHE handshake with ``openssl s_client`` and
# read its "Server Temp Key" line. Restricting to TLS 1.2 (where the weak
# Logjam-class groups live) means a TLS 1.3-only server simply fails to
# negotiate and reports nothing — which is the correct, non-noisy outcome.
_SERVER_TEMP_KEY_RE = re.compile(
    r"Server Temp Key:\s*([A-Za-z0-9]+)[^\n]*?(\d+)\s*bits",
    re.IGNORECASE,
)


def is_openssl_available() -> bool:
    """Return True if the openssl binary is on PATH."""
    return shutil.which("openssl") is not None


def parse_server_temp_key(output: str) -> tuple[str, int] | None:
    """Extract (kex_type, bits) from ``openssl s_client`` output, if present."""
    match = _SERVER_TEMP_KEY_RE.search(output)
    if not match:
        return None
    try:
        return match.group(1), int(match.group(2))
    except ValueError:
        return None


def probe_dh_parameters(
    host: str,
    port: int,
    timeout: float,
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> DhResult:
    """Force a TLS 1.2 finite-field DHE handshake and report the DH group size.

    Returns ``tested=False`` when the probe cannot run (openssl missing, or the
    process failed) so callers can stay silent rather than guess. A server that
    only offers ECDHE or TLS 1.3 produces no "Server Temp Key: DH" line and is
    reported with an empty ``kex_type`` — no weakness.
    """
    if not is_openssl_available():
        return DhResult(tested=False, error="openssl not found on PATH")

    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-cipher", "DHE",
        "-tls1_2",
    ]
    try:
        proc = runner(
            cmd,
            input="Q\n",
            capture_output=True,
            text=True,
            timeout=max(10.0, timeout * 2),
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return DhResult(tested=False, error=f"openssl probe failed: {_short(str(exc))}")

    combined = (getattr(proc, "stdout", "") or "") + "\n" + (getattr(proc, "stderr", "") or "")
    parsed = parse_server_temp_key(combined)
    if parsed is None:
        # No DHE handshake completed (ECDHE-only / TLS 1.3-only server, or no
        # shared cipher). Nothing to flag.
        return DhResult(tested=True, kex_type="", bits=0)
    kex_type, bits = parsed
    return DhResult(tested=True, kex_type=kex_type, bits=bits)


def _short(message: str, limit: int = 200) -> str:
    message = " ".join(message.split())
    return message if len(message) <= limit else message[: limit - 1] + "…"
