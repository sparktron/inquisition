"""Tests for tls_chain (chain validation, CT/SCT, and OCSP)."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

import tls_chain
from models import Finding, ScanConfig
from modules import tls_analysis
from modules.tls_analysis import TlsAnalysisModule
from tls_chain import ChainResult, DhResult, OcspResult, SctResult


class _FakeProc:
    def __init__(self, stdout: str = "", stderr: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_cert(
    cn: str,
    key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    *,
    ocsp_url: str | None = None,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
    )
    if ocsp_url is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _ocsp_response_der(
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    status: ocsp.OCSPCertStatus,
) -> bytes:
    now = datetime.now(timezone.utc)
    revocation_time = now - timedelta(days=1) if status == ocsp.OCSPCertStatus.REVOKED else None
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf,
            issuer=issuer,
            algorithm=hashes.SHA1(),
            cert_status=status,
            this_update=now,
            next_update=now + timedelta(days=1),
            revocation_time=revocation_time,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, issuer)
        .sign(issuer_key, hashes.SHA256())
    )
    return response.public_bytes(serialization.Encoding.DER)


class SctTests(unittest.TestCase):
    def test_self_signed_cert_has_no_embedded_scts(self) -> None:
        key = _key()
        cert = _make_cert("example.test", key, _name("example.test"), key)
        result = tls_chain.analyze_scts(_der(cert))
        self.assertFalse(result.present)
        self.assertEqual(result.count, 0)
        self.assertEqual(result.error, "")

    def test_garbage_der_reports_error(self) -> None:
        result = tls_chain.analyze_scts(b"not-a-certificate")
        self.assertFalse(result.present)
        self.assertNotEqual(result.error, "")


class OcspTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer_key = _key()
        self.issuer = _make_cert("Test CA", self.issuer_key, _name("Test CA"), self.issuer_key)
        self.leaf_key = _key()
        self.leaf = _make_cert(
            "example.test", self.leaf_key, self.issuer.subject, self.issuer_key,
            ocsp_url="http://ocsp.test",
        )

    def test_no_aia_means_no_responder(self) -> None:
        leaf_no_aia = _make_cert("example.test", self.leaf_key, self.issuer.subject, self.issuer_key)
        result = tls_chain.check_ocsp(_der(leaf_no_aia), _der(self.issuer), 5.0)
        self.assertEqual(result.status, "no_responder")

    def test_good_status(self) -> None:
        der = _ocsp_response_der(self.leaf, self.issuer, self.issuer_key, ocsp.OCSPCertStatus.GOOD)
        with patch.object(tls_chain, "_post_ocsp", return_value=der):
            result = tls_chain.check_ocsp(_der(self.leaf), _der(self.issuer), 5.0)
        self.assertEqual(result.status, "good")

    def test_revoked_status(self) -> None:
        der = _ocsp_response_der(self.leaf, self.issuer, self.issuer_key, ocsp.OCSPCertStatus.REVOKED)
        with patch.object(tls_chain, "_post_ocsp", return_value=der):
            result = tls_chain.check_ocsp(_der(self.leaf), _der(self.issuer), 5.0)
        self.assertEqual(result.status, "revoked")

    def test_network_failure_is_error(self) -> None:
        with patch.object(tls_chain, "_post_ocsp", side_effect=OSError("boom")):
            result = tls_chain.check_ocsp(_der(self.leaf), _der(self.issuer), 5.0)
        self.assertEqual(result.status, "error")


class DhParseTests(unittest.TestCase):
    def test_parses_finite_field_dh(self) -> None:
        self.assertEqual(
            tls_chain.parse_server_temp_key("Server Temp Key: DH, 1024 bits\n"),
            ("DH", 1024),
        )

    def test_parses_ecdh(self) -> None:
        self.assertEqual(
            tls_chain.parse_server_temp_key("Server Temp Key: ECDH, P-256, 256 bits"),
            ("ECDH", 256),
        )

    def test_parses_x25519(self) -> None:
        self.assertEqual(
            tls_chain.parse_server_temp_key("    Server Temp Key: X25519, 253 bits"),
            ("X25519", 253),
        )

    def test_no_match_returns_none(self) -> None:
        self.assertIsNone(tls_chain.parse_server_temp_key("handshake failure"))

    def test_probe_reports_dh_bits_via_runner(self) -> None:
        def fake_runner(cmd: list[str], **_: object) -> _FakeProc:
            return _FakeProc(stdout="...\nServer Temp Key: DH, 1024 bits\n...")

        result = tls_chain.probe_dh_parameters("example.test", 443, 5.0, runner=fake_runner)
        self.assertTrue(result.tested)
        self.assertEqual(result.kex_type, "DH")
        self.assertEqual(result.bits, 1024)

    def test_probe_with_no_dhe_handshake_is_clean(self) -> None:
        def fake_runner(cmd: list[str], **_: object) -> _FakeProc:
            return _FakeProc(stderr="no peer certificate available")

        result = tls_chain.probe_dh_parameters("example.test", 443, 5.0, runner=fake_runner)
        self.assertTrue(result.tested)
        self.assertEqual(result.kex_type, "")
        self.assertEqual(result.bits, 0)

    def test_probe_untestable_when_openssl_missing(self) -> None:
        with patch("tls_chain.shutil.which", return_value=None):
            result = tls_chain.probe_dh_parameters("example.test", 443, 5.0)
        self.assertFalse(result.tested)


class ModuleFindingTests(unittest.TestCase):
    def _module(self) -> TlsAnalysisModule:
        return TlsAnalysisModule(ScanConfig(target="example.test", rate_limit=0))

    def test_trusted_chain_ct_and_good_ocsp(self) -> None:
        findings: list[Finding] = []
        chain = ChainResult(verified=True, chain_length=3, chain_der=(b"leaf", b"issuer", b"root"))
        with patch.object(tls_analysis, "fetch_verified_chain", return_value=chain), \
             patch.object(tls_analysis, "analyze_scts", return_value=SctResult(present=True, count=2)), \
             patch.object(tls_analysis, "check_ocsp", return_value=OcspResult("good", "ok")):
            self._module()._check_chain_ct_ocsp("example.test", b"leaf", findings)
        titles = {f.title for f in findings}
        self.assertIn("Certificate chain trusted", titles)
        self.assertIn("Certificate Transparency SCTs present", titles)
        self.assertIn("OCSP: certificate not revoked", titles)

    def test_untrusted_chain_no_scts_and_revoked(self) -> None:
        findings: list[Finding] = []
        chain = ChainResult(verified=False, error="unable to get local issuer certificate",
                            chain_der=(b"leaf", b"issuer"))
        with patch.object(tls_analysis, "fetch_verified_chain", return_value=chain), \
             patch.object(tls_analysis, "analyze_scts", return_value=SctResult(present=False)), \
             patch.object(tls_analysis, "check_ocsp", return_value=OcspResult("revoked", "revoked at X")):
            self._module()._check_chain_ct_ocsp("example.test", b"leaf", findings)
        by_title = {f.title: f for f in findings}
        self.assertIn("Certificate chain not trusted", by_title)
        self.assertIn("No embedded Certificate Transparency SCTs", by_title)
        self.assertIn("Certificate REVOKED (OCSP)", by_title)
        self.assertEqual(by_title["Certificate REVOKED (OCSP)"].severity.name, "CRITICAL")

    def test_untested_chain_emits_nothing(self) -> None:
        findings: list[Finding] = []
        chain = ChainResult(verified=False, error="timed out", untested=True)
        with patch.object(tls_analysis, "fetch_verified_chain", return_value=chain):
            self._module()._check_chain_ct_ocsp("example.test", b"leaf", findings)
        self.assertEqual(findings, [])

    def _dh_finding(self, dh: DhResult) -> list[Finding]:
        findings: list[Finding] = []
        with patch.object(tls_analysis, "probe_dh_parameters", return_value=dh), \
             patch.object(tls_analysis, "probe_tls13_group", return_value=DhResult(tested=True)):
            self._module()._check_dh_parameters("example.test", findings)
        return findings

    def _tls13_finding(self, group: DhResult) -> list[Finding]:
        findings: list[Finding] = []
        with patch.object(tls_analysis, "probe_tls13_group", return_value=group):
            self._module()._check_tls13_group("example.test", findings)
        return findings

    def test_dh_512_bit_is_high(self) -> None:
        findings = self._dh_finding(DhResult(tested=True, kex_type="DH", bits=512))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.name, "HIGH")
        self.assertIn("Export-grade", findings[0].title)

    def test_dh_1024_bit_is_medium(self) -> None:
        findings = self._dh_finding(DhResult(tested=True, kex_type="DH", bits=1024))
        self.assertEqual(findings[0].severity.name, "MEDIUM")

    def test_dh_1536_bit_is_low(self) -> None:
        findings = self._dh_finding(DhResult(tested=True, kex_type="DH", bits=1536))
        self.assertEqual(findings[0].severity.name, "LOW")

    def test_dh_2048_bit_is_info(self) -> None:
        findings = self._dh_finding(DhResult(tested=True, kex_type="DH", bits=2048))
        self.assertEqual(findings[0].severity.name, "INFO")

    def test_ecdh_emits_nothing(self) -> None:
        self.assertEqual(self._dh_finding(DhResult(tested=True, kex_type="ECDH", bits=256)), [])

    def test_untested_dh_emits_nothing(self) -> None:
        self.assertEqual(self._dh_finding(DhResult(tested=False)), [])

    def test_tls13_ffdhe_is_low(self) -> None:
        findings = self._tls13_finding(DhResult(tested=True, kex_type="DH", bits=2048))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.name, "LOW")
        self.assertIn("finite-field", findings[0].title)

    def test_tls13_undersized_ffdhe_is_medium(self) -> None:
        findings = self._tls13_finding(DhResult(tested=True, kex_type="DH", bits=1024))
        self.assertEqual(findings[0].severity.name, "MEDIUM")

    def test_tls13_ecdhe_emits_nothing(self) -> None:
        self.assertEqual(self._tls13_finding(DhResult(tested=True, kex_type="X25519", bits=253)), [])

    def test_tls13_untested_emits_nothing(self) -> None:
        self.assertEqual(self._tls13_finding(DhResult(tested=False)), [])


if __name__ == "__main__":
    unittest.main()
