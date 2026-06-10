from __future__ import annotations

import unittest
from unittest.mock import patch

from models import ScanConfig
from modules.tls_analysis import TlsAnalysisModule


class TlsAnalysisTests(unittest.TestCase):
    def test_certificate_fields_are_reported_from_parsed_cert(self) -> None:
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        info = {
            "peer_cert": cert,
            "peer_cert_der": b"certificate-bytes",
            "version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

        with patch("modules.tls_analysis._get_cert_info", return_value=info):
            findings = TlsAnalysisModule(ScanConfig(target="example.com")).run()

        titles = {finding.title for finding in findings}
        self.assertIn("Certificate CN: example.com", titles)
        self.assertIn("Certificate validity", titles)
        self.assertIn("Subject Alternative Names", titles)
        self.assertNotIn("Hostname not in certificate SAN", titles)

    def test_hostname_mismatch_is_reported(self) -> None:
        cert = {
            "subject": ((("commonName", "other.example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "subjectAltName": (("DNS", "other.example.com"),),
        }
        info = {
            "peer_cert": cert,
            "peer_cert_der": b"certificate-bytes",
            "version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

        with patch("modules.tls_analysis._get_cert_info", return_value=info):
            findings = TlsAnalysisModule(ScanConfig(target="example.com")).run()

        self.assertIn("Hostname not in certificate SAN", {finding.title for finding in findings})

    def test_deprecated_protocols_flagged_and_tls13_gap_reported(self) -> None:
        # Server speaks legacy TLS 1.0/1.1/1.2 but not 1.3.
        supported = {"TLSv1", "TLSv1.1", "TLSv1.2"}

        def fake_supports(host: str, port: int, version: object, timeout: float) -> bool:
            import ssl
            label = {
                ssl.TLSVersion.TLSv1: "TLSv1",
                ssl.TLSVersion.TLSv1_1: "TLSv1.1",
                ssl.TLSVersion.TLSv1_2: "TLSv1.2",
                ssl.TLSVersion.TLSv1_3: "TLSv1.3",
            }[version]
            return label in supported

        module = TlsAnalysisModule(ScanConfig(target="example.com", rate_limit=0))
        findings: list = []
        with patch("modules.tls_analysis._supports_protocol", side_effect=fake_supports):
            module._enumerate_protocols("example.com", findings)

        titles = {f.title for f in findings}
        self.assertIn("Deprecated TLS protocol enabled: TLSv1", titles)
        self.assertIn("Deprecated TLS protocol enabled: TLSv1.1", titles)
        self.assertIn("TLS 1.3 not supported", titles)
        self.assertNotIn("TLS 1.2 not supported", titles)

    def test_modern_only_server_has_no_deprecated_findings(self) -> None:
        def fake_supports(host: str, port: int, version: object, timeout: float) -> bool:
            import ssl
            return version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)

        module = TlsAnalysisModule(ScanConfig(target="example.com", rate_limit=0))
        findings: list = []
        with patch("modules.tls_analysis._supports_protocol", side_effect=fake_supports):
            module._enumerate_protocols("example.com", findings)

        titles = {f.title for f in findings}
        self.assertIn("TLS protocols supported", titles)
        self.assertFalse(any(t.startswith("Deprecated TLS protocol") for t in titles))
        self.assertNotIn("TLS 1.3 not supported", titles)
        self.assertNotIn("TLS 1.2 not supported", titles)

    def test_weak_cipher_acceptance_is_high_severity(self) -> None:
        def fake_accepts(host: str, port: int, cipher: str, timeout: float) -> bool:
            return cipher == "3DES:DES"

        module = TlsAnalysisModule(ScanConfig(target="example.com", rate_limit=0))
        findings: list = []
        with patch("modules.tls_analysis._accepts_cipher", side_effect=fake_accepts):
            module._probe_weak_ciphers("example.com", findings)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Weak cipher family accepted: 3DES/DES")
        self.assertEqual(findings[0].severity.value, "high")


if __name__ == "__main__":
    unittest.main()
