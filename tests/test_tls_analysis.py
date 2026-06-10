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


if __name__ == "__main__":
    unittest.main()
