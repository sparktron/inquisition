"""Tests for authorization and active-scan safety prompts."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from models import ScanConfig
from safety import confirm_active_scan


class ActiveScanAuthorizationTests(unittest.TestCase):
    def test_banner_names_nuclei_engine(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            confirmed = confirm_active_scan(
                ScanConfig(target="example.com", active_engine="nuclei"),
                assume_yes=True,
            )
        self.assertTrue(confirmed)
        self.assertIn("engine (Nuclei)", output.getvalue())

    def test_banner_names_zap_engine(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            confirmed = confirm_active_scan(
                ScanConfig(target="example.com", active_engine="zap"),
                assume_yes=True,
            )
        self.assertTrue(confirmed)
        self.assertIn("engine (OWASP ZAP)", output.getvalue())


if __name__ == "__main__":
    unittest.main()
