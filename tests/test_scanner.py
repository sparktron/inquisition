from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone

from models import Finding, FindingCategory, ReportFormat, ScanReport, Severity
from scanner import _deduplicate, _default_report_path


class ScannerTests(unittest.TestCase):
    def test_default_report_path_uses_report_format_extension(self) -> None:
        report = ScanReport(
            target="www.example.com",
            started_at=datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc),
        )

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                self.assertEqual(
                    str(_default_report_path(report, ReportFormat.JSON)),
                    "reports/20260610_120000_www_example_com.json",
                )
                self.assertEqual(
                    str(_default_report_path(report, ReportFormat.HTML)),
                    "reports/20260610_120000_www_example_com.html",
                )
                self.assertEqual(
                    str(_default_report_path(report, ReportFormat.TEXT)),
                    "reports/20260610_120000_www_example_com.txt",
                )
            finally:
                os.chdir(old_cwd)

    def test_deduplicate_preserves_http_and_https_findings(self) -> None:
        findings = [
            Finding(
                title="Missing header: Content-Security-Policy",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence="https://example.com/ does not return Content-Security-Policy",
            ),
            Finding(
                title="Missing header: Content-Security-Policy",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence="http://example.com/ does not return Content-Security-Policy",
            ),
            Finding(
                title="Missing header: Content-Security-Policy",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence="https://example.com/ does not return Content-Security-Policy",
            ),
        ]

        deduped = _deduplicate(findings)

        self.assertEqual(len(deduped), 2)
        self.assertIn("https://", deduped[0].evidence)
        self.assertIn("http://", deduped[1].evidence)


if __name__ == "__main__":
    unittest.main()
