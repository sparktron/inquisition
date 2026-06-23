from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from models import Finding, FindingCategory, ReportFormat, ScanReport, Severity
from scanner import _deduplicate, _default_report_path, _extract_discovered_urls


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
                # Each website gets its own folder under reports/.
                self.assertEqual(
                    str(_default_report_path(report, ReportFormat.JSON)),
                    "reports/www_example_com/20260610_120000.json",
                )
                self.assertEqual(
                    str(_default_report_path(report, ReportFormat.HTML)),
                    "reports/www_example_com/20260610_120000.html",
                )
                self.assertEqual(
                    str(_default_report_path(report, ReportFormat.TEXT)),
                    "reports/www_example_com/20260610_120000.txt",
                )
                self.assertEqual(
                    str(_default_report_path(report, ReportFormat.MARKDOWN)),
                    "reports/www_example_com/20260610_120000.md",
                )
                # The per-target folder is created on first use.
                self.assertTrue((Path(tmp) / "reports" / "www_example_com").is_dir())
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

    def test_extract_discovered_urls_uses_crawler_metadata(self) -> None:
        urls = _extract_discovered_urls([
            Finding(
                title="Site URL surface discovered",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence="sample",
                metadata={"discovered_urls": ["https://example.com/b", "https://example.com/a", 123]},
            )
        ])

        self.assertEqual(urls, ("https://example.com/a", "https://example.com/b"))


if __name__ == "__main__":
    unittest.main()
