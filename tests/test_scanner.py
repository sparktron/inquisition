from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from models import (
    Finding,
    FindingCategory,
    ReportFormat,
    ScanConfig,
    ScanReport,
    Severity,
)
from scanner import _deduplicate, _default_report_path, _extract_discovered_urls, run_scan


class DiscoveryModeScanTests(unittest.TestCase):
    """Discovery mode runs only the liveness/role modules (port + DNS)."""

    def _run_dry(self, *, discovery: bool) -> ScanReport:
        cfg = ScanConfig(target="192.168.1.5", dry_run=True, discovery=discovery)
        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd()
            os.chdir(tmp)
            try:
                return run_scan(cfg, quiet=True, write_report=False)
            finally:
                os.chdir(old)

    def test_discovery_only_runs_port_and_dns(self) -> None:
        report = self._run_dry(discovery=True)
        categories = {f.category for f in report.findings}
        self.assertTrue(report.findings)  # something ran
        self.assertTrue(categories <= {FindingCategory.PORT, FindingCategory.DNS})

    def test_full_scan_runs_more_than_port_and_dns(self) -> None:
        report = self._run_dry(discovery=False)
        categories = {f.category for f in report.findings}
        # A full (dry-run) scan reaches TLS/HTTP/app modules too.
        self.assertTrue(categories - {FindingCategory.PORT, FindingCategory.DNS})


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

    def test_deduplicate_preserves_distinct_active_template_endpoint_matches(self) -> None:
        findings = [
            Finding(
                title="[active] Shared title",
                category=FindingCategory.VULNERABILITY,
                severity=Severity.HIGH,
                evidence=f"Nuclei template 't{index}' matched at https://example.com/{index}",
                metadata={
                    "active_scan": True,
                    "template_id": f"t{index}",
                    "matched_at": f"https://example.com/{index}",
                },
            )
            for index in range(2)
        ]

        self.assertEqual(len(_deduplicate(findings)), 2)

    def test_deduplicate_preserves_distinct_zap_endpoint_matches(self) -> None:
        findings = [
            Finding(
                title="[active] Shared ZAP alert",
                category=FindingCategory.VULNERABILITY,
                severity=Severity.HIGH,
                evidence=f"ZAP alert '10020' at https://example.com/{index}",
                metadata={
                    "active_scan": True,
                    "scanner": "zap",
                    "plugin_id": "10020",
                    "matched_at": f"https://example.com/{index}",
                    "matched_endpoints": [f"https://example.com/{index}"],
                },
            )
            for index in range(2)
        ]

        self.assertEqual(len(_deduplicate(findings)), 2)
        self.assertEqual(len(_deduplicate(findings + [findings[0]])), 2)

    def test_deduplicate_legacy_active_findings_uses_full_evidence(self) -> None:
        findings = [
            Finding(
                title="[active] Legacy alert",
                category=FindingCategory.VULNERABILITY,
                severity=Severity.HIGH,
                evidence=f"Legacy scanner match at https://example.com/{index}",
            )
            for index in range(2)
        ]

        self.assertEqual(len(_deduplicate(findings)), 2)

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
