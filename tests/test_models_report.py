from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from models import Finding, FindingCategory, ScanReport, Severity
from report import _risk_score, render_html, render_json, render_markdown, render_text


def _history(*totals: int) -> list[dict[str, object]]:
    return [
        {"taken_at": f"2026-06-{10 + i:02d}T00:00:00+00:00", "total": t,
         "counts": {"high": t, "info": 0}}
        for i, t in enumerate(totals)
    ]


class ModelsAndReportTests(unittest.TestCase):
    def test_summary_counts_includes_all_severities(self) -> None:
        report = ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 10, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="critical finding",
                    category=FindingCategory.TLS,
                    severity=Severity.CRITICAL,
                    evidence="expired cert",
                ),
                Finding(
                    title="medium finding",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.MEDIUM,
                    evidence="missing csp",
                ),
                Finding(
                    title="another medium finding",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.MEDIUM,
                    evidence="missing hsts",
                ),
            ],
        )

        self.assertEqual(
            report.summary_counts(),
            {"critical": 1, "high": 0, "medium": 2, "low": 0, "info": 0},
        )

    def test_risk_score_grade_thresholds_are_stable(self) -> None:
        self.assertEqual(_risk_score({"info": 5}), (0, "A+"))
        self.assertEqual(_risk_score({"low": 10}), (10, "B"))
        self.assertEqual(_risk_score({"high": 2, "medium": 4}), (50, "D"))
        self.assertEqual(_risk_score({"critical": 25}), (1000, "F"))

    def test_json_report_contains_machine_readable_finding_fields(self) -> None:
        report = ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 10, 12, tzinfo=timezone.utc),
            finished_at=datetime(2026, 6, 10, 12, 0, 1, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Detected: nginx 1.25",
                    category=FindingCategory.TECH_STACK,
                    severity=Severity.INFO,
                    evidence="Server: nginx/1.25",
                    cpe="cpe:2.3:a:f5:nginx:1.25:*:*:*:*:*:*:*",
                    references=["https://example.com/ref"],
                )
            ],
        )

        data = json.loads(render_json(report))

        self.assertEqual(data["target"], "example.com")
        self.assertEqual(data["summary"]["info"], 1)
        self.assertEqual(data["findings"][0]["cpe"], "cpe:2.3:a:f5:nginx:1.25:*:*:*:*:*:*:*")
        self.assertIn("tools", data["findings"][0])

    def test_brief_text_report_omits_deep_sections(self) -> None:
        report = ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 10, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Missing header: Content-Security-Policy",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.MEDIUM,
                    evidence="missing",
                    impact="impact text",
                    remediation="fix text",
                )
            ],
        )

        output = render_text(report, brief=True)

        self.assertIn("EXECUTIVE SUMMARY", output)
        self.assertIn("DETAILED FINDINGS", output)
        self.assertNotIn("DEEP ISSUE ANALYSIS", output)
        self.assertNotIn("REMEDIATION GUIDE", output)


class MarkdownReportTests(unittest.TestCase):
    def _report(self) -> ScanReport:
        return ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 23, 12, tzinfo=timezone.utc),
            finished_at=datetime(2026, 6, 23, 12, 0, 2, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Missing header: Content-Security-Policy",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.MEDIUM,
                    evidence="missing",
                    impact="impact text",
                    remediation="fix text",
                ),
            ],
        )

    def test_markdown_has_headings_and_summary_table(self) -> None:
        output = render_markdown(self._report())
        self.assertIn("# Inquisition — Security Reconnaissance Report", output)
        self.assertIn("## Executive Summary", output)
        self.assertIn("| Severity | Count |", output)
        self.assertIn("| --- | --- |", output)
        self.assertIn("#### Missing header: Content-Security-Policy", output)
        self.assertTrue(output.endswith("\n"))

    def test_markdown_escapes_pipes_in_table_cells(self) -> None:
        report = ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 23, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Weird | title",
                    category=FindingCategory.APPLICATION,
                    severity=Severity.HIGH,
                    evidence="e",
                ),
            ],
        )
        output = render_markdown(report)
        self.assertIn("Weird \\| title", output)

    def test_markdown_brief_omits_deep_sections(self) -> None:
        output = render_markdown(self._report(), brief=True)
        self.assertIn("## Detailed Findings", output)
        self.assertNotIn("## Deep Issue Analysis", output)
        self.assertNotIn("## Remediation Guide", output)


class AgeAndTrendRenderTests(unittest.TestCase):
    def _report(self) -> ScanReport:
        return ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 14, tzinfo=timezone.utc),
            finished_at=datetime(2026, 6, 14, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Old issue",
                    category=FindingCategory.TLS,
                    severity=Severity.HIGH,
                    evidence="e",
                    first_seen="2026-06-01T00:00:00+00:00",
                    age_scans=4,
                ),
            ],
            history=_history(5, 4, 3, 2),  # improving
        )

    def test_json_includes_age_history_and_trend(self) -> None:
        data = json.loads(render_json(self._report()))
        self.assertEqual(data["findings"][0]["age_scans"], 4)
        self.assertEqual(data["findings"][0]["first_seen"], "2026-06-01T00:00:00+00:00")
        self.assertEqual(len(data["history"]), 4)
        self.assertEqual(data["trend"]["direction"], "improving")
        self.assertEqual(data["trend"]["total_delta"], -3)

    def test_text_report_shows_finding_age(self) -> None:
        output = render_text(self._report())
        self.assertIn("open 4 scans (since 2026-06-01)", output)

    def test_html_report_has_sparkline_and_age(self) -> None:
        html = render_html(self._report())
        self.assertIn("<polyline", html)        # sparkline drawn
        self.assertIn("improving", html)        # trend label
        self.assertIn("open 4 scans", html)     # age row

    def test_html_no_sparkline_without_history(self) -> None:
        report = self._report()
        report.history = []
        self.assertNotIn("<polyline", render_html(report))

    def test_new_finding_reads_as_new(self) -> None:
        report = self._report()
        report.findings[0].age_scans = 1
        self.assertIn("new this scan", render_text(report))


if __name__ == "__main__":
    unittest.main()
