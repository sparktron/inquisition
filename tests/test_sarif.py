from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from models import (
    Finding,
    FindingCategory,
    ReportFormat,
    ScanReport,
    Severity,
    severity_at_least,
)
from report import render, render_sarif


def _report(findings: list[Finding]) -> ScanReport:
    return ScanReport(
        target="example.com",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings=findings,
    )


class SarifReportTests(unittest.TestCase):
    def test_sarif_envelope_is_valid(self) -> None:
        report = _report([
            Finding(
                title="Missing header: Content-Security-Policy",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence="https://example.com/ does not return CSP",
                impact="XSS harder to mitigate",
                remediation="Add a CSP header",
            ),
        ])
        doc = json.loads(render_sarif(report))

        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Inquisition")
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["level"], "warning")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)

    def test_severity_maps_to_sarif_level(self) -> None:
        report = _report([
            Finding(title="A", category=FindingCategory.TLS, severity=Severity.CRITICAL, evidence="e"),
            Finding(title="B", category=FindingCategory.TLS, severity=Severity.LOW, evidence="e"),
        ])
        results = json.loads(render_sarif(report))["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in results}
        self.assertEqual(levels["tls/a"], "error")
        self.assertEqual(levels["tls/b"], "note")

    def test_render_dispatch_selects_sarif(self) -> None:
        report = _report([
            Finding(title="X", category=FindingCategory.DNS, severity=Severity.INFO, evidence="e"),
        ])
        out = render(report, ReportFormat.SARIF)
        self.assertEqual(json.loads(out)["version"], "2.1.0")

    def test_duplicate_titles_share_one_rule(self) -> None:
        report = _report([
            Finding(title="Same", category=FindingCategory.DNS, severity=Severity.LOW, evidence="e1"),
            Finding(title="Same", category=FindingCategory.DNS, severity=Severity.LOW, evidence="e2"),
        ])
        run = json.loads(render_sarif(report))["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(run["results"]), 2)


class FailOnSeverityTests(unittest.TestCase):
    def test_highest_severity(self) -> None:
        report = _report([
            Finding(title="a", category=FindingCategory.DNS, severity=Severity.LOW, evidence="e"),
            Finding(title="b", category=FindingCategory.DNS, severity=Severity.HIGH, evidence="e"),
            Finding(title="c", category=FindingCategory.DNS, severity=Severity.INFO, evidence="e"),
        ])
        self.assertEqual(report.highest_severity(), Severity.HIGH)

    def test_highest_severity_none_when_empty(self) -> None:
        self.assertIsNone(_report([]).highest_severity())

    def test_severity_at_least(self) -> None:
        self.assertTrue(severity_at_least(Severity.CRITICAL, Severity.HIGH))
        self.assertTrue(severity_at_least(Severity.HIGH, Severity.HIGH))
        self.assertFalse(severity_at_least(Severity.MEDIUM, Severity.HIGH))


if __name__ == "__main__":
    unittest.main()
