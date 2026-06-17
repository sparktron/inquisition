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
from report import (
    render,
    render_combined,
    render_fleet_dashboard,
    render_json_combined,
    render_sarif,
    render_sarif_combined,
)


def _report(findings: list[Finding], target: str = "example.com") -> ScanReport:
    return ScanReport(
        target=target,
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


class CombinedReportTests(unittest.TestCase):
    def _fleet(self) -> list[ScanReport]:
        a = _report(
            [Finding(title="A", category=FindingCategory.TLS, severity=Severity.HIGH, evidence="e")],
            target="a.com",
        )
        b = _report(
            [
                Finding(title="B", category=FindingCategory.DNS, severity=Severity.LOW, evidence="e"),
                Finding(title="C", category=FindingCategory.DNS, severity=Severity.MEDIUM, evidence="e"),
            ],
            target="b.com",
        )
        return [a, b]

    def test_sarif_combined_has_one_run_per_target(self) -> None:
        doc = json.loads(render_sarif_combined(self._fleet()))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"]), 2)
        uris = [
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for run in doc["runs"]
        ]
        self.assertEqual(uris, ["a.com", "b.com"])

    def test_json_combined_aggregates_summary(self) -> None:
        doc = json.loads(render_json_combined(self._fleet()))
        self.assertEqual(doc["report_type"], "fleet")
        self.assertEqual(doc["fleet_summary"]["target_count"], 2)
        self.assertEqual(doc["fleet_summary"]["targets"], ["a.com", "b.com"])
        self.assertEqual(doc["fleet_summary"]["total_findings"], 3)
        self.assertEqual(doc["fleet_summary"]["counts"]["high"], 1)
        self.assertEqual(doc["fleet_summary"]["counts"]["medium"], 1)
        self.assertEqual(len(doc["reports"]), 2)

    def test_render_combined_dispatches_by_format(self) -> None:
        fleet = self._fleet()
        self.assertEqual(
            json.loads(render_combined(fleet, ReportFormat.SARIF))["version"], "2.1.0"
        )
        text = render_combined(fleet, ReportFormat.TEXT)
        self.assertIn("a.com", text)
        self.assertIn("b.com", text)
        self.assertIn("FLEET REPORT 1/2", text)

    def test_html_combined_is_fleet_dashboard(self) -> None:
        html = render_combined(self._fleet(), ReportFormat.HTML)
        self.assertIn("Inquisition Fleet Dashboard", html)
        self.assertIn("a.com", html)
        self.assertIn("b.com", html)
        # one dashboard document, not concatenated per-target reports
        self.assertEqual(html.count("<!DOCTYPE html>"), 1)

    def test_dashboard_sorts_riskiest_first(self) -> None:
        # b.com (a MEDIUM) outranks a.com here only if scored; build a clear case
        high = _report([Finding(title="X", category=FindingCategory.TLS,
                                severity=Severity.CRITICAL, evidence="e")], target="risky.com")
        low = _report([Finding(title="Y", category=FindingCategory.DNS,
                               severity=Severity.LOW, evidence="e")], target="calm.com")
        html = render_fleet_dashboard([low, high])
        self.assertLess(html.index("risky.com"), html.index("calm.com"))


if __name__ == "__main__":
    unittest.main()
