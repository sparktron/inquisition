"""Tests for Prometheus/OpenMetrics export."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from metrics import render_prometheus
from models import Finding, FindingCategory, ScanReport, Severity


def _report(target: str, *findings: Finding, duration: float = 2.0) -> ScanReport:
    start = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    return ScanReport(
        target=target,
        started_at=start,
        finished_at=datetime.fromtimestamp(start.timestamp() + duration, tz=timezone.utc),
        findings=list(findings),
    )


def _f(sev: Severity, age: int = 0) -> Finding:
    return Finding(title="x", category=FindingCategory.TLS, severity=sev, evidence="e", age_scans=age)


class PrometheusTests(unittest.TestCase):
    def test_has_help_and_type_headers(self) -> None:
        out = render_prometheus([_report("example.com", _f(Severity.HIGH))])
        self.assertIn("# HELP inquisition_findings ", out)
        self.assertIn("# TYPE inquisition_findings gauge", out)
        self.assertTrue(out.endswith("\n"))

    def test_findings_by_severity_and_total(self) -> None:
        out = render_prometheus([_report("example.com", _f(Severity.HIGH), _f(Severity.LOW))])
        self.assertIn('inquisition_findings{target="example.com",severity="high"} 1', out)
        self.assertIn('inquisition_findings{target="example.com",severity="critical"} 0', out)
        self.assertIn('inquisition_findings_total{target="example.com"} 2', out)

    def test_max_age_and_duration(self) -> None:
        out = render_prometheus([_report("example.com", _f(Severity.HIGH, age=7), duration=1.5)])
        self.assertIn('inquisition_finding_max_age_scans{target="example.com"} 7', out)
        self.assertIn('inquisition_scan_duration_seconds{target="example.com"} 1.5', out)

    def test_multiple_targets_each_get_series(self) -> None:
        out = render_prometheus([_report("a.com", _f(Severity.LOW)), _report("b.com", _f(Severity.HIGH))])
        self.assertIn('inquisition_findings_total{target="a.com"} 1', out)
        self.assertIn('inquisition_findings_total{target="b.com"} 1', out)

    def test_label_value_is_escaped(self) -> None:
        out = render_prometheus([_report('ex"ample', _f(Severity.LOW))])
        self.assertIn('target="ex\\"ample"', out)


if __name__ == "__main__":
    unittest.main()
