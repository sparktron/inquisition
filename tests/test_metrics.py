"""Tests for Prometheus/OpenMetrics export."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from typing import Any

from metrics import push_metrics, render_prometheus
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

    def test_exposure_index_metric(self) -> None:
        svc = Finding(title="Redis exposed to internet", category=FindingCategory.PORT,
                      severity=Severity.HIGH, evidence="e")
        out = render_prometheus([_report("example.com", svc)])
        self.assertIn("# TYPE inquisition_exposure_index gauge", out)
        self.assertRegex(out, r'inquisition_exposure_index\{target="example.com"\} \d+')

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


class HistoryMetricsTests(unittest.TestCase):
    def _report_with_history(self) -> ScanReport:
        r = _report("example.com", _f(Severity.HIGH))
        r.history = [
            {"taken_at": "2026-06-01T00:00:00+00:00", "total": 3, "counts": {"high": 3}},
            {"taken_at": "2026-06-02T00:00:00+00:00", "total": 1, "counts": {"high": 1}},
        ]
        return r

    def test_history_emits_timestamped_samples(self) -> None:
        out = render_prometheus([self._report_with_history()], include_history=True)
        ms1 = int(datetime.fromisoformat("2026-06-01T00:00:00+00:00").timestamp() * 1000)
        ms2 = int(datetime.fromisoformat("2026-06-02T00:00:00+00:00").timestamp() * 1000)
        self.assertIn(f'inquisition_findings_total{{target="example.com"}} 3 {ms1}', out)
        self.assertIn(f'inquisition_findings_total{{target="example.com"}} 1 {ms2}', out)

    def test_non_history_metrics_stay_pointintime(self) -> None:
        out = render_prometheus([self._report_with_history()], include_history=True)
        # risk_score is a current gauge, no trailing timestamp
        line = next(l for l in out.splitlines() if l.startswith("inquisition_risk_score{"))
        self.assertEqual(len(line.split()), 2)  # metric and value only

    def test_default_is_pointintime(self) -> None:
        out = render_prometheus([self._report_with_history()])
        line = next(l for l in out.splitlines() if l.startswith("inquisition_findings_total{"))
        self.assertEqual(len(line.split()), 2)  # no timestamp


class PushTests(unittest.TestCase):
    def test_push_builds_job_url_and_sends_body(self) -> None:
        calls: list[dict[str, Any]] = []

        def fake_put(url: str, **kwargs: Any) -> None:
            calls.append({"url": url, **kwargs})

        push_metrics("http://gw:9091/", "metricdata\n", job="inq", sender=fake_put)
        self.assertEqual(calls[0]["url"], "http://gw:9091/metrics/job/inq")
        self.assertEqual(calls[0]["data"], b"metricdata\n")
        self.assertIn("text/plain", calls[0]["headers"]["Content-Type"])

    def test_push_raises_on_non_2xx_response(self) -> None:
        class _Resp:
            def raise_for_status(self) -> None:
                raise RuntimeError("400 Bad Request")

        def fake_put(url: str, **kwargs: Any) -> _Resp:
            return _Resp()

        with self.assertRaises(RuntimeError):
            push_metrics("http://gw:9091", "x\n", sender=fake_put)


if __name__ == "__main__":
    unittest.main()
