from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from diffing import (
    diff_snapshots,
    load_snapshot,
    save_snapshot,
    snapshot_from_report,
)
from models import (
    Finding,
    FindingCategory,
    ScanReport,
    Severity,
)


def _report(findings: list[Finding], target: str = "example.com") -> ScanReport:
    return ScanReport(
        target=target,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings=findings,
    )


def _finding(title: str, severity: Severity, category: FindingCategory = FindingCategory.HTTP_HEADER) -> Finding:
    return Finding(title=title, category=category, severity=severity, evidence="e")


class DiffSnapshotTests(unittest.TestCase):
    def test_first_scan_is_baseline(self) -> None:
        current = snapshot_from_report(_report([_finding("Missing header: CSP", Severity.MEDIUM)]))
        diff = diff_snapshots(None, current)
        self.assertTrue(diff.is_baseline)
        self.assertEqual(diff.unchanged_count, 1)
        self.assertFalse(diff.has_changes())

    def test_new_and_fixed_findings_detected(self) -> None:
        previous = snapshot_from_report(_report([_finding("Old issue", Severity.LOW)]))
        current = snapshot_from_report(_report([_finding("New issue", Severity.HIGH)]))
        diff = diff_snapshots(previous, current)

        self.assertEqual([d.title for d in diff.new], ["New issue"])
        self.assertEqual([d.title for d in diff.fixed], ["Old issue"])
        self.assertFalse(diff.regressed)

    def test_severity_regression_detected(self) -> None:
        previous = snapshot_from_report(_report([_finding("Cert expiring", Severity.LOW)]))
        current = snapshot_from_report(_report([_finding("Cert expiring", Severity.CRITICAL)]))
        diff = diff_snapshots(previous, current)

        self.assertEqual(len(diff.regressed), 1)
        self.assertEqual(diff.regressed[0].previous_severity, "low")
        self.assertEqual(diff.regressed[0].severity, "critical")
        self.assertFalse(diff.new)
        self.assertFalse(diff.fixed)

    def test_severity_improvement_detected(self) -> None:
        previous = snapshot_from_report(_report([_finding("Weak TLS", Severity.HIGH)]))
        current = snapshot_from_report(_report([_finding("Weak TLS", Severity.LOW)]))
        diff = diff_snapshots(previous, current)

        self.assertEqual(len(diff.improved), 1)
        self.assertFalse(diff.regressed)

    def test_unchanged_finding_counted(self) -> None:
        finding = [_finding("Stable", Severity.MEDIUM)]
        diff = diff_snapshots(
            snapshot_from_report(_report(finding)),
            snapshot_from_report(_report(finding)),
        )
        self.assertEqual(diff.unchanged_count, 1)
        self.assertFalse(diff.has_changes())

    def test_worst_new_severity_threshold(self) -> None:
        previous = snapshot_from_report(_report([]))
        current = snapshot_from_report(_report([_finding("New high", Severity.HIGH)]))
        diff = diff_snapshots(previous, current)
        self.assertTrue(diff.worst_new_severity(Severity.HIGH))
        self.assertTrue(diff.worst_new_severity(Severity.MEDIUM))
        self.assertFalse(diff.worst_new_severity(Severity.CRITICAL))


class SnapshotPersistenceTests(unittest.TestCase):
    def test_save_then_load_round_trip(self) -> None:
        report = _report([_finding("Missing header: HSTS", Severity.MEDIUM)])
        with TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            save_snapshot(report, state_dir)
            loaded = load_snapshot("example.com", state_dir)

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded["target"], "example.com")
        self.assertEqual(loaded["findings"][0]["title"], "Missing header: HSTS")

    def test_load_missing_snapshot_returns_none(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertIsNone(load_snapshot("never-scanned.test", Path(tmp)))

    def test_diff_against_persisted_baseline(self) -> None:
        with TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            save_snapshot(_report([_finding("Issue A", Severity.LOW)]), state_dir)
            previous = load_snapshot("example.com", state_dir)
            current = snapshot_from_report(_report([
                _finding("Issue A", Severity.LOW),
                _finding("Issue B", Severity.HIGH),
            ]))
            diff = diff_snapshots(previous, current)

        self.assertEqual([d.title for d in diff.new], ["Issue B"])
        self.assertEqual(diff.unchanged_count, 1)


if __name__ == "__main__":
    unittest.main()
