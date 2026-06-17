from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from diffing import (
    append_to_history,
    compute_trend,
    diff_snapshots,
    load_history,
    load_snapshot,
    save_snapshot,
    snapshot_from_report,
    update_ages,
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


def _entry(total: int, **counts: int) -> dict[str, object]:
    return {"taken_at": "2026-01-01T00:00:00+00:00", "total": total, "counts": counts}


class AgeTests(unittest.TestCase):
    def test_new_finding_starts_at_one(self) -> None:
        report = _report([_finding("A", Severity.HIGH)])
        update_ages(report, None, datetime(2026, 6, 1, tzinfo=timezone.utc))
        self.assertEqual(report.findings[0].age_scans, 1)
        self.assertTrue(report.findings[0].first_seen.startswith("2026-06-01"))

    def test_returning_finding_carries_first_seen_and_increments(self) -> None:
        first = _report([_finding("A", Severity.HIGH)])
        update_ages(first, None, datetime(2026, 6, 1, tzinfo=timezone.utc))
        prev_snapshot = snapshot_from_report(first)

        second = _report([_finding("A", Severity.HIGH)])
        update_ages(second, prev_snapshot, datetime(2026, 6, 5, tzinfo=timezone.utc))
        self.assertEqual(second.findings[0].age_scans, 2)
        self.assertTrue(second.findings[0].first_seen.startswith("2026-06-01"))  # carried forward

    def test_absent_then_returning_resets(self) -> None:
        first = _report([_finding("A", Severity.HIGH)])
        update_ages(first, None, datetime(2026, 6, 1, tzinfo=timezone.utc))
        # A snapshot that does NOT contain "A"
        other = snapshot_from_report(_report([_finding("B", Severity.LOW)]))
        update_ages(first, other, datetime(2026, 6, 9, tzinfo=timezone.utc))
        self.assertEqual(first.findings[0].age_scans, 1)
        self.assertTrue(first.findings[0].first_seen.startswith("2026-06-09"))


class TrendTests(unittest.TestCase):
    def test_single_entry_is_baseline(self) -> None:
        trend = compute_trend([_entry(3, medium=3)])
        self.assertEqual(trend.direction, "baseline")
        self.assertFalse(trend.has_history())

    def test_fewer_critical_is_improving(self) -> None:
        trend = compute_trend([_entry(5, critical=2, low=3), _entry(4, critical=0, low=4)])
        self.assertEqual(trend.direction, "improving")
        self.assertEqual(trend.total_delta, -1)
        self.assertEqual(trend.crit_high_delta, -2)

    def test_more_high_is_worsening(self) -> None:
        trend = compute_trend([_entry(2, low=2), _entry(3, high=1, low=2)])
        self.assertEqual(trend.direction, "worsening")
        self.assertEqual(trend.crit_high_delta, 1)

    def test_same_risk_score_is_stable(self) -> None:
        trend = compute_trend([_entry(3, medium=3), _entry(3, medium=3)])
        self.assertEqual(trend.direction, "stable")

    def test_more_low_findings_still_improving_if_critical_dropped(self) -> None:
        # one critical removed outweighs several added lows (weighted score)
        trend = compute_trend([_entry(2, critical=1, low=1), _entry(6, low=6)])
        self.assertEqual(trend.direction, "improving")

    def test_append_caps_and_round_trips(self) -> None:
        with TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            for i in range(5):
                report = _report([_finding(f"f{i}", Severity.LOW)])
                history = append_to_history(report, state_dir, max_entries=3)
            self.assertEqual(len(history), 3)  # capped
            self.assertEqual(load_history("example.com", state_dir), history)
            trend = compute_trend(history)
            self.assertEqual(trend.span, 3)

    def test_age_pruning_drops_stale_entries(self) -> None:
        with TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            # Seed an old entry (2 years ago) and a recent one directly.
            old = {"taken_at": "2024-01-01T00:00:00+00:00", "total": 9, "counts": {"high": 9}}
            recent = {"taken_at": datetime.now(timezone.utc).isoformat(), "total": 1, "counts": {"low": 1}}
            with open(state_dir / "example.com.history.json", "w", encoding="utf-8") as fh:
                json.dump({"target": "example.com", "entries": [old, recent]}, fh)

            report = _report([_finding("f", Severity.LOW)])
            history = append_to_history(report, state_dir, max_entries=50, max_age_days=30)
            # The 2-year-old entry is gone; the recent one and the new append remain.
            self.assertEqual(len(history), 2)
            self.assertNotIn("2024-01-01T00:00:00+00:00", [e["taken_at"] for e in history])


if __name__ == "__main__":
    unittest.main()
