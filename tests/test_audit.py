"""Tests for the JSONL audit log."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from audit import append_jsonl, build_cycle_record
from models import Finding, FindingCategory, ScanReport, Severity


def _report(target: str, *findings: Finding) -> ScanReport:
    start = datetime(2026, 6, 1, tzinfo=timezone.utc)
    return ScanReport(
        target=target,
        started_at=start,
        finished_at=start + timedelta(seconds=2),
        findings=list(findings),
        report_path=f"reports/{target}.txt",
    )


def _f(sev: Severity, age: int = 0) -> Finding:
    return Finding(title="x", category=FindingCategory.TLS, severity=sev, evidence="e", age_scans=age)


class BuildRecordTests(unittest.TestCase):
    def test_cycle_record_shape(self) -> None:
        reports = [_report("a.com", _f(Severity.HIGH, age=3)), _report("b.com")]
        rec = build_cycle_record(reports, cycle=4, fail_triggered=True)
        self.assertEqual(rec["event"], "scan_cycle")
        self.assertEqual(rec["cycle"], 4)
        self.assertEqual(rec["target_count"], 2)
        self.assertTrue(rec["fail_triggered"])
        self.assertEqual(rec["targets"][0]["target"], "a.com")
        self.assertEqual(rec["targets"][0]["total"], 1)
        self.assertEqual(rec["targets"][0]["highest"], "high")
        self.assertEqual(rec["targets"][0]["max_age_scans"], 3)
        self.assertEqual(rec["targets"][0]["duration_seconds"], 2.0)
        self.assertIn("ts", rec)

    def test_empty_target_has_no_highest(self) -> None:
        rec = build_cycle_record([_report("a.com")], cycle=1, fail_triggered=False)
        self.assertIsNone(rec["targets"][0]["highest"])
        self.assertEqual(rec["targets"][0]["total"], 0)


class AppendTests(unittest.TestCase):
    def test_appends_one_line_per_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            append_jsonl(path, {"cycle": 1})
            append_jsonl(path, {"cycle": 2})
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[1])["cycle"], 2)

    def test_no_rotation_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.jsonl")
            for i in range(20):
                append_jsonl(path, {"cycle": i})
            self.assertFalse(os.path.exists(path + ".1"))

    def test_age_rotation_when_oldest_record_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.jsonl")
            old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": old_ts, "cycle": 1}) + "\n")
            # Oldest record is 10 days old; a 7-day cap rotates before the new line.
            append_jsonl(path, {"ts": datetime.now(timezone.utc).isoformat(), "cycle": 2},
                         max_age_days=7)
            self.assertTrue(os.path.exists(path + ".1"))
            with open(path, encoding="utf-8") as fh:
                live = fh.read().splitlines()
            self.assertEqual(len(live), 1)
            self.assertEqual(json.loads(live[0])["cycle"], 2)

    def test_age_rotation_skipped_when_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.jsonl")
            for i in range(3):
                append_jsonl(path, {"ts": datetime.now(timezone.utc).isoformat(), "cycle": i},
                             max_age_days=7)
            self.assertFalse(os.path.exists(path + ".1"))

    def test_rotation_caps_size_and_keeps_backups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.jsonl")
            # Each record is well over 20 bytes, so a 60-byte cap rotates often.
            for i in range(10):
                append_jsonl(path, {"cycle": i, "pad": "x" * 40}, max_bytes=60, backups=2)
            # Current file plus at most `backups` rotated files exist.
            self.assertTrue(os.path.exists(path))
            self.assertTrue(os.path.exists(path + ".1"))
            self.assertFalse(os.path.exists(path + ".3"))  # capped at backups=2
            # The newest record is in the live file.
            with open(path, encoding="utf-8") as fh:
                last = fh.read().splitlines()[-1]
            self.assertEqual(json.loads(last)["cycle"], 9)


if __name__ == "__main__":
    unittest.main()
