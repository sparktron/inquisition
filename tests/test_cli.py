"""Tests for the multi-target CLI helpers."""

from __future__ import annotations

import argparse
import os
import tempfile
import unittest

from datetime import datetime, timezone

from inquisition import _gather_targets, _output_path_for, _run_targets
from models import ReportFormat, ScanReport


def _args(target: list[str], targets_file: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(target=target, targets_file=targets_file)


class GatherTargetsTests(unittest.TestCase):
    def test_positional_only(self) -> None:
        self.assertEqual(_gather_targets(_args(["a.com", "b.com"])), ["a.com", "b.com"])

    def test_dedup_preserves_order(self) -> None:
        self.assertEqual(_gather_targets(_args(["a.com", "b.com", "a.com"])), ["a.com", "b.com"])

    def test_merges_file_skipping_comments_and_blanks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "targets.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("c.com\n\n# a comment\nd.com\na.com\n")
            result = _gather_targets(_args(["a.com"], targets_file=path))
        # positional a.com first, then file entries, a.com deduped
        self.assertEqual(result, ["a.com", "c.com", "d.com"])


class OutputPathTests(unittest.TestCase):
    def test_single_target_uses_output_verbatim(self) -> None:
        self.assertEqual(
            _output_path_for("out.txt", "a.com", ReportFormat.TEXT, multi=False), "out.txt"
        )

    def test_single_target_none_stays_none(self) -> None:
        self.assertIsNone(_output_path_for(None, "a.com", ReportFormat.TEXT, multi=False))

    def test_multi_no_output_is_none(self) -> None:
        self.assertIsNone(_output_path_for(None, "a.com", ReportFormat.JSON, multi=True))

    def test_multi_with_output_dir_builds_per_target_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "fleet")
            path = _output_path_for(out_dir, "https://a.com", ReportFormat.JSON, multi=True)
            self.assertEqual(path, os.path.join(out_dir, "https___a.com.json"))
            self.assertTrue(os.path.isdir(out_dir))  # directory is created


class RunTargetsTests(unittest.TestCase):
    @staticmethod
    def _scan(target: str) -> ScanReport:
        return ScanReport(target=target, started_at=datetime.now(timezone.utc))

    def test_sequential_preserves_order(self) -> None:
        reports = _run_targets(["a", "b", "c"], self._scan, jobs=1)
        self.assertEqual([r.target for r in reports], ["a", "b", "c"])

    def test_concurrent_preserves_input_order(self) -> None:
        # Even though completion order may vary, the returned list matches input.
        targets = [f"host{i}" for i in range(8)]
        reports = _run_targets(targets, self._scan, jobs=4)
        self.assertEqual([r.target for r in reports], targets)

    def test_each_target_scanned_once(self) -> None:
        calls: list[str] = []

        def scan(target: str) -> ScanReport:
            calls.append(target)
            return ScanReport(target=target, started_at=datetime.now(timezone.utc))

        _run_targets(["x", "y"], scan, jobs=2)
        self.assertEqual(sorted(calls), ["x", "y"])


if __name__ == "__main__":
    unittest.main()
