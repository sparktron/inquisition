"""Tests for the multi-target CLI helpers."""

from __future__ import annotations

import argparse
import os
import tempfile
import unittest

from datetime import datetime, timezone

from inquisition import (
    _gather_targets,
    _jitter_delay,
    _output_path_for,
    _parse_sla_overrides,
    _resolve_targets,
    _run_targets,
)
from models import ReportFormat, ScanConfig, ScanReport


def _args(target: list[str], targets_file: str | None = None,
          fleet_config: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(target=target, targets_file=targets_file, fleet_config=fleet_config)


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
            # Each website gets its own subfolder under the --output directory.
            safe = "https___a.com"
            self.assertEqual(path, os.path.join(out_dir, safe, f"{safe}.json"))
            self.assertTrue(os.path.isdir(os.path.join(out_dir, safe)))  # per-site dir created


class SlaOverrideParseTests(unittest.TestCase):
    def test_empty_is_empty(self) -> None:
        self.assertEqual(_parse_sla_overrides(None), ())
        self.assertEqual(_parse_sla_overrides(""), ())

    def test_parses_pairs(self) -> None:
        self.assertEqual(
            _parse_sla_overrides("critical=1, high=3 ,medium=10"),
            (("critical", 1), ("high", 3), ("medium", 10)),
        )

    def test_unknown_severity_exits(self) -> None:
        with self.assertRaises(SystemExit):
            _parse_sla_overrides("bogus=2")

    def test_non_numeric_exits(self) -> None:
        with self.assertRaises(SystemExit):
            _parse_sla_overrides("high=soon")

    def test_negative_value_exits(self) -> None:
        with self.assertRaises(SystemExit):
            _parse_sla_overrides("high=-1")

    def test_zero_value_is_allowed(self) -> None:
        self.assertEqual(_parse_sla_overrides("high=0"), (("high", 0),))


class ResolveTargetsTests(unittest.TestCase):
    def test_non_fleet_builds_config_per_target(self) -> None:
        base = ScanConfig(target="", sla_max_age=3)
        targets, by_target = _resolve_targets(_args(["a.com", "b.com"]), base)
        self.assertEqual(targets, ["a.com", "b.com"])
        self.assertEqual(by_target["a.com"].target, "a.com")
        self.assertEqual(by_target["a.com"].sla_max_age, 3)  # inherits base


class JitterTests(unittest.TestCase):
    def test_zero_or_negative_is_zero(self) -> None:
        self.assertEqual(_jitter_delay(0), 0.0)
        self.assertEqual(_jitter_delay(-5), 0.0)

    def test_within_range(self) -> None:
        for _ in range(50):
            self.assertTrue(0.0 <= _jitter_delay(2.0) <= 2.0)


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
