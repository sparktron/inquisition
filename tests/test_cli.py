"""Tests for the multi-target CLI helpers."""

from __future__ import annotations

import argparse
import os
import tempfile
import unittest

from datetime import datetime, timezone

from inquisition import (
    _discovery_mode,
    _gather_targets,
    _gather_targets_and_meta,
    _jitter_delay,
    _output_path_for,
    _parse_args,
    _parse_sla_overrides,
    _resolve_jobs,
    _resolve_targets,
    _run_targets,
)
from models import ReportFormat, ScanConfig, ScanReport


def _args(target: list[str], targets_file: str | None = None,
          fleet_config: str | None = None, *, discovery: bool = False,
          full: bool = False, depth: str = "standard") -> argparse.Namespace:
    return argparse.Namespace(
        target=target, targets_file=targets_file, fleet_config=fleet_config,
        discovery=discovery, full=full, depth=depth,
    )


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


class CidrExpansionTests(unittest.TestCase):
    def test_cidr_expands_to_usable_hosts(self) -> None:
        # /30 yields the two usable hosts (network and broadcast excluded).
        self.assertEqual(
            _gather_targets(_args(["192.168.1.0/30"])),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_slash31_includes_both_addresses(self) -> None:
        self.assertEqual(
            _gather_targets(_args(["10.0.0.0/31"])),
            ["10.0.0.0", "10.0.0.1"],
        )

    def test_slash32_is_the_single_address(self) -> None:
        self.assertEqual(_gather_targets(_args(["10.0.0.5/32"])), ["10.0.0.5"])

    def test_host_bits_set_are_masked(self) -> None:
        # A non-network address with a prefix still expands the whole block.
        self.assertEqual(
            _gather_targets(_args(["192.168.1.1/30"])),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_hostnames_and_bare_ips_pass_through(self) -> None:
        self.assertEqual(
            _gather_targets(_args(["example.com", "10.0.0.5"])),
            ["example.com", "10.0.0.5"],
        )

    def test_dedup_across_cidr_and_explicit(self) -> None:
        # Explicit .1 first, then a /30 that also contains it -> .1 not repeated.
        self.assertEqual(
            _gather_targets(_args(["192.168.1.1", "192.168.1.0/30"])),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_ipv6_cidr_expands(self) -> None:
        result = _gather_targets(_args(["2001:db8::/126"]))
        # /126 has 4 addresses; IPv6 hosts() drops the subnet-router anycast.
        self.assertIn("2001:db8::1", result)
        self.assertTrue(all(":" in h for h in result))

    def test_oversize_range_exits(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            _gather_targets(_args(["10.0.0.0/8"]))
        self.assertEqual(raised.exception.code, 2)

    def test_invalid_network_exits(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            _gather_targets(_args(["192.168.1.0/33"]))
        self.assertEqual(raised.exception.code, 2)


class NumericValidationTests(unittest.TestCase):
    def test_invalid_numeric_ranges_exit_as_argparse_errors(self) -> None:
        invalid = (
            ["example.com", "--jobs", "0"],
            ["example.com", "--history-size", "0"],
            ["example.com", "--history-max-age-days", "-1"],
            ["example.com", "--watch", "-1"],
            ["example.com", "--watch-jitter", "-0.1"],
            ["example.com", "--metrics-serve", "70000"],
            ["example.com", "--audit-max-bytes", "-1"],
            ["example.com", "--audit-backups", "-1"],
            ["example.com", "--audit-max-age-days", "-1"],
            ["example.com", "--threads", "0"],
            ["example.com", "--rate-limit", "-0.1"],
            ["example.com", "--timeout", "0"],
            ["example.com", "--connect-timeout", "0"],
            ["example.com", "--ports", "0"],
            ["example.com", "--ports", "70000"],
        )
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as raised:
                _parse_args(argv)
            self.assertEqual(raised.exception.code, 2)

    def test_documented_zero_disable_values_are_accepted(self) -> None:
        args = _parse_args([
            "example.com",
            "--history-max-age-days", "0",
            "--sla-max-age", "0",
            "--watch", "0",
            "--watch-jitter", "0",
            "--metrics-serve", "0",
            "--audit-max-bytes", "0",
            "--audit-backups", "0",
            "--audit-max-age-days", "0",
        ])
        self.assertEqual(args.audit_backups, 0)

    def test_malformed_auth_values_exit_as_argparse_errors(self) -> None:
        invalid = (
            ["example.com", "--auth-header", "Bearer token"],
            ["example.com", "--auth-header", "Bad Header: token"],
            ["example.com", "--auth-header", "Authorization:"],
            ["example.com", "--auth-header", "Authorization: token\r\nX-Evil: yes"],
            ["example.com", "--auth-cookie", "session=x\nX-Evil: yes"],
            ["example.com", "--auth-cookie", "   "],
        )
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as raised:
                _parse_args(argv)
            self.assertEqual(raised.exception.code, 2)

    def test_network_map_flag_parsed(self) -> None:
        args = _parse_args(["example.com", "--network-map", "map.html"])
        self.assertEqual(args.network_map, "map.html")

    def test_network_map_defaults_none(self) -> None:
        self.assertIsNone(_parse_args(["example.com"]).network_map)

    def test_well_formed_auth_values_are_accepted(self) -> None:
        args = _parse_args([
            "example.com",
            "--auth-header", "Authorization: Bearer token",
            "--auth-cookie", "session=abc",
        ])
        self.assertEqual(args.auth_header, "Authorization: Bearer token")
        self.assertEqual(args.auth_cookie, "session=abc")


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
        targets, by_target, is_subnet = _resolve_targets(_args(["a.com", "b.com"]), base)
        self.assertEqual(targets, ["a.com", "b.com"])
        self.assertFalse(is_subnet)
        self.assertEqual(by_target["a.com"].target, "a.com")
        self.assertEqual(by_target["a.com"].sla_max_age, 3)  # inherits base

    def test_cidr_target_is_flagged_as_subnet(self) -> None:
        base = ScanConfig(target="", sla_max_age=3)
        targets, by_target, is_subnet = _resolve_targets(_args(["192.168.1.0/30"]), base)
        self.assertEqual(targets, ["192.168.1.1", "192.168.1.2"])
        self.assertTrue(is_subnet)
        self.assertEqual(by_target["192.168.1.1"].target, "192.168.1.1")

    def test_single_host_cidr_is_not_a_subnet(self) -> None:
        base = ScanConfig(target="", sla_max_age=3)
        _targets, _by, is_subnet = _resolve_targets(_args(["10.0.0.5/32"]), base)
        self.assertFalse(is_subnet)

    def test_gather_meta_flags_mixed_cidr(self) -> None:
        targets, is_subnet = _gather_targets_and_meta(_args(["a.com", "192.168.1.0/30"]))
        self.assertEqual(targets, ["a.com", "192.168.1.1", "192.168.1.2"])
        self.assertTrue(is_subnet)


class DiscoveryModeTests(unittest.TestCase):
    def test_subnet_defaults_to_discovery(self) -> None:
        self.assertTrue(_discovery_mode(_args(["10.0.0.0/24"]), is_subnet=True))

    def test_non_subnet_is_full(self) -> None:
        self.assertFalse(_discovery_mode(_args(["a.com"]), is_subnet=False))

    def test_explicit_discovery_flag_wins(self) -> None:
        self.assertTrue(_discovery_mode(_args(["a.com"], discovery=True), is_subnet=False))

    def test_full_flag_forces_full_on_subnet(self) -> None:
        self.assertFalse(_discovery_mode(_args(["10.0.0.0/24"], full=True), is_subnet=True))

    def test_depth_deep_forces_full_on_subnet(self) -> None:
        self.assertFalse(_discovery_mode(_args(["10.0.0.0/24"], depth="deep"), is_subnet=True))

    def test_resolve_targets_marks_subnet_configs_discovery(self) -> None:
        base = ScanConfig(target="")
        _t, by_target, _s = _resolve_targets(_args(["192.168.1.0/30"]), base)
        self.assertTrue(all(c.discovery for c in by_target.values()))

    def test_resolve_targets_full_flag_keeps_configs_full(self) -> None:
        base = ScanConfig(target="")
        _t, by_target, _s = _resolve_targets(_args(["192.168.1.0/30"], full=True), base)
        self.assertTrue(all(not c.discovery for c in by_target.values()))

    def test_resolve_targets_single_host_not_discovery(self) -> None:
        base = ScanConfig(target="")
        _t, by_target, _s = _resolve_targets(_args(["a.com"]), base)
        self.assertFalse(by_target["a.com"].discovery)


class ResolveJobsTests(unittest.TestCase):
    def test_explicit_jobs_honored(self) -> None:
        self.assertEqual(_resolve_jobs(4, 100, consolidated=True), 4)
        self.assertEqual(_resolve_jobs(1, 100, consolidated=True), 1)

    def test_auto_parallel_for_consolidated_subnet(self) -> None:
        self.assertEqual(_resolve_jobs(None, 5, consolidated=True), 5)

    def test_auto_jobs_capped(self) -> None:
        from inquisition import _AUTO_JOBS_CAP
        self.assertEqual(_resolve_jobs(None, 1000, consolidated=True), _AUTO_JOBS_CAP)

    def test_sequential_when_not_consolidated(self) -> None:
        self.assertEqual(_resolve_jobs(None, 50, consolidated=False), 1)

    def test_single_target_stays_sequential(self) -> None:
        self.assertEqual(_resolve_jobs(None, 1, consolidated=True), 1)


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

    def test_on_done_called_in_order_sequential(self) -> None:
        seen: list[tuple[int, int, str]] = []
        _run_targets(["a", "b"], self._scan, jobs=1,
                     on_done=lambda d, t, r: seen.append((d, t, r.target)))
        self.assertEqual(seen, [(1, 2, "a"), (2, 2, "b")])

    def test_on_done_called_for_every_target_concurrent(self) -> None:
        seen: list[int] = []
        reports = _run_targets(["a", "b", "c"], self._scan, jobs=3,
                               on_done=lambda d, t, r: seen.append(d))
        self.assertEqual(sorted(seen), [1, 2, 3])
        self.assertEqual([r.target for r in reports], ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
