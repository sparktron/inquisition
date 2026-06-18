"""Tests for JSON fleet configuration resolution."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from fleet_config import FleetConfigError, load_fleet_config, resolved_configs
from models import ScanConfig, ScanDepth


def _base() -> ScanConfig:
    return ScanConfig(target="", depth=ScanDepth.STANDARD, sla_max_age=2)


class ResolveTests(unittest.TestCase):
    def test_string_and_object_targets(self) -> None:
        cfg = {"targets": ["a.com", {"target": "b.com", "depth": "deep"}]}
        configs = resolved_configs(cfg, _base())
        self.assertEqual([c.target for c in configs], ["a.com", "b.com"])
        self.assertEqual(configs[0].depth, ScanDepth.STANDARD)  # inherits base
        self.assertEqual(configs[1].depth, ScanDepth.DEEP)      # per-target override

    def test_defaults_then_per_target_precedence(self) -> None:
        cfg = {
            "defaults": {"depth": "quick", "sla_max_age": 5},
            "targets": [{"target": "a.com"}, {"target": "b.com", "sla_max_age": 1}],
        }
        configs = resolved_configs(cfg, _base())
        self.assertEqual(configs[0].depth, ScanDepth.QUICK)     # from defaults
        self.assertEqual(configs[0].sla_max_age, 5)             # from defaults
        self.assertEqual(configs[1].sla_max_age, 1)             # per-target wins

    def test_ports_and_types_coerced(self) -> None:
        cfg = {"targets": [{"target": "a.com", "ports": [80, 443], "timeout": 3.5, "active": True}]}
        c = resolved_configs(cfg, _base())[0]
        self.assertEqual(c.ports, (80, 443))
        self.assertEqual(c.timeout, 3.5)
        self.assertTrue(c.active)

    def test_sla_by_severity_becomes_overrides(self) -> None:
        cfg = {"targets": [{"target": "a.com", "sla_by_severity": {"critical": 1, "high": 3}}]}
        c = resolved_configs(cfg, _base())[0]
        self.assertEqual(dict(c.sla_severity_overrides), {"critical": 1, "high": 3})

    def test_unknown_field_raises(self) -> None:
        with self.assertRaises(FleetConfigError):
            resolved_configs({"targets": [{"target": "a.com", "bogus": 1}]}, _base())

    def test_bad_depth_raises(self) -> None:
        with self.assertRaises(FleetConfigError):
            resolved_configs({"targets": [{"target": "a.com", "depth": "ultra"}]}, _base())

    def test_target_object_without_target_raises(self) -> None:
        with self.assertRaises(FleetConfigError):
            resolved_configs({"targets": [{"depth": "deep"}]}, _base())


class LoadTests(unittest.TestCase):
    def test_load_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"targets": ["a.com"]}, fh)
            self.assertEqual(load_fleet_config(path)["targets"], ["a.com"])

    def test_missing_targets_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"defaults": {}}, fh)
            with self.assertRaises(FleetConfigError):
                load_fleet_config(path)

    def test_not_json_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with self.assertRaises(FleetConfigError):
                load_fleet_config(path)


if __name__ == "__main__":
    unittest.main()
