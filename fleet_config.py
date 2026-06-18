"""JSON fleet configuration — define targets and per-target scan overrides.

A fleet config lets one run scan many targets with different settings each,
without long command lines. Shape::

    {
      "defaults": {"depth": "standard", "sla_max_age": 5},
      "targets": [
        "plain-target.com",
        {"target": "api.example.com", "depth": "deep",
         "sla_by_severity": {"critical": 1, "high": 3}}
      ]
    }

Per-target settings override ``defaults``, which override the base config built
from CLI flags. Only scan-behavior fields may be overridden (run-level options
such as output/notify stay global).
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from models import ScanConfig, ScanDepth, Severity

_STR_FIELDS = {"auth_header", "auth_cookie", "active_engine"}
_INT_FIELDS = {"max_threads", "sla_max_age"}
_FLOAT_FIELDS = {"rate_limit", "timeout", "connect_timeout"}
_BOOL_FIELDS = {"active"}


class FleetConfigError(ValueError):
    """Raised when a fleet config file is malformed."""


def load_fleet_config(path: str) -> dict[str, Any]:
    """Load and minimally validate a JSON fleet config file."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise FleetConfigError(f"could not read fleet config: {exc}") from exc
    except ValueError as exc:
        raise FleetConfigError(f"fleet config is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FleetConfigError("fleet config must be a JSON object with a 'targets' array")
    if not isinstance(data.get("targets"), list) or not data["targets"]:
        raise FleetConfigError("fleet config must define a non-empty 'targets' array")
    return data


def _coerce(key: str, value: Any) -> tuple[str, Any]:
    """Map a config key/value to a (ScanConfig field, typed value) pair."""
    if key == "depth":
        try:
            return "depth", ScanDepth(str(value))
        except ValueError:
            raise FleetConfigError(f"invalid depth: {value!r} (use quick/standard/deep)") from None
    if key == "ports":
        if not isinstance(value, list):
            raise FleetConfigError("ports must be a list of integers")
        try:
            return "ports", tuple(int(p) for p in value)
        except (TypeError, ValueError):
            raise FleetConfigError("ports must be a list of integers") from None
    if key == "sla_by_severity":
        return "sla_severity_overrides", _coerce_sla(value)
    if key in _INT_FIELDS:
        return key, int(value)
    if key in _FLOAT_FIELDS:
        return key, float(value)
    if key in _BOOL_FIELDS:
        return key, bool(value)
    if key in _STR_FIELDS:
        return key, str(value)
    raise FleetConfigError(f"unknown fleet config field: {key!r}")


def _coerce_sla(value: Any) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, dict):
        raise FleetConfigError("sla_by_severity must be an object like {\"critical\": 1}")
    valid = {s.value for s in Severity}
    pairs: list[tuple[str, int]] = []
    for sev, scans in value.items():
        if str(sev).lower() not in valid:
            raise FleetConfigError(f"unknown severity in sla_by_severity: {sev!r}")
        pairs.append((str(sev).lower(), int(scans)))
    return tuple(pairs)


def _apply(base: ScanConfig, target: str, overrides: dict[str, Any]) -> ScanConfig:
    kwargs: dict[str, Any] = {"target": target}
    for key, value in overrides.items():
        field, typed = _coerce(key, value)
        kwargs[field] = typed
    return replace(base, **kwargs)


def resolved_configs(fleet_cfg: dict[str, Any], base: ScanConfig) -> list[ScanConfig]:
    """Build one ScanConfig per fleet target, merging defaults then per-target overrides."""
    defaults = fleet_cfg.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise FleetConfigError("fleet config 'defaults' must be an object")

    configs: list[ScanConfig] = []
    for entry in fleet_cfg["targets"]:
        if isinstance(entry, str):
            entry = {"target": entry}
        if not isinstance(entry, dict):
            raise FleetConfigError("each fleet target must be a string or an object")
        target = entry.get("target")
        if not target or not isinstance(target, str):
            raise FleetConfigError("each fleet target object needs a string 'target'")
        merged = {**defaults, **{k: v for k, v in entry.items() if k != "target"}}
        configs.append(_apply(base, target, merged))
    return configs
