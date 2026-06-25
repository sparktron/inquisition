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
import os
import re
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from models import ScanConfig, ScanDepth, Severity

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

_STR_FIELDS = {"auth_header", "auth_cookie", "active_engine"}
# Valid crown-jewel asset-value tiers (Theme D / D2).
_ASSET_VALUES = {"crown", "high", "medium", "low"}
_INT_FIELDS = {"max_threads", "sla_max_age"}
_FLOAT_FIELDS = {"rate_limit", "timeout", "connect_timeout"}
_BOOL_FIELDS = {"active", "validate_poc"}


class FleetConfigError(ValueError):
    """Raised when a fleet config file is malformed."""


def _parse_yaml(text: str) -> Any:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        raise FleetConfigError(
            "PyYAML is required for YAML fleet configs — install pyyaml or use a .json file"
        ) from None
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise FleetConfigError(f"fleet config is not valid YAML: {exc}") from exc


def load_fleet_config(path: str) -> dict[str, Any]:
    """Load and minimally validate a JSON or YAML fleet config file."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise FleetConfigError(f"could not read fleet config: {exc}") from exc

    if path.lower().endswith((".yaml", ".yml")):
        data = _parse_yaml(text)
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise FleetConfigError(f"fleet config is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise FleetConfigError("fleet config must be an object with a 'targets' array")
    if not isinstance(data.get("targets"), list) or not data["targets"]:
        raise FleetConfigError("fleet config must define a non-empty 'targets' array")
    return data


def interpolate_env(obj: Any, env: Mapping[str, str] | None = None) -> Any:
    """Recursively replace ``${VAR}`` in string values from the environment.

    A reference to an undefined variable raises ``FleetConfigError`` rather than
    silently leaving the literal text — important when the value is a secret such
    as an auth token.
    """
    environ = os.environ if env is None else env
    if isinstance(obj, dict):
        return {k: interpolate_env(v, environ) for k, v in obj.items()}
    if isinstance(obj, list):
        return [interpolate_env(v, environ) for v in obj]
    if isinstance(obj, str):
        def _sub(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in environ:
                raise FleetConfigError(f"undefined environment variable in fleet config: ${{{name}}}")
            return environ[name]
        return _ENV_RE.sub(_sub, obj)
    return obj


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
    if key == "asset_value":
        tier = str(value).lower()
        if tier not in _ASSET_VALUES:
            raise FleetConfigError(
                f"invalid asset_value: {value!r} (use crown/high/medium/low)"
            )
        return "asset_value", tier
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
