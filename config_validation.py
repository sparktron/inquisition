"""Shared coercion and range validation for scanner and run configuration."""

from __future__ import annotations

import math
from typing import Any

from models import ScanConfig


class ConfigValidationError(ValueError):
    """Raised when a configuration value has an invalid type or range."""


def coerce_int(value: Any, name: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool):
        raise ConfigValidationError(f"{name} must be an integer, got {value!r}")
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise ConfigValidationError(f"{name} must be an integer, got {value!r}") from None
    if isinstance(value, float) and not value.is_integer():
        raise ConfigValidationError(f"{name} must be an integer, got {value!r}")
    if isinstance(value, str) and value.strip() != str(result):
        raise ConfigValidationError(f"{name} must be an integer, got {value!r}")
    if minimum is not None and result < minimum:
        raise ConfigValidationError(f"{name} must be >= {minimum}, got {result}")
    return result


def coerce_float(
    value: Any,
    name: str,
    *,
    minimum: float | None = None,
    exclusive_minimum: float | None = None,
) -> float:
    if isinstance(value, bool):
        raise ConfigValidationError(f"{name} must be a number, got {value!r}")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ConfigValidationError(f"{name} must be a number, got {value!r}") from None
    if not math.isfinite(result):
        raise ConfigValidationError(f"{name} must be finite, got {value!r}")
    if minimum is not None and result < minimum:
        raise ConfigValidationError(f"{name} must be >= {minimum:g}, got {result:g}")
    if exclusive_minimum is not None and result <= exclusive_minimum:
        raise ConfigValidationError(f"{name} must be > {exclusive_minimum:g}, got {result:g}")
    return result


def coerce_ports(value: Any, name: str = "ports") -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ConfigValidationError(f"{name} must be a non-empty list of integers")
    ports = tuple(coerce_int(port, f"{name} entry", minimum=1) for port in value)
    invalid = next((port for port in ports if port > 65535), None)
    if invalid is not None:
        raise ConfigValidationError(f"{name} entries must be in 1..65535, got {invalid}")
    return ports


def scan_config_errors(config: ScanConfig, *, require_target: bool = True) -> list[str]:
    """Return all invalid ScanConfig fields using the shared range rules."""
    errors: list[str] = []
    if require_target and not config.target:
        errors.append("target must not be empty")
    checks = (
        lambda: coerce_int(config.max_threads, "max_threads", minimum=1),
        lambda: coerce_float(config.rate_limit, "rate_limit", minimum=0),
        lambda: coerce_float(config.timeout, "timeout", exclusive_minimum=0),
        lambda: coerce_float(config.connect_timeout, "connect_timeout", exclusive_minimum=0),
        lambda: coerce_ports(config.ports),
        lambda: coerce_int(config.sla_max_age, "sla_max_age", minimum=0),
    )
    for check in checks:
        try:
            check()
        except ConfigValidationError as exc:
            errors.append(str(exc))
    if config.active_engine not in {"nuclei", "zap"}:
        errors.append("active_engine must be 'nuclei' or 'zap'")
    return errors


def validate_scan_config(config: ScanConfig, *, require_target: bool = True) -> ScanConfig:
    """Raise for an invalid ScanConfig and otherwise return it unchanged."""
    errors = scan_config_errors(config, require_target=require_target)
    if errors:
        raise ConfigValidationError("; ".join(errors))
    return config
