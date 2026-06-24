"""Detailed analysis and remediation knowledge-base loader for Inquisition findings."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

_KB_RESOURCE = "data/analysis_kb.json"


@lru_cache(maxsize=1)
def _load_entries() -> tuple[tuple[str, dict[str, Any]], ...]:
    """Load ordered knowledge-base entries from structured package data."""
    data_path = resources.files("modules").joinpath(_KB_RESOURCE)
    raw = json.loads(data_path.read_text(encoding="utf-8"))
    entries: list[tuple[str, dict[str, Any]]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("KB entry must be an object")
        keyword = _required_string(item, "keyword")
        entries.append((
            keyword,
            {
                "analysis": _required_string(item, "analysis"),
                "remediation": _required_string(item, "remediation"),
                "attack_scenario": item.get("attack_scenario", ""),
                "mitre_techniques": item.get("mitre_techniques", []),
                "poc_command": item.get("poc_command", ""),
            },
        ))
    return tuple(entries)


def _required_string(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"KB entry field {key!r} must be a non-empty string")
    return value


def entries() -> tuple[tuple[str, dict[str, Any]], ...]:
    """Return all ordered knowledge-base entries."""
    return _load_entries()


def lookup(title: str) -> dict[str, Any] | None:
    """Return the knowledge-base entry for the given finding title, or None.

    Matching is done by checking whether each KB keyword appears as a
    substring of the lowercase finding title. The first match wins, so
    more-specific entries must appear earlier in the structured data file.
    """
    title_lower = title.lower()
    for keyword, entry in _load_entries():
        if keyword in title_lower:
            return entry
    return None
