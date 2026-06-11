"""Scan diffing — compare a scan against the previous run for the same target.

A point-in-time scan answers "how secure is this site right now." Continuous
assurance needs the *delta*: what got worse, what got fixed, what is still
outstanding. This module persists a normalized snapshot of each scan's findings
and computes the difference against the prior snapshot for the same target.

Findings are identified by a stable fingerprint — ``(category, title)`` — so an
issue is tracked across scans even as its volatile evidence (IPs, counts, byte
sizes) changes. Severity is tracked separately so a finding that changes
severity between scans surfaces as a regression/improvement rather than as a
fixed+new pair.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models import ScanReport, Severity, severity_at_least

_STATE_DIRNAME = ".state"


def _safe_target(target: str) -> str:
    return "".join(c if c.isalnum() or c in "-." else "_" for c in target)


def fingerprint(category: str, title: str) -> str:
    """Stable identity for a finding across scans (ignores volatile evidence)."""
    return f"{category}::{title}"


def snapshot_from_report(report: ScanReport) -> dict[str, Any]:
    """Build a normalized, serializable snapshot of a report's findings."""
    return {
        "target": report.target,
        "taken_at": (report.finished_at or report.started_at or datetime.now(timezone.utc)).isoformat(),
        "findings": [
            {
                "fingerprint": fingerprint(f.category.value, f.title),
                "category": f.category.value,
                "title": f.title,
                "severity": f.severity.value,
            }
            for f in report.findings
        ],
    }


@dataclass
class FindingDelta:
    fingerprint: str
    title: str
    category: str
    severity: str
    previous_severity: str | None = None  # set only for severity changes


@dataclass
class DiffResult:
    """The difference between the previous and current scan of one target."""

    is_baseline: bool = False  # True when there was no previous snapshot
    new: list[FindingDelta] = field(default_factory=list)
    fixed: list[FindingDelta] = field(default_factory=list)
    regressed: list[FindingDelta] = field(default_factory=list)   # severity got worse
    improved: list[FindingDelta] = field(default_factory=list)    # severity got better
    unchanged_count: int = 0

    def has_changes(self) -> bool:
        return bool(self.new or self.fixed or self.regressed or self.improved)

    def worst_new_severity(self, threshold: Severity) -> bool:
        """True if any new or regressed finding is at least ``threshold`` severe."""
        for delta in (*self.new, *self.regressed):
            try:
                if severity_at_least(Severity(delta.severity), threshold):
                    return True
            except ValueError:
                continue
        return False


def diff_snapshots(previous: dict[str, Any] | None, current: dict[str, Any]) -> DiffResult:
    """Compute the delta between a previous snapshot and the current one."""
    cur_by_fp = {f["fingerprint"]: f for f in current.get("findings", [])}

    if previous is None:
        return DiffResult(is_baseline=True, unchanged_count=len(cur_by_fp))

    prev_by_fp = {f["fingerprint"]: f for f in previous.get("findings", [])}
    result = DiffResult()

    for fp, cur in cur_by_fp.items():
        prev = prev_by_fp.get(fp)
        delta = FindingDelta(
            fingerprint=fp,
            title=cur["title"],
            category=cur["category"],
            severity=cur["severity"],
        )
        if prev is None:
            result.new.append(delta)
        elif prev["severity"] != cur["severity"]:
            delta.previous_severity = prev["severity"]
            if severity_at_least(Severity(cur["severity"]), Severity(prev["severity"])):
                # current is at least as severe as before, and they differ → worse
                result.regressed.append(delta)
            else:
                result.improved.append(delta)
        else:
            result.unchanged_count += 1

    for fp, prev in prev_by_fp.items():
        if fp not in cur_by_fp:
            result.fixed.append(FindingDelta(
                fingerprint=fp,
                title=prev["title"],
                category=prev["category"],
                severity=prev["severity"],
            ))

    return result


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _state_path(target: str, state_dir: Path) -> Path:
    return state_dir / f"{_safe_target(target)}.json"


def load_snapshot(target: str, state_dir: Path) -> dict[str, Any] | None:
    """Load the most recent saved snapshot for ``target``, or None."""
    path = _state_path(target, state_dir)
    try:
        with open(path, encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
            return data
    except (OSError, ValueError):
        return None


def save_snapshot(report: ScanReport, state_dir: Path) -> Path:
    """Persist a snapshot of ``report`` and return the file path."""
    state_dir.mkdir(parents=True, exist_ok=True)
    path = _state_path(report.target, state_dir)
    snapshot = snapshot_from_report(report)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)
    return path


def default_state_dir(reports_dir: str = "reports") -> Path:
    return Path(reports_dir) / _STATE_DIRNAME
