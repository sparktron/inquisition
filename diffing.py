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
_HISTORY_SUFFIX = ".history.json"
_DEFAULT_HISTORY_SIZE = 10

# Weights used to collapse a severity breakdown into one comparable risk score
# for trend direction. Higher-severity findings dominate, so fixing a CRITICAL
# counts for more than adding a handful of INFO notes.
_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 100, "high": 40, "medium": 10, "low": 3, "info": 0,
}


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
                "first_seen": f.first_seen,
                "scan_count": f.age_scans,
            }
            for f in report.findings
        ],
    }


def update_ages(
    report: ScanReport, previous: dict[str, Any] | None, now: datetime
) -> None:
    """Stamp each finding with its first-seen time and consecutive-scan count.

    A finding present in the previous snapshot carries its original ``first_seen``
    forward and increments its count; a finding not seen before (or returning
    after an absence) starts fresh at this scan.
    """
    prev_by_fp: dict[str, dict[str, Any]] = {}
    if previous:
        for entry in previous.get("findings", []):
            if isinstance(entry, dict) and "fingerprint" in entry:
                prev_by_fp[entry["fingerprint"]] = entry

    iso = now.isoformat()
    for finding in report.findings:
        fp = fingerprint(finding.category.value, finding.title)
        prev = prev_by_fp.get(fp)
        if prev and prev.get("first_seen"):
            finding.first_seen = str(prev["first_seen"])
            finding.age_scans = int(prev.get("scan_count", 0)) + 1
        else:
            finding.first_seen = iso
            finding.age_scans = 1


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


# ---------------------------------------------------------------------------
# Trend history (rolling window of past scans)
# ---------------------------------------------------------------------------

@dataclass
class TrendEntry:
    taken_at: str
    total: int
    counts: dict[str, int]


@dataclass
class TrendResult:
    """Movement across the last N scans of one target."""

    entries: list[TrendEntry] = field(default_factory=list)
    direction: str = "baseline"   # improving | worsening | stable | baseline
    total_delta: int = 0          # newest total minus oldest in the window
    crit_high_delta: int = 0      # newest (critical+high) minus oldest
    span: int = 0                 # number of scans compared

    def has_history(self) -> bool:
        return self.span >= 2


def _risk_score(counts: dict[str, int]) -> int:
    return sum(_SEVERITY_WEIGHT.get(sev, 0) * n for sev, n in counts.items())


def _history_path(target: str, state_dir: Path) -> Path:
    return state_dir / f"{_safe_target(target)}{_HISTORY_SUFFIX}"


def load_history(target: str, state_dir: Path) -> list[dict[str, Any]]:
    """Load the saved trend history (chronological) for ``target``, or []."""
    path = _history_path(target, state_dir)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    entries = data.get("entries", []) if isinstance(data, dict) else []
    return [e for e in entries if isinstance(e, dict)]


def append_to_history(
    report: ScanReport, state_dir: Path, max_entries: int = _DEFAULT_HISTORY_SIZE
) -> list[dict[str, Any]]:
    """Append a compact entry for ``report``, cap to ``max_entries``, persist, return it."""
    counts = report.summary_counts()
    entry = {
        "taken_at": (report.finished_at or report.started_at or datetime.now(timezone.utc)).isoformat(),
        "total": sum(counts.values()),
        "counts": counts,
    }
    history = load_history(report.target, state_dir)
    history.append(entry)
    if max_entries > 0:
        history = history[-max_entries:]

    state_dir.mkdir(parents=True, exist_ok=True)
    with open(_history_path(report.target, state_dir), "w", encoding="utf-8") as fh:
        json.dump({"target": report.target, "entries": history}, fh, indent=2)
    return history


def compute_trend(history: list[dict[str, Any]]) -> TrendResult:
    """Summarize movement across a chronological list of history entries."""
    entries = [
        TrendEntry(
            taken_at=str(e.get("taken_at", "")),
            total=int(e.get("total", 0)),
            counts={str(k): int(v) for k, v in (e.get("counts") or {}).items()},
        )
        for e in history
    ]
    if len(entries) < 2:
        return TrendResult(entries=entries, direction="baseline", span=len(entries))

    oldest, newest = entries[0], entries[-1]
    old_score, new_score = _risk_score(oldest.counts), _risk_score(newest.counts)
    if new_score < old_score:
        direction = "improving"
    elif new_score > old_score:
        direction = "worsening"
    else:
        direction = "stable"

    def crit_high(counts: dict[str, int]) -> int:
        return counts.get("critical", 0) + counts.get("high", 0)

    return TrendResult(
        entries=entries,
        direction=direction,
        total_delta=newest.total - oldest.total,
        crit_high_delta=crit_high(newest.counts) - crit_high(oldest.counts),
        span=len(entries),
    )
