"""Structured JSONL audit log — one line per scan cycle, for ingestion.

Each completed scan cycle appends a single JSON object recording what was
scanned and the outcome, so a log pipeline (Loki, Elastic, a SIEM) can track
the daemon's activity over time without parsing human-readable output.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from models import ScanReport


def _target_record(report: ScanReport) -> dict[str, Any]:
    counts = report.summary_counts()
    highest = report.highest_severity()
    duration = 0.0
    if report.finished_at and report.started_at:
        duration = max(0.0, (report.finished_at - report.started_at).total_seconds())
    return {
        "target": report.target,
        "total": sum(counts.values()),
        "counts": counts,
        "highest": highest.value if highest else None,
        "max_age_scans": max((f.age_scans for f in report.findings), default=0),
        "cve_count": len(report.cve_records),
        "misconfig_count": len(report.misconfigurations),
        "report_path": report.report_path,
        "duration_seconds": round(duration, 3),
        "errors": len(report.errors),
    }


def build_cycle_record(
    reports: list[ScanReport], *, cycle: int, fail_triggered: bool
) -> dict[str, Any]:
    """Build the JSON object describing one scan cycle."""
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "scan_cycle",
        "cycle": cycle,
        "target_count": len(reports),
        "fail_triggered": fail_triggered,
        "targets": [_target_record(r) for r in reports],
    }


def _first_record_age_days(path: str, now: datetime) -> float | None:
    """Age in days of the oldest record in ``path`` (from its ``ts``), or None."""
    try:
        with open(path, encoding="utf-8") as fh:
            first = fh.readline()
    except OSError:
        return None
    try:
        ts = json.loads(first).get("ts")
    except ValueError:
        return None
    if not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).total_seconds() / 86400.0


def _rotate(path: str, backups: int) -> None:
    """Roll ``path`` to ``path.1``, shifting existing backups up to ``backups``."""
    oldest = f"{path}.{backups}"
    if os.path.exists(oldest):
        os.remove(oldest)
    for i in range(backups - 1, 0, -1):
        src, dst = f"{path}.{i}", f"{path}.{i + 1}"
        if os.path.exists(src):
            os.replace(src, dst)
    if os.path.exists(path):
        os.replace(path, f"{path}.1")


def append_jsonl(
    path: str,
    record: dict[str, Any],
    *,
    max_bytes: int = 0,
    backups: int = 3,
    max_age_days: float = 0,
) -> None:
    """Append ``record`` as a JSON line, rotating first if a cap is exceeded.

    Rotation (when ``backups > 0``) rolls the file to ``path.1`` (and ``.1``→``.2``
    …) before the new line starts a fresh file. It triggers on size
    (``max_bytes``) or on the age of the oldest record (``max_age_days``, read
    from its ``ts`` field) — whichever applies first.
    """
    line = json.dumps(record) + "\n"
    if backups > 0 and os.path.exists(path) and os.path.getsize(path) > 0:
        should_rotate = False
        if max_bytes > 0 and os.path.getsize(path) + len(line.encode("utf-8")) > max_bytes:
            should_rotate = True
        if not should_rotate and max_age_days > 0:
            age = _first_record_age_days(path, datetime.now(timezone.utc))
            if age is not None and age >= max_age_days:
                should_rotate = True
        if should_rotate:
            _rotate(path, backups)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
