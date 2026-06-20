"""Structured JSONL audit log — one line per scan cycle, for ingestion.

Each completed scan cycle appends a single JSON object recording what was
scanned and the outcome, so a log pipeline (Loki, Elastic, a SIEM) can track
the daemon's activity over time without parsing human-readable output.
"""

from __future__ import annotations

import json
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


def append_jsonl(path: str, record: dict[str, Any]) -> None:
    """Append one record as a JSON line to ``path``."""
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
