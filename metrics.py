"""Prometheus / OpenMetrics text exposition for scan results.

Emits one set of gauges per scanned target so a fleet run produces a single
scrape-able file. Designed for the Prometheus text exposition format (also
accepted by OpenMetrics parsers): a node_exporter textfile collector, a
Pushgateway, or a CI artifact a monitoring job ingests.
"""

from __future__ import annotations

from models import ScanReport, Severity
from report import _risk_score

_PREFIX = "inquisition"


def _escape_label(value: str) -> str:
    """Escape a Prometheus label value (backslash, double-quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _metric(name: str, labels: dict[str, str], value: float) -> str:
    label_str = ",".join(f'{k}="{_escape_label(v)}"' for k, v in labels.items())
    # Render integers without a trailing .0 for readability.
    num = int(value) if float(value).is_integer() else value
    return f"{_PREFIX}_{name}{{{label_str}}} {num}"


def render_prometheus(reports: list[ScanReport]) -> str:
    """Render scan results for one or more targets as Prometheus text exposition."""
    blocks: list[tuple[str, str, str]] = [
        ("findings", "gauge", "Open findings by target and severity"),
        ("findings_total", "gauge", "Total open findings by target"),
        ("risk_score", "gauge", "Severity-weighted risk score by target"),
        ("cves_total", "gauge", "Correlated CVE records by target"),
        ("misconfigurations_total", "gauge", "Derived misconfigurations by target"),
        ("finding_max_age_scans", "gauge", "Oldest finding's age in consecutive scans by target"),
        ("scan_duration_seconds", "gauge", "Scan wall-clock duration by target"),
    ]

    lines: list[str] = []
    for name, mtype, help_text in blocks:
        lines.append(f"# HELP {_PREFIX}_{name} {help_text}")
        lines.append(f"# TYPE {_PREFIX}_{name} {mtype}")
        for report in reports:
            lines.extend(_series_for(name, report))
    return "\n".join(lines) + "\n"


def _series_for(name: str, report: ScanReport) -> list[str]:
    target = report.target
    counts = report.summary_counts()

    if name == "findings":
        return [
            _metric("findings", {"target": target, "severity": sev.value}, counts.get(sev.value, 0))
            for sev in Severity
        ]
    if name == "findings_total":
        return [_metric("findings_total", {"target": target}, sum(counts.values()))]
    if name == "risk_score":
        return [_metric("risk_score", {"target": target}, _risk_score(counts)[0])]
    if name == "cves_total":
        return [_metric("cves_total", {"target": target}, len(report.cve_records))]
    if name == "misconfigurations_total":
        return [_metric("misconfigurations_total", {"target": target}, len(report.misconfigurations))]
    if name == "finding_max_age_scans":
        max_age = max((f.age_scans for f in report.findings), default=0)
        return [_metric("finding_max_age_scans", {"target": target}, max_age)]
    if name == "scan_duration_seconds":
        duration = 0.0
        if report.finished_at and report.started_at:
            duration = max(0.0, (report.finished_at - report.started_at).total_seconds())
        return [_metric("scan_duration_seconds", {"target": target}, round(duration, 3))]
    return []
