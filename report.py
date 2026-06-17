"""Report generation — text, JSON, and HTML output."""

from __future__ import annotations

import html as _html
import json
import re
from datetime import datetime
from typing import Any

from models import (
    Confidence,
    Finding,
    FindingCategory,
    ReportFormat,
    ScanReport,
    Severity,
    TOOL_REFERENCE,
)
from vuln_correlation import tools_for_category
from diffing import compute_trend
import analysis_kb

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high": 15,
    "medium": 5,
    "low": 1,
    "info": 0,
}

_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (0,   "A+"),
    (9,   "A"),
    (24,  "B"),
    (49,  "C"),
    (99,  "D"),
    (999, "F"),
]


def _risk_score(counts: dict[str, int]) -> tuple[int, str]:
    """Return (numeric_score, letter_grade) derived from severity counts."""
    score = sum(counts.get(sev, 0) * weight for sev, weight in _SEVERITY_WEIGHTS.items())
    grade = "F"
    for threshold, g in _GRADE_THRESHOLDS:
        if score <= threshold:
            grade = g
            break
    return score, grade


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------

def _age_phrase(f: Finding) -> str:
    """Human phrase for a finding's cross-scan age, e.g. 'new' or 'open 4 scans since 2026-06-01'."""
    if f.age_scans <= 1:
        return "new this scan"
    day = f.first_seen[:10] if f.first_seen else "?"
    return f"open {f.age_scans} scans (since {day})"


def _hr(char: str = "=", width: int = 72) -> str:
    return char * width


def _section(title: str) -> str:
    return f"\n{_hr()}\n  {title}\n{_hr()}\n"


def _wrap_paragraphs(text: str, indent: str = "    ") -> list[str]:
    """Split a multi-paragraph KB entry into indented output lines."""
    lines: list[str] = []
    for paragraph in text.split("\n"):
        lines.append(f"{indent}{paragraph}")
    return lines


def _render_deep_analysis(lines: list[str], report: ScanReport) -> None:
    """Append the DEEP ISSUE ANALYSIS section to lines."""
    actionable = [
        f for f in report.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    ]
    if not actionable:
        return

    lines.append(_section("DEEP ISSUE ANALYSIS"))
    lines.append(
        "  This section explains what each finding is, the underlying mechanism that\n"
        "  makes it a security problem, and the real-world risk it presents."
    )

    for sev in _SEV_ORDER:
        group = [f for f in actionable if f.severity == sev]
        if not group:
            continue
        for f in group:
            kb = analysis_kb.lookup(f.title)
            analysis_text = kb["analysis"] if kb else f.impact
            if not analysis_text:
                continue

            label = f"[{_SEVERITY_LABEL[f.severity]}] {f.title}"
            lines.append(f"\n  {label}")
            lines.append("  " + "-" * (len(label) + 2))
            lines.extend(_wrap_paragraphs(analysis_text))
            lines.append(f"\n    Evidence: {f.evidence}")
            lines.append("")


def _render_remediation_guide(lines: list[str], report: ScanReport) -> None:
    """Append the REMEDIATION GUIDE section to lines."""
    actionable = [
        f for f in report.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    if not actionable:
        return

    lines.append(_section("REMEDIATION GUIDE"))
    lines.append(
        "  Step-by-step instructions for resolving each finding, ordered by severity.\n"
        "  Address CRITICAL and HIGH items immediately; schedule MEDIUM items promptly."
    )

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
        group = [f for f in actionable if f.severity == sev]
        if not group:
            continue
        lines.append(f"\n  {'=' * 68}")
        lines.append(f"  {_SEVERITY_LABEL[sev]} PRIORITY")
        lines.append(f"  {'=' * 68}\n")
        for f in group:
            kb = analysis_kb.lookup(f.title)
            remediation_text = kb["remediation"] if kb else f.remediation
            if not remediation_text:
                remediation_text = f.remediation or "No specific remediation guidance available."

            label = f"[{_SEVERITY_LABEL[f.severity]}] {f.title}"
            lines.append(f"  {label}")
            lines.append("  " + "-" * (len(label) + 2))
            lines.extend(_wrap_paragraphs(remediation_text))
            if f.verification:
                lines.append(f"\n    Verification: {f.verification}")
            if f.references:
                lines.append(f"    References  : {', '.join(f.references)}")
            lines.append("")


def render_text(report: ScanReport, *, brief: bool = False) -> str:
    """Produce a human-readable text report."""
    lines: list[str] = []

    # --- Banner ---
    lines.append(_hr("#"))
    lines.append("  INQUISITION — Security Reconnaissance Report")
    lines.append(_hr("#"))
    lines.append(f"  Target   : {report.target}")
    lines.append(f"  Started  : {report.started_at:%Y-%m-%d %H:%M:%S UTC}")
    if report.finished_at:
        duration = (report.finished_at - report.started_at).total_seconds()
        lines.append(f"  Finished : {report.finished_at:%Y-%m-%d %H:%M:%S UTC} ({duration:.1f}s)")
    if report.config:
        lines.append(f"  Depth    : {report.config.depth.value}")
        lines.append(f"  Mode     : {'dry-run' if report.config.dry_run else 'safe' if report.config.safe_mode else 'standard'}")
    lines.append("")

    # --- Executive Summary ---
    lines.append(_section("EXECUTIVE SUMMARY"))
    counts = report.summary_counts()
    total = sum(counts.values())
    score, grade = _risk_score(counts)
    lines.append(f"  Total findings: {total}")
    for sev in _SEV_ORDER:
        count = counts.get(sev.value, 0)
        if count:
            lines.append(f"    {_SEVERITY_LABEL[sev]:<10s}: {count}")
    lines.append(f"  CVEs correlated  : {len(report.cve_records)}")
    lines.append(f"  Misconfigurations: {len(report.misconfigurations)}")
    if report.errors:
        lines.append(f"  Scan errors      : {len(report.errors)}")
    lines.append(f"\n  Risk score : {score}  |  Security grade : {grade}")
    lines.append("  (Grade scale: A+ = clean, A/B = minor issues, C = moderate risk,")
    lines.append("   D = significant risk, F = critical exposure requiring immediate action)")
    lines.append("")

    # --- Remediation Priority Matrix ---
    lines.append(_section("REMEDIATION PRIORITY MATRIX"))
    actionable = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    if actionable:
        lines.append(f"  {'#':<4s} {'Severity':<10s} {'Category':<16s} {'Title'}")
        lines.append(f"  {'-'*4} {'-'*10} {'-'*16} {'-'*38}")
        for idx, f in enumerate(sorted(actionable, key=lambda x: _SEV_ORDER.index(x.severity)), 1):
            lines.append(f"  {idx:<4d} {_SEVERITY_LABEL[f.severity]:<10s} {f.category.value:<16s} {f.title}")
    else:
        lines.append("  No actionable findings.")
    lines.append("")

    # --- Detailed Findings ---
    lines.append(_section("DETAILED FINDINGS"))
    for sev in _SEV_ORDER:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        lines.append(f"\n  --- {_SEVERITY_LABEL[sev]} ({len(group)}) ---\n")
        for f in group:
            lines.append(f"  [{_SEVERITY_LABEL[f.severity]}] {f.title}")
            lines.append(f"    Category : {f.category.value}")
            if f.confidence is not Confidence.CONFIRMED:
                lines.append(f"    Confidence: {f.confidence.value}")
            lines.append(f"    Evidence : {f.evidence}")
            if f.impact:
                lines.append(f"    Impact   : {f.impact}")
            if f.remediation:
                lines.append(f"    Fix      : {f.remediation}")
            if f.verification:
                lines.append(f"    Verify   : {f.verification}")
            if f.cpe:
                lines.append(f"    CPE      : {f.cpe}")
            if f.age_scans:
                lines.append(f"    Age      : {_age_phrase(f)}")
            if f.references:
                lines.append(f"    Refs     : {', '.join(f.references)}")
            # Tool reference
            tools = tools_for_category(f.category)
            if tools:
                lines.append(f"    Tools    : {', '.join(tools)}")
            lines.append("")

    # --- Deep Issue Analysis ---
    if not brief:
        _render_deep_analysis(lines, report)

    # --- Remediation Guide ---
    if not brief:
        _render_remediation_guide(lines, report)

    # --- CVE Correlation ---
    if report.cve_records:
        lines.append(_section("CVE CORRELATION"))
        for cve in sorted(report.cve_records, key=lambda c: c.cvss_score, reverse=True):
            lines.append(f"  {cve.cve_id}  (CVSS {cve.cvss_score:.1f} / {_SEVERITY_LABEL[cve.severity]})")
            lines.append(f"    {cve.description[:200]}")
            if cve.references:
                lines.append(f"    Refs: {', '.join(cve.references[:3])}")
            lines.append("")

    # --- Misconfiguration Summary ---
    if report.misconfigurations:
        lines.append(_section("MISCONFIGURATION SUMMARY"))
        for mc in sorted(report.misconfigurations, key=lambda m: _SEV_ORDER.index(m.severity)):
            lines.append(f"  [{_SEVERITY_LABEL[mc.severity]}] {mc.name}")
            lines.append(f"    {mc.description}")
            lines.append(f"    Evidence  : {mc.evidence}")
            lines.append(f"    Remediate : {mc.remediation}")
            lines.append("")

    # --- Tool Reference Table ---
    lines.append(_section("TOOL REFERENCE TABLE"))
    lines.append(f"  {'Category':<20s} {'Recommended tools'}")
    lines.append(f"  {'-'*20} {'-'*50}")
    for cat in FindingCategory:
        tools = TOOL_REFERENCE.get(cat, [])
        if tools:
            lines.append(f"  {cat.value:<20s} {', '.join(tools)}")
    lines.append("")

    # --- Errors ---
    if report.errors:
        lines.append(_section("SCAN ERRORS"))
        for err in report.errors:
            lines.append(f"  - {err}")
        lines.append("")

    lines.append(_hr("#"))
    lines.append("  End of report")
    lines.append(_hr("#"))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def _finding_to_dict(f: Finding) -> dict[str, Any]:
    d: dict[str, Any] = {
        "title": f.title,
        "category": f.category.value,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "evidence": f.evidence,
    }
    if f.impact:
        d["impact"] = f.impact
    if f.remediation:
        d["remediation"] = f.remediation
    if f.verification:
        d["verification"] = f.verification
    if f.cpe:
        d["cpe"] = f.cpe
    if f.age_scans:
        d["first_seen"] = f.first_seen
        d["age_scans"] = f.age_scans
    if f.references:
        d["references"] = f.references
    d["tools"] = tools_for_category(f.category)
    kb = analysis_kb.lookup(f.title)
    if kb:
        d["deep_analysis"] = kb["analysis"]
        d["deep_remediation"] = kb["remediation"]
    return d


def _json_report_dict(report: ScanReport) -> dict[str, Any]:
    """The per-report JSON body, reused by single and combined renderers."""
    data: dict[str, Any] = {
        "target": report.target,
        "started_at": report.started_at.isoformat(),
        "finished_at": report.finished_at.isoformat() if report.finished_at else None,
        "summary": report.summary_counts(),
        "findings": [_finding_to_dict(f) for f in report.findings],
        "cve_records": [
            {
                "cve_id": c.cve_id,
                "description": c.description,
                "severity": c.severity.value,
                "cvss_score": c.cvss_score,
                "references": c.references,
            }
            for c in report.cve_records
        ],
        "misconfigurations": [
            {
                "name": m.name,
                "description": m.description,
                "severity": m.severity.value,
                "evidence": m.evidence,
                "remediation": m.remediation,
            }
            for m in report.misconfigurations
        ],
        "errors": report.errors,
    }
    if report.history:
        trend = compute_trend(report.history)
        data["history"] = report.history
        data["trend"] = {
            "direction": trend.direction,
            "span": trend.span,
            "total_delta": trend.total_delta,
            "crit_high_delta": trend.crit_high_delta,
        }
    return data


def render_json(report: ScanReport) -> str:
    """Produce a JSON report."""
    data = _json_report_dict(report)
    data["tool_reference"] = {cat.value: tools for cat, tools in TOOL_REFERENCE.items()}
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# SARIF report (for CI / GitHub code scanning)
# ---------------------------------------------------------------------------

# SARIF result levels: error, warning, note, none.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub sorts code-scanning alerts by a 0.0–10.0 numeric band.
_SARIF_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

_TOOL_VERSION = "0.1.0"
_TOOL_URI = "https://github.com/sparktron/inquisition"


def _sarif_rule_id(f: Finding) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", f.title.lower()).strip("-")
    return f"{f.category.value}/{slug}" if slug else f.category.value


def _sarif_run(report: ScanReport) -> dict[str, Any]:
    """Build a single SARIF ``run`` for one target's report."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in report.findings:
        rule_id = _sarif_rule_id(f)
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.impact or f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {
                    "category": f.category.value,
                    "security-severity": _SARIF_SECURITY_SEVERITY[f.severity],
                },
            }
            if f.remediation:
                rule["help"] = {"text": f.remediation}
            rules[rule_id] = rule

        message = f.evidence or f.title
        if f.remediation:
            message = f"{message}\nRemediation: {f.remediation}"
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.target},
                }
            }],
            "partialFingerprints": {"inquisitionFingerprint": rule_id},
        })

    return {
        "tool": {
            "driver": {
                "name": "Inquisition",
                "informationUri": _TOOL_URI,
                "version": _TOOL_VERSION,
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }


def render_sarif(report: ScanReport) -> str:
    """Produce a SARIF 2.1.0 report for CI ingestion / GitHub code scanning."""
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [_sarif_run(report)],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_SEV_CSS: dict[Severity, tuple[str, str, str]] = {
    # (badge-bg, badge-text, badge-border)
    Severity.CRITICAL: ("#fef2f2", "#991b1b", "#fca5a5"),
    Severity.HIGH:     ("#fff7ed", "#9a3412", "#fdba74"),
    Severity.MEDIUM:   ("#fffbeb", "#92400e", "#fcd34d"),
    Severity.LOW:      ("#eff6ff", "#1e40af", "#93c5fd"),
    Severity.INFO:     ("#f8fafc", "#475569", "#cbd5e1"),
}

_GRADE_CSS: dict[str, str] = {
    "A+": "#15803d", "A": "#16a34a",
    "B": "#65a30d", "C": "#ca8a04",
    "D": "#ea580c", "F": "#dc2626",
}


def _e(text: str) -> str:
    """HTML-escape a string."""
    return _html.escape(str(text), quote=True)


def _badge(severity: Severity) -> str:
    bg, fg, border = _SEV_CSS[severity]
    label = _SEVERITY_LABEL[severity]
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:0.75rem;font-weight:700;letter-spacing:.05em;'
        f'background:{bg};color:{fg};border:1px solid {border}">{label}</span>'
    )


def _nl2br(text: str) -> str:
    """Convert newlines to <br> and preserve leading spaces as &nbsp;."""
    lines = []
    for line in _e(text).split("\n"):
        stripped = line.lstrip()
        spaces = len(line) - len(stripped)
        lines.append("&nbsp;" * spaces + stripped)
    return "<br>\n".join(lines)


def _trend_sparkline_html(report: ScanReport) -> str:
    """Inline SVG sparkline of total findings over the rolling history window."""
    totals = [int(e.get("total", 0)) for e in report.history]
    if len(totals) < 2:
        return ""

    trend = compute_trend(report.history)
    color = {"improving": "#16a34a", "worsening": "#dc2626", "stable": "#64748b"}.get(
        trend.direction, "#64748b"
    )
    arrow = {"improving": "▼", "worsening": "▲", "stable": "▬"}.get(trend.direction, "")

    w, h, pad = 180, 36, 3
    lo, hi = min(totals), max(totals)
    span = hi - lo or 1
    n = len(totals)
    step = (w - 2 * pad) / (n - 1)
    pts = [
        (pad + i * step, h - pad - (t - lo) / span * (h - 2 * pad))
        for i, t in enumerate(totals)
    ]
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    last_x, last_y = pts[-1]
    delta = f"{'+' if trend.total_delta > 0 else ''}{trend.total_delta}"
    return (
        f'<div style="margin-top:12px;display:flex;align-items:center;gap:10px">'
        f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
        f'aria-label="findings trend over last {n} scans">'
        f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{poly}"/>'
        f'<circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="2.5" fill="{color}"/></svg>'
        f'<span style="font-size:.85rem;color:{color};font-weight:600">{arrow} {trend.direction}</span>'
        f'<span style="font-size:.8rem;color:#64748b">over last {n} scans '
        f'(total {delta}, crit+high {"+" if trend.crit_high_delta > 0 else ""}{trend.crit_high_delta})</span>'
        f'</div>'
    )


def render_html(report: ScanReport) -> str:
    """Produce a self-contained HTML security report."""
    counts = report.summary_counts()
    score, grade = _risk_score(counts)
    grade_color = _GRADE_CSS.get(grade, "#dc2626")
    duration = ""
    if report.finished_at:
        secs = (report.finished_at - report.started_at).total_seconds()
        duration = f" ({secs:.1f}s)"

    mode = "dry-run"
    if report.config:
        if report.config.dry_run:
            mode = "dry-run"
        elif report.config.safe_mode:
            mode = "safe / read-only"
        else:
            mode = "standard"

    # ---- severity summary chips ----
    summary_chips = ""
    for sev in _SEV_ORDER:
        n = counts.get(sev.value, 0)
        if n:
            summary_chips += f'<span style="margin-right:8px">{_badge(sev)} &nbsp;{n}</span>'

    # ---- priority matrix rows ----
    actionable = [
        f for f in report.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    matrix_rows = ""
    for idx, f in enumerate(sorted(actionable, key=lambda x: _SEV_ORDER.index(x.severity)), 1):
        matrix_rows += (
            f"<tr>"
            f"<td style='padding:6px 10px;color:#64748b'>{idx}</td>"
            f"<td style='padding:6px 10px'>{_badge(f.severity)}</td>"
            f"<td style='padding:6px 10px;color:#64748b;font-size:.85rem'>{_e(f.category.value)}</td>"
            f"<td style='padding:6px 10px;font-weight:500'>{_e(f.title)}</td>"
            f"</tr>\n"
        )

    # ---- finding cards ----
    finding_cards = ""
    for sev in _SEV_ORDER:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        bg, fg, border = _SEV_CSS[sev]
        finding_cards += (
            f'<h3 style="margin:24px 0 8px;color:{fg}">'
            f'{_SEVERITY_LABEL[sev]} ({len(group)})</h3>\n'
        )
        for f in group:
            kb = analysis_kb.lookup(f.title)
            tools = tools_for_category(f.category)

            rows = f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Category</td><td>{_e(f.category.value)}</td></tr>\n"
            if f.confidence is not Confidence.CONFIRMED:
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Confidence</td><td>{_e(f.confidence.value)}</td></tr>\n"
            rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Evidence</td><td><code style='font-size:.85rem;background:#f1f5f9;padding:1px 4px;border-radius:3px'>{_e(f.evidence)}</code></td></tr>\n"
            if f.impact:
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Impact</td><td>{_e(f.impact)}</td></tr>\n"
            if f.remediation:
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Quick fix</td><td>{_e(f.remediation)}</td></tr>\n"
            if f.cpe:
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>CPE</td><td><code style='font-size:.85rem'>{_e(f.cpe)}</code></td></tr>\n"
            if f.age_scans:
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Age</td><td>{_e(_age_phrase(f))}</td></tr>\n"
            if tools:
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Tools</td><td>{_e(', '.join(tools))}</td></tr>\n"

            analysis_section = ""
            if kb:
                analysis_section = (
                    f'<details style="margin-top:12px">'
                    f'<summary style="cursor:pointer;font-weight:600;color:#1e293b;padding:4px 0">'
                    f'&#128269; Issue Analysis</summary>'
                    f'<div style="margin-top:8px;padding:12px;background:#f8fafc;border-radius:6px;'
                    f'font-size:.9rem;line-height:1.7;white-space:pre-wrap;font-family:inherit">'
                    f'{_e(kb["analysis"])}</div></details>'
                    f'<details style="margin-top:8px">'
                    f'<summary style="cursor:pointer;font-weight:600;color:#1e293b;padding:4px 0">'
                    f'&#128295; Remediation Steps</summary>'
                    f'<div style="margin-top:8px;padding:12px;background:#f0fdf4;border-radius:6px;'
                    f'font-size:.9rem;line-height:1.7;white-space:pre-wrap;font-family:inherit">'
                    f'{_e(kb["remediation"])}</div></details>'
                )

            finding_cards += (
                f'<div style="margin-bottom:16px;border:1px solid {border};border-radius:8px;'
                f'background:{bg};overflow:hidden">'
                f'<div style="padding:10px 16px;display:flex;align-items:center;gap:10px;'
                f'border-bottom:1px solid {border}">'
                f'{_badge(f.severity)}'
                f'<span style="font-weight:600;color:#1e293b">{_e(f.title)}</span>'
                f'</div>'
                f'<div style="padding:12px 16px">'
                f'<table style="border-collapse:collapse;width:100%">{rows}</table>'
                f'{analysis_section}'
                f'</div>'
                f'</div>\n'
            )

    # ---- CVE rows ----
    cve_rows = ""
    for cve in sorted(report.cve_records, key=lambda c: c.cvss_score, reverse=True):
        bg, fg, border = _SEV_CSS[cve.severity]
        refs_html = ""
        if cve.references:
            refs_html = " ".join(
                f'<a href="{_e(r)}" style="color:#2563eb;font-size:.8rem" target="_blank" rel="noopener">[ref]</a>'
                for r in cve.references[:3]
            )
        cve_rows += (
            f"<tr style='border-bottom:1px solid #e2e8f0'>"
            f"<td style='padding:8px 10px;font-weight:600;white-space:nowrap'>{_e(cve.cve_id)}</td>"
            f"<td style='padding:8px 10px'>{_badge(cve.severity)} {cve.cvss_score:.1f}</td>"
            f"<td style='padding:8px 10px;font-size:.9rem'>{_e(cve.description[:200])}</td>"
            f"<td style='padding:8px 10px'>{refs_html}</td>"
            f"</tr>\n"
        )

    # ---- misconfiguration rows ----
    mc_rows = ""
    for mc in sorted(report.misconfigurations, key=lambda m: _SEV_ORDER.index(m.severity)):
        mc_rows += (
            f"<tr style='border-bottom:1px solid #e2e8f0'>"
            f"<td style='padding:8px 10px'>{_badge(mc.severity)}</td>"
            f"<td style='padding:8px 10px;font-weight:500'>{_e(mc.name)}</td>"
            f"<td style='padding:8px 10px;font-size:.9rem'>{_e(mc.description)}</td>"
            f"<td style='padding:8px 10px;font-size:.9rem'>{_e(mc.remediation)}</td>"
            f"</tr>\n"
        )

    # ---- error list ----
    error_items = "".join(f"<li style='color:#dc2626'>{_e(e)}</li>" for e in report.errors)
    errors_section = (
        f'<section style="margin-bottom:40px">'
        f'<h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">Scan Errors</h2>'
        f'<ul style="margin:0;padding-left:20px">{error_items}</ul>'
        f'</section>'
        if report.errors else ""
    )

    finished_str = ""
    if report.finished_at:
        finished_str = f"<br>Finished: {report.finished_at:%Y-%m-%d %H:%M:%S UTC}{duration}"

    depth_str = report.config.depth.value if report.config else "unknown"

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Inquisition Report — {_e(report.target)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 0; background: #f1f5f9; color: #1e293b; line-height: 1.6; }}
  a {{ color: #2563eb; }}
  details > summary {{ user-select: none; }}
  details > summary::-webkit-details-marker {{ color: #94a3b8; }}
</style>
</head>
<body>

<!-- Header -->
<header style="background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:#f8fafc;padding:32px 40px">
  <div style="max-width:1100px;margin:0 auto">
    <div style="font-size:1.4rem;font-weight:800;letter-spacing:.05em;color:#38bdf8">
      &#128273; INQUISITION
    </div>
    <div style="font-size:.9rem;color:#94a3b8;margin-top:4px">Security Reconnaissance Report</div>
    <div style="margin-top:20px;display:flex;flex-wrap:wrap;gap:32px">
      <div>
        <div style="font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em">Target</div>
        <div style="font-size:1.2rem;font-weight:600;color:#e2e8f0">{_e(report.target)}</div>
      </div>
      <div>
        <div style="font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em">Started</div>
        <div style="font-size:.9rem;color:#e2e8f0">{report.started_at:%Y-%m-%d %H:%M:%S UTC}{duration}</div>
      </div>
      <div>
        <div style="font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em">Depth / Mode</div>
        <div style="font-size:.9rem;color:#e2e8f0">{_e(depth_str)} / {_e(mode)}</div>
      </div>
      <div>
        <div style="font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em">Security Grade</div>
        <div style="font-size:2rem;font-weight:800;color:{grade_color}">{_e(grade)}</div>
      </div>
      <div>
        <div style="font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em">Risk Score</div>
        <div style="font-size:2rem;font-weight:800;color:{grade_color}">{score}</div>
      </div>
    </div>
  </div>
</header>

<main style="max-width:1100px;margin:0 auto;padding:32px 24px">

<!-- Executive Summary -->
<section style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">Executive Summary</h2>
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px">{summary_chips}</div>
  <div style="color:#64748b;font-size:.9rem">
    CVEs correlated: <strong>{len(report.cve_records)}</strong> &nbsp;|&nbsp;
    Misconfigurations: <strong>{len(report.misconfigurations)}</strong> &nbsp;|&nbsp;
    Total findings: <strong>{sum(counts.values())}</strong>
  </div>
  {_trend_sparkline_html(report)}
  <div style="margin-top:10px;font-size:.85rem;color:#64748b">
    Grade scale: <strong>A+</strong> = clean &nbsp;·&nbsp;
    <strong>A/B</strong> = minor issues &nbsp;·&nbsp;
    <strong>C</strong> = moderate risk &nbsp;·&nbsp;
    <strong>D</strong> = significant risk &nbsp;·&nbsp;
    <strong>F</strong> = critical exposure
  </div>
</section>

<!-- Priority Matrix -->
<section style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">Remediation Priority Matrix</h2>
  {'<p style="color:#64748b">No actionable findings.</p>' if not matrix_rows else f'''
  <div style="overflow-x:auto">
  <table style="width:100%;border-collapse:collapse;font-size:.9rem">
    <thead>
      <tr style="background:#f8fafc;border-bottom:2px solid #e2e8f0">
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">#</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Severity</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Category</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Title</th>
      </tr>
    </thead>
    <tbody>{matrix_rows}</tbody>
  </table>
  </div>'''}
</section>

<!-- Detailed Findings -->
<section style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">Detailed Findings</h2>
  <p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:16px">
    Click <em>Issue Analysis</em> or <em>Remediation Steps</em> on any card to expand the deep-dive content.
  </p>
  {finding_cards if finding_cards else '<p style="color:#64748b">No findings.</p>'}
</section>

<!-- CVE Correlation -->
{f'''<section style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">CVE Correlation</h2>
  <div style="overflow-x:auto">
  <table style="width:100%;border-collapse:collapse;font-size:.9rem">
    <thead>
      <tr style="background:#f8fafc;border-bottom:2px solid #e2e8f0">
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">CVE ID</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Severity / CVSS</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Description</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Refs</th>
      </tr>
    </thead>
    <tbody>{cve_rows}</tbody>
  </table>
  </div>
</section>''' if report.cve_records else ''}

<!-- Misconfigurations -->
{f'''<section style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">Misconfiguration Summary</h2>
  <div style="overflow-x:auto">
  <table style="width:100%;border-collapse:collapse;font-size:.9rem">
    <thead>
      <tr style="background:#f8fafc;border-bottom:2px solid #e2e8f0">
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Severity</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Name</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Description</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Remediation</th>
      </tr>
    </thead>
    <tbody>{mc_rows}</tbody>
  </table>
  </div>
</section>''' if report.misconfigurations else ''}

{errors_section}

</main>

<footer style="background:#0f172a;color:#475569;text-align:center;padding:16px;font-size:.8rem;margin-top:40px">
  Generated by Inquisition &nbsp;·&nbsp; {_e(report.target)} &nbsp;·&nbsp; {report.started_at:%Y-%m-%d %H:%M UTC}
</footer>

</body>
</html>"""

    return html_doc


def render(report: ScanReport, fmt: ReportFormat, *, brief: bool = False) -> str:
    if fmt == ReportFormat.JSON:
        return render_json(report)
    if fmt == ReportFormat.HTML:
        return render_html(report)
    if fmt == ReportFormat.SARIF:
        return render_sarif(report)
    return render_text(report, brief=brief)


# ---------------------------------------------------------------------------
# Combined (fleet) reports — one artifact spanning several targets
# ---------------------------------------------------------------------------

def _fleet_summary(reports: list[ScanReport]) -> dict[str, Any]:
    """Aggregate severity counts across every report in a fleet run."""
    totals: dict[str, int] = {sev.value: 0 for sev in Severity}
    for report in reports:
        for sev_value, count in report.summary_counts().items():
            totals[sev_value] += count
    return {
        "targets": [r.target for r in reports],
        "target_count": len(reports),
        "total_findings": sum(totals.values()),
        "counts": totals,
    }


def render_json_combined(reports: list[ScanReport]) -> str:
    """One JSON document holding every target's report plus a fleet summary."""
    data: dict[str, Any] = {
        "tool": "inquisition",
        "report_type": "fleet",
        "fleet_summary": _fleet_summary(reports),
        "reports": [_json_report_dict(r) for r in reports],
        "tool_reference": {cat.value: tools for cat, tools in TOOL_REFERENCE.items()},
    }
    return json.dumps(data, indent=2)


def render_sarif_combined(reports: list[ScanReport]) -> str:
    """One SARIF 2.1.0 document with one run per target (GitHub accepts many runs)."""
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [_sarif_run(r) for r in reports],
    }
    return json.dumps(sarif, indent=2)


def _last_scan_delta_html(report: ScanReport) -> str:
    """Colored cell showing the change in total findings vs the immediately previous scan."""
    totals = [int(e.get("total", 0)) for e in report.history]
    if len(totals) < 2:
        return "<span style='color:#94a3b8'>—</span>"
    delta = totals[-1] - totals[-2]
    if delta > 0:
        return f"<span style='color:#dc2626;font-weight:600'>▲ +{delta}</span>"
    if delta < 0:
        return f"<span style='color:#16a34a;font-weight:600'>▼ {delta}</span>"
    return "<span style='color:#64748b'>0</span>"


def render_fleet_dashboard(reports: list[ScanReport]) -> str:
    """A single self-contained HTML dashboard summarizing every target in a fleet run."""
    fleet = _fleet_summary(reports)
    overall_score, overall_grade = _risk_score(fleet["counts"])
    grade_color = _GRADE_CSS.get(overall_grade, "#dc2626")
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    rows = ""
    for r in sorted(reports, key=lambda x: _risk_score(x.summary_counts())[0], reverse=True):
        counts = r.summary_counts()
        _, grade = _risk_score(counts)
        total = sum(counts.values())
        highest = r.highest_severity()
        highest_badge = _badge(highest) if highest else "<span style='color:#94a3b8'>—</span>"
        spark = _trend_sparkline_html(r) or "<span style='color:#94a3b8;font-size:.8rem'>no history</span>"

        def _cell(sev: Severity) -> str:
            n = counts.get(sev.value, 0)
            bg, fg, _ = _SEV_CSS[sev]
            return f"<span style='color:{fg if n else '#cbd5e1'};font-weight:{600 if n else 400}'>{n}</span>"

        rows += (
            f"<tr style='border-bottom:1px solid #e2e8f0'>"
            f"<td style='padding:10px 12px;font-weight:600'>{_e(r.target)}</td>"
            f"<td style='padding:10px 12px;text-align:center;font-weight:800;color:{_GRADE_CSS.get(grade, '#dc2626')}'>{grade}</td>"
            f"<td style='padding:10px 12px;text-align:center'>{highest_badge}</td>"
            f"<td style='padding:10px 12px;text-align:center'>{_cell(Severity.CRITICAL)}</td>"
            f"<td style='padding:10px 12px;text-align:center'>{_cell(Severity.HIGH)}</td>"
            f"<td style='padding:10px 12px;text-align:center'>{_cell(Severity.MEDIUM)}</td>"
            f"<td style='padding:10px 12px;text-align:center'>{_cell(Severity.LOW)}</td>"
            f"<td style='padding:10px 12px;text-align:center;font-weight:600'>{total}</td>"
            f"<td style='padding:10px 12px;text-align:center'>{_last_scan_delta_html(r)}</td>"
            f"<td style='padding:10px 12px'>{spark}</td>"
            f"</tr>\n"
        )

    head = (
        "<th style='padding:10px 12px;text-align:left'>Target</th>"
        "<th style='padding:10px 12px'>Grade</th>"
        "<th style='padding:10px 12px'>Highest</th>"
        "<th style='padding:10px 12px'>C</th><th style='padding:10px 12px'>H</th>"
        "<th style='padding:10px 12px'>M</th><th style='padding:10px 12px'>L</th>"
        "<th style='padding:10px 12px'>Total</th>"
        "<th style='padding:10px 12px'>&Delta; last</th>"
        "<th style='padding:10px 12px;text-align:left'>Trend</th>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Inquisition Fleet Dashboard</title>
</head>
<body style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;color:#1e293b">
<header style="background:#0f172a;color:#fff;padding:24px">
  <div style="max-width:1100px;margin:0 auto;display:flex;justify-content:space-between;align-items:center">
    <div>
      <div style="font-size:1.4rem;font-weight:800">Inquisition Fleet Dashboard</div>
      <div style="font-size:.85rem;color:#cbd5e1">{fleet['target_count']} target(s) · {fleet['total_findings']} total finding(s) · generated {generated}</div>
    </div>
    <div style="text-align:center">
      <div style="font-size:.7rem;color:#94a3b8;text-transform:uppercase">Fleet grade</div>
      <div style="font-size:2rem;font-weight:800;color:{grade_color}">{overall_grade}</div>
    </div>
  </div>
</header>
<main style="max-width:1100px;margin:0 auto;padding:32px 24px">
  <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden">
    <thead style="background:#f1f5f9;font-size:.8rem;color:#475569;text-align:center">
      <tr>{head}</tr>
    </thead>
    <tbody>
{rows}    </tbody>
  </table>
  <p style="margin-top:16px;font-size:.8rem;color:#94a3b8">
    Sorted by risk score (highest first). Trend sparkline shows total findings across each target's recent scans.
  </p>
</main>
</body>
</html>"""


def render_combined(reports: list[ScanReport], fmt: ReportFormat, *, brief: bool = False) -> str:
    """Render several reports into a single combined artifact.

    JSON and SARIF produce structured merges (a fleet object / multi-run SARIF).
    HTML produces a fleet dashboard; text is concatenated with a per-target separator.
    """
    if fmt == ReportFormat.JSON:
        return render_json_combined(reports)
    if fmt == ReportFormat.SARIF:
        return render_sarif_combined(reports)
    if fmt == ReportFormat.HTML:
        return render_fleet_dashboard(reports)
    banner = "\n\n" + _hr("#") + "\n"
    return banner.join(
        f"  FLEET REPORT {idx}/{len(reports)} — {r.target}\n{render_text(r, brief=brief)}"
        for idx, r in enumerate(reports, 1)
    )
