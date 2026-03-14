"""Report generation — text and JSON output."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from models import (
    Finding,
    FindingCategory,
    ReportFormat,
    ScanReport,
    Severity,
    TOOL_REFERENCE,
)
from vuln_correlation import tools_for_category
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
# Text report
# ---------------------------------------------------------------------------

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
            lines.append("  " + "\u2504" * (len(label) + 2))
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
            lines.append("  " + "\u2504" * (len(label) + 2))
            lines.extend(_wrap_paragraphs(remediation_text))
            if f.verification:
                lines.append(f"\n    Verification: {f.verification}")
            if f.references:
                lines.append(f"    References  : {', '.join(f.references)}")
            lines.append("")


def render_text(report: ScanReport) -> str:
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
    lines.append(f"  Total findings: {total}")
    for sev in _SEV_ORDER:
        count = counts.get(sev.value, 0)
        if count:
            lines.append(f"    {_SEVERITY_LABEL[sev]:<10s}: {count}")
    lines.append(f"  CVEs correlated  : {len(report.cve_records)}")
    lines.append(f"  Misconfigurations: {len(report.misconfigurations)}")
    if report.errors:
        lines.append(f"  Scan errors      : {len(report.errors)}")
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
            lines.append(f"    Evidence : {f.evidence}")
            if f.impact:
                lines.append(f"    Impact   : {f.impact}")
            if f.remediation:
                lines.append(f"    Fix      : {f.remediation}")
            if f.verification:
                lines.append(f"    Verify   : {f.verification}")
            if f.cpe:
                lines.append(f"    CPE      : {f.cpe}")
            if f.references:
                lines.append(f"    Refs     : {', '.join(f.references)}")
            # Tool reference
            tools = tools_for_category(f.category)
            if tools:
                lines.append(f"    Tools    : {', '.join(tools)}")
            lines.append("")

    # --- Deep Issue Analysis ---
    _render_deep_analysis(lines, report)

    # --- Remediation Guide ---
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
    if f.references:
        d["references"] = f.references
    d["tools"] = tools_for_category(f.category)
    kb = analysis_kb.lookup(f.title)
    if kb:
        d["deep_analysis"] = kb["analysis"]
        d["deep_remediation"] = kb["remediation"]
    return d


def render_json(report: ScanReport) -> str:
    """Produce a JSON report."""
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
        "tool_reference": {cat.value: tools for cat, tools in TOOL_REFERENCE.items()},
        "errors": report.errors,
    }
    return json.dumps(data, indent=2)


def render(report: ScanReport, fmt: ReportFormat) -> str:
    if fmt == ReportFormat.JSON:
        return render_json(report)
    return render_text(report)
