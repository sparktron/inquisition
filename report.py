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
    cve_priority,
)
from vuln_correlation import tools_for_category
from diffing import compute_trend
import analysis_kb
import mitre
import attack_graph
import reachability

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

# "What Could Happen" consequence ladder — maps letter grade to real-world outcome language.
_CONSEQUENCE_LADDER: list[tuple[str, str, str]] = [
    # (grade, headline, detail)
    ("A+", "No material risk",
     "No actionable findings. Continue routine monitoring."),
    ("A",  "Minimal risk",
     "Minor configuration gaps. Low attacker value; schedule routine hardening."),
    ("B",  "Limited impact if exploited",
     "Information leakage or minor disruption likely. An opportunistic attacker gains reconnaissance advantage."),
    ("C",  "Credential theft or data exposure likely",
     "A motivated attacker can intercept sessions, steal credentials, or access sensitive data without advanced tools."),
    ("D",  "Account takeover or significant breach probable",
     "Active exploitation is straightforward. Expect lateral movement, data exfiltration, or service disruption if targeted."),
    ("F",  "Full system compromise and mass data exfiltration",
     "Critical exposures present that require no credentials to exploit. Ransomware, backdoor installation, and supply-chain attacks are viable immediately."),
]

_MITRE_BASE_URL = "https://attack.mitre.org/techniques/"


def _mitre_url(technique_id: str) -> str:
    """Return the MITRE ATT&CK URL for a technique ID like T1557 or T1557.002."""
    base = technique_id.replace(".", "/")
    return f"{_MITRE_BASE_URL}{base}/"


def _exploitability_key(f: Finding) -> tuple[int, int, int]:
    """Sort key for attacker-POV ordering: most exploitable first.

    Primary: severity (lower index = more severe).
    Secondary: findings with a PoC command rank higher (attacker already has a tool).
    Tertiary: findings with MITRE tags rank higher (known attack path).
    """
    return (
        _SEV_ORDER.index(f.severity),
        0 if f.poc_command else 1,
        0 if f.mitre_techniques else 1,
    )


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

# User-facing graded risk score, tuned to map onto _GRADE_THRESHOLDS below.
# Distinct from ``diffing._SEVERITY_WEIGHT`` (an internal trend-direction signal);
# both are kept monotonic in severity so a worsening trend never shows a better
# grade. See the note in diffing.py for why they are not shared.
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
            attack_scenario = f.attack_scenario or (kb.get("attack_scenario", "") if kb else "")
            mitre_ids = f.mitre_techniques or (kb.get("mitre_techniques", []) if kb else [])
            poc = f.poc_command or (kb.get("poc_command", "") if kb else "")

            if not analysis_text and not attack_scenario:
                continue

            label = f"[{_SEVERITY_LABEL[f.severity]}] {f.title}"
            lines.append(f"\n  {label}")
            lines.append("  " + "-" * (len(label) + 2))
            if analysis_text:
                lines.extend(_wrap_paragraphs(analysis_text))
            if attack_scenario:
                lines.append("")
                lines.append("    HOW AN ATTACKER EXPLOITS THIS:")
                lines.extend(_wrap_paragraphs(attack_scenario))
            if mitre_ids:
                lines.append(f"\n    MITRE ATT&CK: {', '.join(mitre_ids)}")
            if poc:
                lines.append("\n    ATTACKER'S COMMAND:")
                for poc_line in poc.split("\n"):
                    lines.append(f"      {poc_line}")
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

            kb = analysis_kb.lookup(f.title)
            poc = f.poc_command or (kb.get("poc_command", "") if kb else "")
            label = f"[{_SEVERITY_LABEL[f.severity]}] {f.title}"
            lines.append(f"  {label}")
            lines.append("  " + "-" * (len(label) + 2))
            lines.extend(_wrap_paragraphs(remediation_text))
            if poc:
                lines.append("\n    VERIFY THE FIX (run after remediation — should now fail/return 403):")
                for poc_line in poc.split("\n"):
                    lines.append(f"      {poc_line}")
            if f.verification:
                lines.append(f"\n    Verification: {f.verification}")
            if f.references:
                lines.append(f"    References  : {', '.join(f.references)}")
            lines.append("")


def render_text(report: ScanReport, *, brief: bool = False, attacker_pov: bool = False) -> str:
    """Produce a human-readable text report."""
    lines: list[str] = []

    pov = attacker_pov or bool(report.config and report.config.attacker_pov)

    # --- Banner ---
    lines.append(_hr("#"))
    title = "  INQUISITION — Attacker's View Report" if pov else "  INQUISITION — Security Reconnaissance Report"
    lines.append(title)
    lines.append(_hr("#"))
    lines.append(f"  Target   : {report.target}")
    lines.append(f"  Started  : {report.started_at:%Y-%m-%d %H:%M:%S UTC}")
    if report.finished_at:
        duration = (report.finished_at - report.started_at).total_seconds()
        lines.append(f"  Finished : {report.finished_at:%Y-%m-%d %H:%M:%S UTC} ({duration:.1f}s)")
    if report.config:
        lines.append(f"  Depth    : {report.config.depth.value}")
        lines.append(f"  Mode     : {'dry-run' if report.config.dry_run else 'safe' if report.config.safe_mode else 'standard'}")
    if pov:
        lines.append("  View     : ATTACKER POV — findings ordered by exploitability")
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
    exposure = reachability.exposure_index(report)
    lines.append(f"\n  Risk score : {score}  |  Security grade : {grade}  |  Exposure index : {exposure}/100")
    lines.append("")

    # --- What Could Happen (consequence ladder) ---
    lines.append(_section("WHAT COULD HAPPEN — CONSEQUENCE ASSESSMENT"))
    for g, headline, detail in _CONSEQUENCE_LADDER:
        marker = ">>>" if g == grade else "   "
        lines.append(f"  {marker} Grade {g:<3s}  {headline}")
        if g == grade:
            lines.append(f"           {detail}")
    lines.append("")

    # --- Executive Attack Story ---
    story = attack_graph.attack_story(report)
    if story:
        lines.append(_section("EXECUTIVE ATTACK STORY"))
        lines.extend(_wrap_paragraphs(story, indent="  "))
        lines.append("")

    # --- Remediation Priority Matrix ---
    lines.append(_section("REMEDIATION PRIORITY MATRIX"))
    actionable = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    sort_key = _exploitability_key if pov else lambda x: (_SEV_ORDER.index(x.severity), 0, 0)
    if actionable:
        lines.append(f"  {'#':<4s} {'Severity':<10s} {'Category':<16s} {'Title'}")
        lines.append(f"  {'-'*4} {'-'*10} {'-'*16} {'-'*38}")
        for idx, f in enumerate(sorted(actionable, key=sort_key), 1):
            poc_flag = " [PoC]" if f.poc_command else ""
            lines.append(f"  {idx:<4d} {_SEVERITY_LABEL[f.severity]:<10s} {f.category.value:<16s} {f.title}{poc_flag}")
    else:
        lines.append("  No actionable findings.")
    lines.append("")

    # --- Detailed Findings ---
    header = "DETAILED FINDINGS — ATTACKER POV (easiest to exploit first)" if pov else "DETAILED FINDINGS"
    lines.append(_section(header))
    findings_ordered = sorted(report.findings, key=_exploitability_key) if pov else report.findings
    for sev in _SEV_ORDER:
        group = [f for f in findings_ordered if f.severity == sev]
        if not group:
            continue
        lines.append(f"\n  --- {_SEVERITY_LABEL[sev]} ({len(group)}) ---\n")
        for f in group:
            lines.append(f"  [{_SEVERITY_LABEL[f.severity]}] {f.title}")
            lines.append(f"    Category : {f.category.value}")
            if f.confidence is not Confidence.CONFIRMED:
                lines.append(f"    Confidence: {f.confidence.value}")
            lines.append(f"    Evidence : {f.evidence}")
            if f.mitre_techniques:
                links = [f"{t} ({_mitre_url(t)})" for t in f.mitre_techniques]
                lines.append(f"    MITRE    : {', '.join(links)}")
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
            tools = tools_for_category(f.category)
            if tools:
                lines.append(f"    Tools    : {', '.join(tools)}")
            if pov and f.poc_command:
                lines.append("    PoC cmd  :")
                for poc_line in f.poc_command.split("\n"):
                    lines.append(f"      {poc_line}")
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
        lines.append("  Ranked by real-world exploitation risk (KEV > public exploit > EPSS > CVSS)\n")
        for cve in sorted(report.cve_records, key=cve_priority, reverse=True):
            kev_flag = " [CISA KEV — ACTIVELY EXPLOITED]" if cve.in_cisa_kev else ""
            age_str = f"  disclosed {cve.days_since_disclosure}d ago" if cve.days_since_disclosure else ""
            lines.append(f"  {cve.cve_id}  (CVSS {cve.cvss_score:.1f} / {_SEVERITY_LABEL[cve.severity]}){kev_flag}{age_str}")
            lines.append(f"    {cve.description[:200]}")
            if cve.epss_score:
                lines.append(
                    f"    EPSS     : {cve.epss_score:.1%} probability "
                    f"(top {(1 - cve.epss_percentile):.1%} of all CVEs)"
                )
            if cve.exploit_public:
                lines.append(f"    Exploit  : PUBLIC — {', '.join(cve.exploit_sources)}")
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
            if mc.mitre_techniques:
                lines.append(f"    MITRE     : {', '.join(mc.mitre_techniques)}")
            if mc.attack_scenario:
                lines.append("    Attack    :")
                lines.extend(_wrap_paragraphs(mc.attack_scenario))
            lines.append("")

    # --- Attack Chains ---
    if report.attack_chains:
        lines.append(_section("ATTACK CHAIN ANALYSIS"))
        lines.append(
            "  The following multi-step kill chains are possible given the combination\n"
            "  of findings present. Each chain represents a realistic attacker workflow."
        )
        for chain in report.attack_chains:
            lines.append(f"\n  CHAIN: {chain.name}")
            lines.append(f"  {'-' * (len(chain.name) + 7)}")
            lines.append(f"    {chain.description}")
            lines.append("")
            for i, step in enumerate(chain.steps, 1):
                lines.append(f"    Step {i}: {step}")
            if chain.mitre_techniques:
                lines.append(f"\n    MITRE: {', '.join(chain.mitre_techniques)}")
            lines.append("")

    # --- Attack Graph (reachable objectives) ---
    graph = attack_graph.build_attack_graph(report)
    if not graph.empty:
        lines.append(_section("ATTACK GRAPH — REACHABLE OBJECTIVES"))
        lines.append(
            "  Objectives an attacker can reach by chaining the findings below, worst\n"
            "  first. Each path is the shortest route from an external position.\n"
        )
        lines.extend(attack_graph.summary_lines(graph))
        lines.append("")

    # --- MITRE ATT&CK Coverage ---
    hits = mitre.coverage(report)
    if hits:
        lines.append(_section("MITRE ATT&CK COVERAGE"))
        lines.append(
            "  Attacker techniques mapped from this scan's findings, grouped by tactic.\n"
        )
        current_tactic = ""
        for hit in hits:
            if hit.tactic != current_tactic:
                current_tactic = hit.tactic
                lines.append(f"  {current_tactic}")
            lines.append(f"    {hit.technique_id:<12s} {hit.name}  (x{hit.count})")
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
# Markdown report
# ---------------------------------------------------------------------------

def _md_cell(text: str) -> str:
    """Escape a value for safe inclusion in a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: ScanReport, *, brief: bool = False, attacker_pov: bool = False) -> str:
    """Produce a GitHub-flavored Markdown report.

    Mirrors render_text's structure with real Markdown headings, tables, and
    inline code so it renders cleanly in PRs, issues, and Markdown viewers.
    """
    out: list[str] = []
    pov = attacker_pov or bool(report.config and report.config.attacker_pov)

    # --- Banner / metadata ---
    title = "Inquisition — Attacker's View Report" if pov else "Inquisition — Security Reconnaissance Report"
    out.append(f"# {title}")
    out.append("")
    out.append(f"- **Target:** `{report.target}`")
    out.append(f"- **Started:** {report.started_at:%Y-%m-%d %H:%M:%S UTC}")
    if report.finished_at:
        duration = (report.finished_at - report.started_at).total_seconds()
        out.append(f"- **Finished:** {report.finished_at:%Y-%m-%d %H:%M:%S UTC} ({duration:.1f}s)")
    if report.config:
        mode = "dry-run" if report.config.dry_run else "safe" if report.config.safe_mode else "standard"
        out.append(f"- **Depth:** {report.config.depth.value}")
        out.append(f"- **Mode:** {mode}")
    if pov:
        out.append("- **View:** Attacker POV — ordered by exploitability")
    out.append("")

    # --- Executive Summary ---
    out.append("## Executive Summary")
    out.append("")
    counts = report.summary_counts()
    total = sum(counts.values())
    score, grade = _risk_score(counts)
    out.append(
        f"**Total findings: {total}** — risk score **{score}**, security grade **{grade}**, "
        f"exposure index **{reachability.exposure_index(report)}/100**"
    )
    out.append("")
    out.append("| Severity | Count |")
    out.append("| --- | --- |")
    for sev in _SEV_ORDER:
        count = counts.get(sev.value, 0)
        if count:
            out.append(f"| {_SEVERITY_LABEL[sev]} | {count} |")
    out.append(f"| CVEs correlated | {len(report.cve_records)} |")
    out.append(f"| Misconfigurations | {len(report.misconfigurations)} |")
    if report.errors:
        out.append(f"| Scan errors | {len(report.errors)} |")
    out.append("")

    # --- What Could Happen ---
    out.append("## What Could Happen — Consequence Assessment")
    out.append("")
    out.append("| Grade | Headline | Detail |")
    out.append("| --- | --- | --- |")
    for g, headline, detail in _CONSEQUENCE_LADDER:
        marker = f"**{g}** ◀ current" if g == grade else g
        out.append(f"| {marker} | {headline} | {_md_cell(detail)} |")
    out.append("")

    # --- Remediation Priority Matrix ---
    out.append("## Remediation Priority Matrix")
    out.append("")
    actionable = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    sort_key = _exploitability_key if pov else lambda x: (_SEV_ORDER.index(x.severity), 0, 0)
    if actionable:
        poc_col = " PoC |" if pov else ""
        out.append(f"| # | Severity | Category | Title |{poc_col}")
        out.append(f"| --- | --- | --- | --- |{'--- |' if pov else ''}")
        for idx, f in enumerate(sorted(actionable, key=sort_key), 1):
            poc_flag = "✓" if f.poc_command else ""
            row = f"| {idx} | {_SEVERITY_LABEL[f.severity]} | {_md_cell(f.category.value)} | {_md_cell(f.title)} |"
            if pov:
                row += f" {poc_flag} |"
            out.append(row)
    else:
        out.append("_No actionable findings._")
    out.append("")

    # --- Detailed Findings ---
    header = "Detailed Findings — Attacker POV" if pov else "Detailed Findings"
    out.append(f"## {header}")
    out.append("")
    any_findings = False
    findings_ordered = sorted(report.findings, key=_exploitability_key) if pov else report.findings
    for sev in _SEV_ORDER:
        group = [f for f in findings_ordered if f.severity == sev]
        if not group:
            continue
        any_findings = True
        out.append(f"### {_SEVERITY_LABEL[sev]} ({len(group)})")
        out.append("")
        for f in group:
            out.append(f"#### {f.title}")
            out.append("")
            out.append(f"- **Category:** {f.category.value}")
            if f.confidence is not Confidence.CONFIRMED:
                out.append(f"- **Confidence:** {f.confidence.value}")
            out.append(f"- **Evidence:** {f.evidence}")
            if f.mitre_techniques:
                links = ", ".join(f"[{t}]({_mitre_url(t)})" for t in f.mitre_techniques)
                out.append(f"- **MITRE ATT&CK:** {links}")
            if f.impact:
                out.append(f"- **Impact:** {f.impact}")
            if f.remediation:
                out.append(f"- **Fix:** {f.remediation}")
            if f.verification:
                out.append(f"- **Verify:** {f.verification}")
            if f.cpe:
                out.append(f"- **CPE:** `{f.cpe}`")
            if f.age_scans:
                out.append(f"- **Age:** {_age_phrase(f)}")
            if f.references:
                out.append(f"- **References:** {', '.join(f.references)}")
            tools = tools_for_category(f.category)
            if tools:
                out.append(f"- **Tools:** {', '.join(tools)}")
            if f.attack_scenario:
                out.append("")
                out.append(f"> **How an attacker exploits this:** {f.attack_scenario}")
            if f.poc_command:
                out.append("")
                out.append("```bash")
                out.append(f.poc_command)
                out.append("```")
            out.append("")
    if not any_findings:
        out.append("_No findings recorded._")
        out.append("")

    # --- Deep Issue Analysis ---
    if not brief:
        deep = [
            f for f in report.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        ]
        if deep:
            out.append("## Deep Issue Analysis")
            out.append("")
            for sev in _SEV_ORDER:
                for f in (x for x in deep if x.severity == sev):
                    kb = analysis_kb.lookup(f.title)
                    analysis_text = kb["analysis"] if kb else f.impact
                    if not analysis_text:
                        continue
                    out.append(f"### [{_SEVERITY_LABEL[f.severity]}] {f.title}")
                    out.append("")
                    out.append(analysis_text)
                    out.append("")
                    out.append(f"**Evidence:** {f.evidence}")
                    out.append("")

    # --- Remediation Guide ---
    if not brief:
        rem = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
        if rem:
            out.append("## Remediation Guide")
            out.append("")
            for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                group = [f for f in rem if f.severity == sev]
                if not group:
                    continue
                out.append(f"### {_SEVERITY_LABEL[sev]} priority")
                out.append("")
                for f in group:
                    kb = analysis_kb.lookup(f.title)
                    remediation_text = (kb["remediation"] if kb else f.remediation) or \
                        f.remediation or "No specific remediation guidance available."
                    poc = f.poc_command or (kb.get("poc_command", "") if kb else "")
                    out.append(f"#### {f.title}")
                    out.append("")
                    out.append(remediation_text)
                    out.append("")
                    if poc:
                        out.append("**Verify the fix (should now fail/return 403):**")
                        out.append("```bash")
                        out.append(poc)
                        out.append("```")
                        out.append("")
                    if f.verification:
                        out.append(f"**Verification:** {f.verification}")
                        out.append("")
                    if f.references:
                        out.append(f"**References:** {', '.join(f.references)}")
                        out.append("")

    # --- CVE Correlation ---
    if report.cve_records:
        out.append("## CVE Correlation")
        out.append("")
        out.append("_Ranked by real-world exploitation risk (KEV > public exploit > EPSS > CVSS)._")
        out.append("")
        out.append("| CVE ID | CVSS | EPSS | Severity | KEV | Exploit | Days Old | Description |")
        out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for cve in sorted(report.cve_records, key=cve_priority, reverse=True):
            kev = "⚠️ **KEV**" if cve.in_cisa_kev else "—"
            epss = f"{cve.epss_score:.0%}" if cve.epss_score else "—"
            exploit = f"**{', '.join(cve.exploit_sources)}**" if cve.exploit_public else "—"
            age = f"{cve.days_since_disclosure}d" if cve.days_since_disclosure else "—"
            out.append(
                f"| {cve.cve_id} | {cve.cvss_score:.1f} | {epss} | {_SEVERITY_LABEL[cve.severity]} "
                f"| {kev} | {exploit} | {age} | {_md_cell(cve.description[:120])} |"
            )
        out.append("")

    # --- Misconfiguration Summary ---
    if report.misconfigurations:
        out.append("## Misconfiguration Summary")
        out.append("")
        for mc in sorted(report.misconfigurations, key=lambda m: _SEV_ORDER.index(m.severity)):
            out.append(f"### [{_SEVERITY_LABEL[mc.severity]}] {mc.name}")
            out.append("")
            out.append(mc.description)
            out.append("")
            out.append(f"- **Evidence:** {mc.evidence}")
            out.append(f"- **Remediate:** {mc.remediation}")
            if mc.mitre_techniques:
                links = ", ".join(f"[{t}]({_mitre_url(t)})" for t in mc.mitre_techniques)
                out.append(f"- **MITRE ATT&CK:** {links}")
            if mc.attack_scenario:
                out.append(f"- **Attack scenario:** {mc.attack_scenario}")
            if mc.poc_command:
                out.append("")
                out.append("```bash")
                out.append(mc.poc_command)
                out.append("```")
            out.append("")

    # --- Attack Chains ---
    if report.attack_chains:
        out.append("## Attack Chain Analysis")
        out.append("")
        out.append("The following multi-step kill chains are possible given the combination of findings present.")
        out.append("")
        for chain in report.attack_chains:
            out.append(f"### {chain.name}")
            out.append("")
            out.append(f"> {chain.description}")
            out.append("")
            for i, step in enumerate(chain.steps, 1):
                out.append(f"{i}. {step}")
            out.append("")
            if chain.mitre_techniques:
                links = ", ".join(f"[{t}]({_mitre_url(t)})" for t in chain.mitre_techniques)
                out.append(f"**MITRE ATT&CK:** {links}")
                out.append("")

    # --- Tool Reference Table ---
    out.append("## Tool Reference Table")
    out.append("")
    out.append("| Category | Recommended tools |")
    out.append("| --- | --- |")
    for cat in FindingCategory:
        tools = TOOL_REFERENCE.get(cat, [])
        if tools:
            out.append(f"| {_md_cell(cat.value)} | {_md_cell(', '.join(tools))} |")
    out.append("")

    # --- Errors ---
    if report.errors:
        out.append("## Scan Errors")
        out.append("")
        for err in report.errors:
            out.append(f"- {err}")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


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
        "exposure_index": reachability.exposure_index(report),
        "findings": [_finding_to_dict(f) for f in report.findings],
        "cve_records": [
            {
                "cve_id": c.cve_id,
                "description": c.description,
                "severity": c.severity.value,
                "cvss_score": c.cvss_score,
                "epss_score": c.epss_score,
                "epss_percentile": c.epss_percentile,
                "in_cisa_kev": c.in_cisa_kev,
                "exploit_public": c.exploit_public,
                "exploit_sources": c.exploit_sources,
                "references": c.references,
            }
            for c in sorted(report.cve_records, key=cve_priority, reverse=True)
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


def _attack_chain_svg(chain_steps: list[str]) -> str:
    """Render an attack chain as a simple inline SVG flowchart."""
    box_w, box_h, gap = 220, 44, 28
    total_h = len(chain_steps) * (box_h + gap) - gap + 20
    total_w = box_w + 40
    svg_lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{total_h}" '
        f'viewBox="0 0 {total_w} {total_h}" role="img" aria-label="attack chain flowchart">'
    ]
    for i, step in enumerate(chain_steps):
        y = i * (box_h + gap) + 10
        cx = total_w / 2
        text = step[:38] + ("…" if len(step) > 38 else "")
        color = "#dc2626" if i == 0 else "#ea580c" if i == 1 else "#ca8a04" if i < len(chain_steps) - 1 else "#7c3aed"
        svg_lines.append(
            f'<rect x="{cx - box_w/2:.0f}" y="{y}" width="{box_w}" height="{box_h}" rx="6" '
            f'fill="{color}18" stroke="{color}" stroke-width="1.5"/>'
            f'<text x="{cx:.0f}" y="{y + box_h/2 + 5:.0f}" text-anchor="middle" '
            f'font-family="system-ui,sans-serif" font-size="11" fill="{color}" font-weight="600">'
            f'<tspan x="{cx:.0f}">{_e(f"Step {i+1}: {text}")}</tspan></text>'
        )
        if i < len(chain_steps) - 1:
            arrow_y = y + box_h
            svg_lines.append(
                f'<line x1="{cx:.0f}" y1="{arrow_y}" x2="{cx:.0f}" y2="{arrow_y + gap}" '
                f'stroke="#94a3b8" stroke-width="1.5" marker-end="url(#arr)"/>'
            )
    # Arrow marker definition
    svg_lines.insert(1,
        '<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto">'
        '<path d="M0,0 L8,4 L0,8 Z" fill="#94a3b8"/></marker></defs>'
    )
    svg_lines.append("</svg>")
    return "\n".join(svg_lines)


def render_html(report: ScanReport, *, attacker_pov: bool = False) -> str:
    """Produce a self-contained HTML security report."""
    pov = attacker_pov or bool(report.config and report.config.attacker_pov)
    counts = report.summary_counts()
    score, grade = _risk_score(counts)
    exposure_idx = reachability.exposure_index(report)
    story = attack_graph.attack_story(report)
    story_callout = (
        f'<div style="background:#fef2f2;border-left:4px solid #dc2626;border-radius:6px;'
        f'padding:14px 16px;margin-top:16px">'
        f'<div style="font-size:.75rem;font-weight:700;color:#b91c1c;text-transform:uppercase;'
        f'letter-spacing:.06em;margin-bottom:6px">&#128520; Executive Attack Story</div>'
        f'<div style="font-size:.92rem;color:#7f1d1d;line-height:1.6">{_e(story)}</div></div>'
        if story else ""
    )
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

    # ---- consequence ladder ----
    consequence_rows = ""
    for g, headline, detail in _CONSEQUENCE_LADDER:
        is_current = g == grade
        bg = "#fef2f2" if is_current and grade in ("D", "F") else \
             "#fffbeb" if is_current and grade in ("B", "C") else \
             "#f0fdf4" if is_current and grade in ("A+", "A") else \
             "#f8fafc"
        border_left = f"4px solid {_GRADE_CSS.get(g, '#64748b')}" if is_current else "4px solid transparent"
        badge_color = _GRADE_CSS.get(g, "#64748b")
        current_label = " ← YOUR SITE" if is_current else ""
        consequence_rows += (
            f"<tr style='background:{bg};border-left:{border_left}'>"
            f"<td style='padding:8px 12px;font-weight:800;color:{badge_color};white-space:nowrap'>"
            f"{_e(g)}{_e(current_label)}</td>"
            f"<td style='padding:8px 12px;font-weight:600'>{_e(headline)}</td>"
            f"<td style='padding:8px 12px;font-size:.9rem;color:#475569'>{_e(detail)}</td>"
            f"</tr>\n"
        )

    # ---- priority matrix rows ----
    actionable = [
        f for f in report.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    sort_key = _exploitability_key if pov else lambda x: (_SEV_ORDER.index(x.severity), 0, 0)
    matrix_rows = ""
    for idx, f in enumerate(sorted(actionable, key=sort_key), 1):
        poc_cell = "<td style='padding:6px 10px;color:#16a34a;font-weight:700'>✓</td>" if f.poc_command else "<td style='padding:6px 10px;color:#cbd5e1'>—</td>"
        matrix_rows += (
            f"<tr>"
            f"<td style='padding:6px 10px;color:#64748b'>{idx}</td>"
            f"<td style='padding:6px 10px'>{_badge(f.severity)}</td>"
            f"<td style='padding:6px 10px;color:#64748b;font-size:.85rem'>{_e(f.category.value)}</td>"
            f"<td style='padding:6px 10px;font-weight:500'>{_e(f.title)}</td>"
            f"{poc_cell}"
            f"</tr>\n"
        )

    # ---- finding cards ----
    finding_cards = ""
    findings_ordered = sorted(report.findings, key=_exploitability_key) if pov else report.findings
    for sev in _SEV_ORDER:
        group = [f for f in findings_ordered if f.severity == sev]
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
            mitre_ids = f.mitre_techniques or (kb.get("mitre_techniques", []) if kb else [])
            attack_scenario = f.attack_scenario or (kb.get("attack_scenario", "") if kb else "")
            poc = f.poc_command or (kb.get("poc_command", "") if kb else "")

            rows = f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Category</td><td>{_e(f.category.value)}</td></tr>\n"
            if f.confidence is not Confidence.CONFIRMED:
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Confidence</td><td>{_e(f.confidence.value)}</td></tr>\n"
            rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Evidence</td><td><code style='font-size:.85rem;background:#f1f5f9;padding:1px 4px;border-radius:3px'>{_e(f.evidence)}</code></td></tr>\n"
            if mitre_ids:
                mitre_links = " ".join(
                    f'<a href="{_e(_mitre_url(t))}" target="_blank" rel="noopener" '
                    f'style="display:inline-block;margin:0 2px 2px 0;padding:1px 6px;border-radius:3px;'
                    f'background:#dbeafe;color:#1d4ed8;font-size:.78rem;font-weight:600;text-decoration:none">{_e(t)}</a>'
                    for t in mitre_ids
                )
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>MITRE</td><td>{mitre_links}</td></tr>\n"
            if f.preconditions:
                effort = reachability.feasibility_label(reachability.feasibility(f))
                rows += (
                    f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Preconditions</td>"
                    f"<td>{_e('; '.join(f.preconditions))} "
                    f"<span style='color:#94a3b8;font-size:.78rem'>({effort} for attacker)</span></td></tr>\n"
                )
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
                attack_html = ""
                if attack_scenario:
                    attack_html = (
                        f'<details style="margin-top:8px">'
                        f'<summary style="cursor:pointer;font-weight:600;color:#7c3aed;padding:4px 0">'
                        f'&#128373; How an Attacker Exploits This</summary>'
                        f'<div style="margin-top:8px;padding:12px;background:#faf5ff;border-radius:6px;'
                        f'border-left:3px solid #7c3aed;font-size:.9rem;line-height:1.7;font-family:inherit">'
                        f'{_nl2br(attack_scenario)}</div></details>'
                    )
                poc_html = ""
                if poc:
                    poc_html = (
                        f'<details style="margin-top:8px">'
                        f'<summary style="cursor:pointer;font-weight:600;color:#dc2626;padding:4px 0">'
                        f'&#128192; Attacker\'s Command (PoC)</summary>'
                        f'<pre style="margin-top:8px;padding:12px;background:#1e293b;color:#f8fafc;'
                        f'border-radius:6px;font-size:.82rem;line-height:1.6;overflow-x:auto;'
                        f'white-space:pre-wrap;font-family:\'SF Mono\',\'Fira Code\',monospace">'
                        f'{_e(poc)}</pre></details>'
                    )
                analysis_section = (
                    f'<details style="margin-top:12px">'
                    f'<summary style="cursor:pointer;font-weight:600;color:#1e293b;padding:4px 0">'
                    f'&#128269; Issue Analysis</summary>'
                    f'<div style="margin-top:8px;padding:12px;background:#f8fafc;border-radius:6px;'
                    f'font-size:.9rem;line-height:1.7;white-space:pre-wrap;font-family:inherit">'
                    f'{_e(kb["analysis"])}</div></details>'
                    f'{attack_html}'
                    f'<details style="margin-top:8px">'
                    f'<summary style="cursor:pointer;font-weight:600;color:#1e293b;padding:4px 0">'
                    f'&#128295; Remediation Steps</summary>'
                    f'<div style="margin-top:8px;padding:12px;background:#f0fdf4;border-radius:6px;'
                    f'font-size:.9rem;line-height:1.7;white-space:pre-wrap;font-family:inherit">'
                    f'{_e(kb["remediation"])}</div></details>'
                    f'{poc_html}'
                )

            tactics = sorted({mitre.technique_tactic(t) for t in mitre.techniques_for_finding(f)})
            finding_cards += (
                f'<div class="finding-card" data-severity="{f.severity.value}" '
                f'data-category="{f.category.value}" data-confidence="{f.confidence.value}" '
                f'data-tactics="{_e("|".join(tactics))}" '
                f'style="margin-bottom:16px;border:1px solid {border};border-radius:8px;'
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

    # ---- interactive findings filter bar (C4) ----
    findings_filter = ""
    if finding_cards:
        cats = sorted({f.category.value for f in report.findings})
        tactics_all = sorted({
            mitre.technique_tactic(t)
            for f in report.findings for t in mitre.techniques_for_finding(f)
        })
        confs = sorted({f.confidence.value for f in report.findings})

        def _opts(values: list[str]) -> str:
            return "".join(f'<option value="{_e(v)}">{_e(v)}</option>' for v in values)

        _sel = ("padding:5px 8px;border:1px solid #cbd5e1;border-radius:6px;"
                "font-size:.85rem;background:#fff;color:#1e293b")
        findings_filter = (
            f'<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:16px">'
            f'<input id="flt-search" type="search" placeholder="Filter findings…" '
            f'style="{_sel};flex:1 1 200px">'
            f'<select id="flt-severity" style="{_sel}"><option value="">All severities</option>'
            f'{_opts([s.value for s in _SEV_ORDER])}</select>'
            f'<select id="flt-category" style="{_sel}"><option value="">All categories</option>{_opts(cats)}</select>'
            f'<select id="flt-tactic" style="{_sel}"><option value="">All tactics</option>{_opts(tactics_all)}</select>'
            f'<select id="flt-confidence" style="{_sel}"><option value="">All confidence</option>{_opts(confs)}</select>'
            f'<span id="flt-count" style="font-size:.82rem;color:#64748b;white-space:nowrap"></span>'
            f'</div>'
        )

    findings_filter_js = (
        '<script>(function(){'
        'var s=document.getElementById("flt-search");'
        'if(!s)return;'
        'var sev=document.getElementById("flt-severity"),cat=document.getElementById("flt-category"),'
        'tac=document.getElementById("flt-tactic"),conf=document.getElementById("flt-confidence"),'
        'count=document.getElementById("flt-count");'
        'var cards=Array.prototype.slice.call(document.querySelectorAll(".finding-card"));'
        'function apply(){var q=s.value.toLowerCase(),shown=0;cards.forEach(function(c){'
        'var ok=(!sev.value||c.dataset.severity===sev.value)'
        '&&(!cat.value||c.dataset.category===cat.value)'
        '&&(!conf.value||c.dataset.confidence===conf.value)'
        '&&(!tac.value||(c.dataset.tactics||"").split("|").indexOf(tac.value)>-1)'
        '&&(!q||c.textContent.toLowerCase().indexOf(q)>-1);'
        'c.style.display=ok?"":"none";if(ok)shown++;});'
        'count.textContent=shown+" / "+cards.length+" shown";}'
        '[s,sev,cat,tac,conf].forEach(function(el){el.addEventListener("input",apply);'
        'el.addEventListener("change",apply);});apply();})();</script>'
    )

    # ---- CVE rows ----
    cve_rows = ""
    for cve in sorted(report.cve_records, key=cve_priority, reverse=True):
        bg, fg, border = _SEV_CSS[cve.severity]
        refs_html = ""
        if cve.references:
            refs_html = " ".join(
                f'<a href="{_e(r)}" style="color:#2563eb;font-size:.8rem" target="_blank" rel="noopener">[ref]</a>'
                for r in cve.references[:3]
            )
        kev_badge = (
            '<span style="display:inline-block;padding:1px 6px;border-radius:3px;'
            'background:#fef2f2;color:#dc2626;font-size:.75rem;font-weight:700;'
            'border:1px solid #fca5a5">⚠ KEV</span>'
            if cve.in_cisa_kev else ""
        )
        age_str = (
            f'<span style="font-size:.8rem;color:#64748b">{cve.days_since_disclosure}d ago</span>'
            if cve.days_since_disclosure else ""
        )
        epss_html = (
            f'<span style="font-weight:600">{cve.epss_score:.0%}</span> '
            f'<span style="font-size:.75rem;color:#64748b">EPSS</span>'
            if cve.epss_score else '<span style="color:#94a3b8">—</span>'
        )
        exploit_html = (
            '<br><span style="display:inline-block;margin-top:2px;padding:1px 6px;border-radius:3px;'
            'background:#fff7ed;color:#c2410c;font-size:.72rem;font-weight:700;border:1px solid #fdba74" '
            f'title="{_e(", ".join(cve.exploit_sources))}">EXPLOIT</span>'
            if cve.exploit_public else ""
        )
        cve_rows += (
            f"<tr style='border-bottom:1px solid #e2e8f0'>"
            f"<td style='padding:8px 10px;font-weight:600;white-space:nowrap'>{_e(cve.cve_id)}</td>"
            f"<td style='padding:8px 10px'>{_badge(cve.severity)} {cve.cvss_score:.1f}</td>"
            f"<td style='padding:8px 10px'>{epss_html}{exploit_html}</td>"
            f"<td style='padding:8px 10px'>{kev_badge} {age_str}</td>"
            f"<td style='padding:8px 10px;font-size:.9rem'>{_e(cve.description[:200])}</td>"
            f"<td style='padding:8px 10px'>{refs_html}</td>"
            f"</tr>\n"
        )

    # ---- misconfiguration rows / cards ----
    mc_rows = ""
    for mc in sorted(report.misconfigurations, key=lambda m: _SEV_ORDER.index(m.severity)):
        mitre_tags = ""
        if mc.mitre_techniques:
            mitre_tags = " ".join(
                f'<a href="{_e(_mitre_url(t))}" target="_blank" rel="noopener" '
                f'style="display:inline-block;margin:0 2px;padding:1px 6px;border-radius:3px;'
                f'background:#dbeafe;color:#1d4ed8;font-size:.75rem;font-weight:600;text-decoration:none">{_e(t)}</a>'
                for t in mc.mitre_techniques
            )
        scenario_html = ""
        if mc.attack_scenario:
            scenario_html = (
                f'<details style="margin-top:6px">'
                f'<summary style="cursor:pointer;font-size:.85rem;color:#7c3aed;font-weight:600">&#128373; Attack scenario</summary>'
                f'<div style="margin-top:6px;padding:8px 12px;background:#faf5ff;border-radius:6px;'
                f'font-size:.85rem;line-height:1.6">{_nl2br(mc.attack_scenario)}</div></details>'
            )
        poc_html = ""
        if mc.poc_command:
            poc_html = (
                f'<details style="margin-top:6px">'
                f'<summary style="cursor:pointer;font-size:.85rem;color:#dc2626;font-weight:600">&#128192; PoC command</summary>'
                f'<pre style="margin-top:6px;padding:10px;background:#1e293b;color:#f8fafc;border-radius:6px;'
                f'font-size:.8rem;overflow-x:auto;white-space:pre-wrap;font-family:\'SF Mono\',monospace">'
                f'{_e(mc.poc_command)}</pre></details>'
            )
        mc_rows += (
            f"<tr style='border-bottom:1px solid #e2e8f0;vertical-align:top'>"
            f"<td style='padding:8px 10px'>{_badge(mc.severity)}</td>"
            f"<td style='padding:8px 10px;font-weight:500'>{_e(mc.name)}</td>"
            f"<td style='padding:8px 10px;font-size:.9rem'>{_e(mc.description)}</td>"
            f"<td style='padding:8px 10px;font-size:.9rem'>{_e(mc.remediation)}</td>"
            f"<td style='padding:8px 10px'>{mitre_tags}{scenario_html}{poc_html}</td>"
            f"</tr>\n"
        )

    # ---- attack chain section ----
    attack_chain_section = ""
    if report.attack_chains:
        chain_cards = ""
        for chain in report.attack_chains:
            steps_html = "".join(
                f'<li style="margin-bottom:6px"><span style="color:#7c3aed;font-weight:700">Step {i}:</span> {_e(s)}</li>'
                for i, s in enumerate(chain.steps, 1)
            )
            mitre_badges = " ".join(
                f'<a href="{_e(_mitre_url(t))}" target="_blank" rel="noopener" '
                f'style="display:inline-block;margin:0 2px;padding:1px 6px;border-radius:3px;'
                f'background:#dbeafe;color:#1d4ed8;font-size:.75rem;font-weight:600;text-decoration:none">{_e(t)}</a>'
                for t in chain.mitre_techniques
            )
            svg = _attack_chain_svg(chain.steps)
            chain_cards += (
                f'<div style="margin-bottom:20px;border:1px solid #e9d5ff;border-radius:8px;'
                f'background:#faf5ff;overflow:hidden">'
                f'<div style="padding:10px 16px;border-bottom:1px solid #e9d5ff;background:#f3e8ff">'
                f'<span style="font-weight:700;color:#6d28d9">&#9888; {_e(chain.name)}</span>'
                f'</div>'
                f'<div style="padding:16px;display:flex;gap:24px;flex-wrap:wrap">'
                f'<div style="flex:1;min-width:260px">'
                f'<p style="color:#4b5563;margin:0 0 12px;font-size:.9rem">{_e(chain.description)}</p>'
                f'<ol style="margin:0 0 12px;padding-left:20px;font-size:.9rem">{steps_html}</ol>'
                f'<div style="font-size:.85rem">{mitre_badges}</div>'
                f'</div>'
                f'<div style="display:flex;align-items:flex-start">{svg}</div>'
                f'</div>'
                f'</div>\n'
            )
        attack_chain_section = (
            f'<section style="margin-bottom:40px">'
            f'<h2 style="font-size:1.1rem;font-weight:700;color:#6d28d9;border-bottom:2px solid #e9d5ff;'
            f'padding-bottom:8px;margin-bottom:16px">&#9947; Attack Chain Analysis</h2>'
            f'<p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:16px">'
            f'Multi-step kill chains are possible given the combination of findings present. '
            f'Each chain represents a realistic, end-to-end attacker workflow.</p>'
            f'{chain_cards}'
            f'</section>'
        )

    # ---- MITRE ATT&CK coverage ----
    attack_coverage_section = ""
    hits = mitre.coverage(report)
    if hits:
        by_tactic: dict[str, list[mitre.TechniqueHit]] = {}
        for hit in hits:
            by_tactic.setdefault(hit.tactic, []).append(hit)
        cols = ""
        for tactic, techs in by_tactic.items():
            chips = "".join(
                f'<div style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;'
                f'padding:4px 8px;margin:3px 0;font-size:.8rem">'
                f'<span style="font-weight:600;color:#334155">{_e(t.technique_id)}</span> '
                f'{_e(t.name)} <span style="color:#64748b">&times;{t.count}</span></div>'
                for t in techs
            )
            cols += (
                f'<div style="flex:1 1 220px;min-width:200px">'
                f'<div style="font-weight:700;color:#6d28d9;font-size:.85rem;margin-bottom:6px">{_e(tactic)}</div>'
                f'{chips}</div>'
            )
        attack_coverage_section = (
            f'<section style="margin-bottom:40px">'
            f'<h2 style="font-size:1.1rem;font-weight:700;color:#6d28d9;border-bottom:2px solid #e9d5ff;'
            f'padding-bottom:8px;margin-bottom:16px">&#9876; MITRE ATT&amp;CK Coverage</h2>'
            f'<p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:16px">'
            f'Attacker techniques mapped from this scan\'s findings, grouped by tactic '
            f'(kill-chain order). Import the Navigator layer for the full matrix view.</p>'
            f'<div style="display:flex;flex-wrap:wrap;gap:16px">{cols}</div>'
            f'</section>'
        )

    # ---- attack graph (reachable objectives + Mermaid diagram) ----
    attack_graph_section = ""
    mermaid_script = ""
    graph = attack_graph.build_attack_graph(report)
    if not graph.empty:
        goal_rows = "".join(
            f'<tr style="border-bottom:1px solid #fecaca">'
            f'<td style="padding:6px 10px;font-weight:700;color:#b91c1c;white-space:nowrap">{g.value}</td>'
            f'<td style="padding:6px 10px;font-weight:600">{_e(g.label)}</td>'
            f'<td style="padding:6px 10px;font-size:.85rem;color:#475569">'
            + _e(" → ".join(["External"] + [attack_graph.STATE_LABEL.get(e.to, e.to) for e in g.path]))
            + "</td></tr>"
            for g in graph.goals
        )
        mermaid_def = attack_graph.to_mermaid(graph)
        attack_graph_section = (
            f'<section style="margin-bottom:40px">'
            f'<h2 style="font-size:1.1rem;font-weight:700;color:#b91c1c;border-bottom:2px solid #fecaca;'
            f'padding-bottom:8px;margin-bottom:16px">&#128520; Attack Graph &mdash; Reachable Objectives</h2>'
            f'<p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:16px">'
            f'Objectives an attacker can reach by chaining the findings, worst first. '
            f'The diagram shows attacker states (nodes) and the findings that move '
            f'between them (edges); red nodes are objectives.</p>'
            f'<table style="border-collapse:collapse;width:100%;margin-bottom:20px">'
            f'<thead><tr style="border-bottom:2px solid #fecaca">'
            f'<th style="padding:6px 10px;text-align:left;color:#64748b;font-weight:600">Value</th>'
            f'<th style="padding:6px 10px;text-align:left;color:#64748b;font-weight:600">Objective</th>'
            f'<th style="padding:6px 10px;text-align:left;color:#64748b;font-weight:600">Shortest path</th>'
            f'</tr></thead><tbody>{goal_rows}</tbody></table>'
            f'<pre class="mermaid" style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;overflow:auto">{_e(mermaid_def)}</pre>'
            f'</section>'
        )
        mermaid_script = (
            '<script type="module">'
            'import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";'
            'mermaid.initialize({ startOnLoad: true, securityLevel: "strict" });'
            '</script>'
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

    depth_str = report.config.depth.value if report.config else "unknown"
    pov_banner = (
        '<div style="background:#7c3aed;color:#fff;text-align:center;padding:8px;font-size:.85rem;font-weight:600">'
        '&#128373; Attacker\'s View — findings ordered by exploitability</div>'
        if pov else ""
    )

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

{pov_banner}

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
      <div>
        <div style="font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em" title="How much attack surface is open, independent of severity">Exposure</div>
        <div style="font-size:2rem;font-weight:800;color:#e2e8f0">{exposure_idx}<span style="font-size:.9rem;color:#64748b">/100</span></div>
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
  {story_callout}
</section>

<!-- What Could Happen -->
<section style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">&#9888; What Could Happen — Consequence Assessment</h2>
  <p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:12px">
    The highlighted row shows the actual risk level for this site based on findings detected.
  </p>
  <div style="overflow-x:auto">
  <table style="width:100%;border-collapse:collapse;font-size:.9rem;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden">
    <thead>
      <tr style="background:#f8fafc;border-bottom:2px solid #e2e8f0">
        <th style="padding:8px 12px;text-align:left;color:#64748b;font-weight:600;width:120px">Grade</th>
        <th style="padding:8px 12px;text-align:left;color:#64748b;font-weight:600">If Left Unresolved…</th>
        <th style="padding:8px 12px;text-align:left;color:#64748b;font-weight:600">Detail</th>
      </tr>
    </thead>
    <tbody>{consequence_rows}</tbody>
  </table>
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
        <th style="padding:8px 10px;text-align:center;color:#64748b;font-weight:600" title="Proof-of-concept command available">PoC</th>
      </tr>
    </thead>
    <tbody>{{matrix_rows}}</tbody>
  </table>
  </div>'''.format(matrix_rows=matrix_rows)}
</section>

<!-- Detailed Findings -->
<section style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">Detailed Findings</h2>
  <p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:16px">
    Expand <em>&#128373; How an Attacker Exploits This</em> to see the realistic attack scenario.
    Expand <em>&#128192; Attacker's Command</em> for a proof-of-concept command.
    Click MITRE technique badges to open the MITRE ATT&amp;CK knowledge base.
  </p>
  {findings_filter}
  <div id="findings-container">{finding_cards if finding_cards else '<p style="color:#64748b">No findings.</p>'}</div>
</section>

{attack_graph_section}

{attack_chain_section}

{attack_coverage_section}

<!-- CVE Correlation -->
{f'''<section style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">CVE Correlation</h2>
  <p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:12px">
    <strong>KEV</strong> = CISA Known Exploited Vulnerabilities catalog — active exploitation confirmed in the wild.
  </p>
  <div style="overflow-x:auto">
  <table style="width:100%;border-collapse:collapse;font-size:.9rem">
    <thead>
      <tr style="background:#f8fafc;border-bottom:2px solid #e2e8f0">
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">CVE ID</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Severity / CVSS</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600" title="Probability of exploitation (FIRST.org EPSS) / known public exploit">EPSS / Exploit</th>
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">KEV / Age</th>
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
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Attack Context</th>
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
{mermaid_script}
{findings_filter_js}
</body>
</html>"""

    return html_doc


def render(report: ScanReport, fmt: ReportFormat, *, brief: bool = False, attacker_pov: bool = False) -> str:
    if fmt == ReportFormat.JSON:
        return render_json(report)
    if fmt == ReportFormat.HTML:
        return render_html(report, attacker_pov=attacker_pov)
    if fmt == ReportFormat.SARIF:
        return render_sarif(report)
    if fmt == ReportFormat.MARKDOWN:
        return render_markdown(report, brief=brief, attacker_pov=attacker_pov)
    return render_text(report, brief=brief, attacker_pov=attacker_pov)


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


def render_combined(reports: list[ScanReport], fmt: ReportFormat, *, brief: bool = False, attacker_pov: bool = False) -> str:
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
    if fmt == ReportFormat.MARKDOWN:
        return "\n\n---\n\n".join(
            f"# Fleet report {idx}/{len(reports)} — {r.target}\n\n{render_markdown(r, brief=brief, attacker_pov=attacker_pov)}"
            for idx, r in enumerate(reports, 1)
        )
    banner = "\n\n" + _hr("#") + "\n"
    return banner.join(
        f"  FLEET REPORT {idx}/{len(reports)} — {r.target}\n{render_text(r, brief=brief)}"
        for idx, r in enumerate(reports, 1)
    )
