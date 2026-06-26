"""Plain-text report renderer (ASCII, 72-char rules)."""
from __future__ import annotations

from models import (
    Confidence,
    FindingCategory,
    ScanReport,
    Severity,
    TOOL_REFERENCE,
    cve_priority,
)
from vuln_correlation import tools_for_category
import analysis_kb
import mitre
import attack_graph
import reachability

from .scoring import (
    _CONSEQUENCE_LADDER,
    _SEV_ORDER,
    _SEVERITY_LABEL,
    _age_phrase,
    _exploitability_key,
    _mitre_url,
    _risk_score,
)


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


def render_text(
    report: ScanReport,
    *,
    brief: bool = False,
    attacker_pov: bool = False,
    fleet: "list[ScanReport] | None" = None,
) -> str:
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
    story = attack_graph.attack_story(report, fleet=fleet)
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
            lines.append("    Provenance: Modeled — knowledge-base rule")
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

    # --- Threat-intel freshness (F1) ---
    if report.intel_sources:
        lines.append(_section("THREAT INTELLIGENCE"))
        lines.append("  Freshness of the external feeds consulted for this scan.\n")
        for s in report.intel_sources:
            as_of = f"as of {s.as_of}" if s.as_of else "date unknown"
            stale = "  [STALE — refresh recommended]" if s.stale else ""
            count_str = f", {s.item_count} records" if s.item_count else ""
            lines.append(f"  {s.name:<22s} {as_of} ({s.detail}{count_str}){stale}")
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
