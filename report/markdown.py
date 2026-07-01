"""Markdown (GitHub-flavored) report renderer."""
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
import reachability

from .scoring import (
    _CONSEQUENCE_LADDER,
    _SEV_ORDER,
    _SEVERITY_LABEL,
    _age_phrase,
    _exploitability_key,
    _intel_freshness_summary,
    _mitre_url,
    _remediation_for,
    _risk_score,
    estimate_effort,
)


def _md_cell(text: str) -> str:
    """Escape a value for safe inclusion in a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def _md_url(url: str) -> str:
    """Percent-encode the characters in ``url`` that would break a Markdown
    inline link inside a table cell.

    A raw ``)`` closes the ``[label](url)`` target early, a ``|`` splits the
    table row, and whitespace ends the URL — external reference URLs contain all
    three, so encode them rather than trust the source.
    """
    return (
        url.replace("(", "%28").replace(")", "%29").replace("|", "%7C").replace(" ", "%20")
    )


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
    intel_line = _intel_freshness_summary(report)
    if intel_line:
        out.append(f"- **Intel:** {intel_line}")
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

    # --- Fix These First ---
    out.append("## Fix These First")
    out.append("")
    actionable = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    sort_key = _exploitability_key if pov else lambda x: (_SEV_ORDER.index(x.severity), 0, 0)
    if actionable:
        poc_col = " PoC |" if pov else ""
        out.append(f"| # | Severity | Category | Title | Effort |{poc_col}")
        out.append(f"| --- | --- | --- | --- | --- |{'--- |' if pov else ''}")
        for idx, f in enumerate(sorted(actionable, key=sort_key), 1):
            poc_flag = "✓" if f.poc_command else ""
            effort = "Quick fix" if estimate_effort(f) == "quick" else "Needs planning"
            row = (
                f"| {idx} | {_SEVERITY_LABEL[f.severity]} | {_md_cell(f.category.value)} | "
                f"{_md_cell(f.title)} | {effort} |"
            )
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
            technique_ids = mitre.techniques_for_finding(f)
            if technique_ids:
                links = ", ".join(f"[{t}]({_mitre_url(t)})" for t in technique_ids)
                out.append(f"- **MITRE ATT&CK:** {links}")
            if f.impact:
                out.append(f"- **Impact:** {f.impact}")
            out.append(f"- **Fix:** {_remediation_for(f)}")
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
        out.append("| CVE ID | CVSS | EPSS | Severity | KEV | Exploit | Days Old | Description | Exploit Links |")
        out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for cve in sorted(report.cve_records, key=cve_priority, reverse=True):
            kev = "⚠️ **KEV**" if cve.in_cisa_kev else "—"
            epss = f"{cve.epss_score:.0%}" if cve.epss_score else "—"
            exploit = f"**{', '.join(cve.exploit_sources)}**" if cve.exploit_public else "—"
            age = f"{cve.days_since_disclosure}d" if cve.days_since_disclosure else "—"
            links = ", ".join(f"[{_md_cell(label)}]({_md_url(url)})" for label, url in cve.exploit_links) or "—"
            out.append(
                f"| {cve.cve_id} | {cve.cvss_score:.1f} | {epss} | {_SEVERITY_LABEL[cve.severity]} "
                f"| {kev} | {exploit} | {age} | {_md_cell(cve.description[:120])} | {links} |"
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
