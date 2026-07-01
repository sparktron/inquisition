"""Bulk 'quick fix' export — a reviewable runbook, not a blind auto-fixer.

Remediation text in the knowledge base is prose written for a human: it
branches on your mail provider, framework, or infra ("If using Google
Workspace: ... If using Microsoft 365: ..."). Auto-extracting and chaining
command-looking lines out of that prose would risk silently running something
the operator never chose — so this deliberately does not do that. Instead it
bundles every "quick fix" finding's remediation as a heavily-commented
checklist, and leaves only genuinely safe, read-only verification commands
(reusing :mod:`poc_validation`'s allowlist) as actually-runnable lines, so the
script is safe to execute as-is: it verifies, it does not modify anything.
"""
from __future__ import annotations

from datetime import datetime, timezone

import analysis_kb
import poc_validation
from models import Finding, ScanReport, Severity
from report.scoring import _SEV_ORDER, _SEVERITY_LABEL, _remediation_for, estimate_effort

_ACTIONABLE_SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)


def _comment_block(text: str) -> str:
    """Prefix every line of ``text`` with '# ' (or bare '#' for blank lines)."""
    return "\n".join(f"# {line}" if line else "#" for line in text.split("\n"))


def _verify_command_for(f: Finding) -> str:
    """The same command the text/HTML remediation guides label 'verify the fix'."""
    if f.poc_command:
        return f.poc_command
    kb = analysis_kb.lookup(f.title)
    return kb.get("poc_command", "") if kb else ""


def _finding_section(f: Finding) -> str:
    lines = [
        "# " + "=" * 70,
        f"# [{_SEVERITY_LABEL[f.severity]}] {f.title}",
        f"# Category: {f.category.value}",
        "# " + "=" * 70,
        "#",
        "# Remediation (review before applying — steps often branch on your",
        "# specific mail provider / framework / infra; pick the ones that apply):",
        "#",
        _comment_block(_remediation_for(f)),
        "#",
    ]
    verify_cmd = _verify_command_for(f)
    if verify_cmd:
        safe, reason = poc_validation.classify_command(verify_cmd)
        if safe:
            lines.append("# Verify after fixing (safe, read-only check):")
            lines.append(verify_cmd)
        else:
            lines.append(f"# Verify after fixing (review before running — {reason}):")
            lines.append(_comment_block(verify_cmd))
    lines.append("")
    return "\n".join(lines)


def render_fix_script(reports: list[ScanReport]) -> str:
    """Render a bash runbook bundling every 'quick fix' finding across ``reports``.

    Ordered by severity (worst first). Multi-target runs label each section with
    its target so the operator knows which host a step applies to.
    """
    multi = len(reports) > 1
    quick: list[tuple[ScanReport, Finding]] = [
        (report, f)
        for report in reports
        for f in report.findings
        if f.severity in _ACTIONABLE_SEVERITIES and estimate_effort(f) == "quick"
    ]

    lines = [
        "#!/usr/bin/env bash",
        "# Inquisition quick-fix runbook",
        f"# Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
        "#",
        "# This is a REVIEWABLE CHECKLIST, not an auto-fixer: remediation steps stay",
        "# as comments because they routinely branch on your mail provider,",
        "# framework, or infra (see each block), and picking the wrong option can",
        "# break email delivery or lock out legitimate traffic. Only verification",
        "# commands — read-only checks like curl/dig/openssl — are left",
        "# uncommented, so this script is safe to run as-is: it checks, it does not",
        "# modify anything.",
        "#",
        "set -euo pipefail",
        "",
    ]
    if not quick:
        lines.append("# No quick-fix findings at CRITICAL/HIGH/MEDIUM severity.")
        return "\n".join(lines) + "\n"

    for report, f in sorted(quick, key=lambda pair: _SEV_ORDER.index(pair[1].severity)):
        if multi:
            lines.append(f"# Target: {report.target}")
        lines.append(_finding_section(f))

    return "\n".join(lines) + "\n"
