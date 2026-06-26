"""Report generation — text, Markdown, JSON, SARIF, HTML, and fleet renderers.

Previously a single 2000-line ``report.py``; split into a package along renderer
boundaries (see the sibling modules). This module re-exports the public API and
hosts the two format dispatchers, so ``from report import render`` etc. keep
working unchanged.
"""
from __future__ import annotations

from models import ReportFormat, ScanReport

from .scoring import _risk_score
from .text import _hr, render_text
from .markdown import render_markdown
from .serialize import (
    render_json,
    render_json_combined,
    render_sarif,
    render_sarif_combined,
)
from .html import render_html
from .fleet import render_fleet_dashboard


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
        f"  FLEET REPORT {idx}/{len(reports)} — {r.target}\n{render_text(r, brief=brief, fleet=reports)}"
        for idx, r in enumerate(reports, 1)
    )


__all__ = [
    "render",
    "render_combined",
    "render_text",
    "render_markdown",
    "render_json",
    "render_sarif",
    "render_html",
    "render_json_combined",
    "render_sarif_combined",
    "render_fleet_dashboard",
    "_risk_score",
]
