"""Fleet dashboard renderer — one HTML page ranking a multi-target run."""
from __future__ import annotations

import html as _html
from datetime import datetime

from models import ScanReport, Severity

from .scoring import _risk_score
from .serialize import _fleet_summary
from .html import _GRADE_CSS, _SEV_CSS, _badge, _e, _trend_sparkline_html


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

    correlation_section = _fleet_correlation_html(reports)
    blast_section = _fleet_blast_radius_html(reports)

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
{correlation_section}{blast_section}</main>
</body>
</html>"""


_ASSET_TIER_CSS: dict[str, str] = {
    "crown": "#7c3aed", "high": "#dc2626", "medium": "#ca8a04",
    "low": "#16a34a", "untagged": "#64748b",
}


def _fleet_blast_radius_html(reports: list[ScanReport]) -> str:
    """Blast-radius / crown-jewel section for the fleet dashboard (Theme D / D2)."""
    import fleet_correlation
    ranked = fleet_correlation.blast_radius(reports)
    if not ranked:
        return ""

    rows = ""
    for b in ranked:
        tier = b.value or "untagged"
        tier_color = _ASSET_TIER_CSS.get(tier, "#64748b")
        endangered = ", ".join(_e(t) for t in b.endangered) or "—"
        rows += (
            "<tr style='border-bottom:1px solid #e2e8f0;vertical-align:top'>"
            f"<td style='padding:10px 12px;font-weight:600'>{_e(b.target)}</td>"
            f"<td style='padding:10px 12px'><span style='color:{tier_color};font-weight:700;"
            f"text-transform:capitalize'>{_e(tier)}</span></td>"
            f"<td style='padding:10px 12px;text-align:center;font-weight:800;color:#b91c1c'>{b.endangered_value}</td>"
            f"<td style='padding:10px 12px;font-size:.85rem;color:#475569'>{endangered}</td>"
            "</tr>\n"
        )

    return (
        "<section style='margin-top:32px'>"
        "<h2 style='font-size:1.1rem;font-weight:700;color:#7c3aed;border-bottom:2px solid #ddd6fe;"
        "padding-bottom:8px;margin-bottom:8px'>&#128081; Blast Radius &amp; Crown Jewels</h2>"
        "<p style='font-size:.8rem;color:#64748b;margin-top:0;margin-bottom:16px'>"
        "Remediation priority by the asset value a host's compromise would endanger across the fleet "
        "(a cheap pivot bridged to a crown jewel ranks above a locally-severe but isolated host). "
        "Tag targets with <code>asset_value: crown|high|medium|low</code> in the fleet config.</p>"
        "<table style='width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden'>"
        "<thead style='background:#f1f5f9;font-size:.8rem;color:#475569;text-align:left'><tr>"
        "<th style='padding:10px 12px'>Target</th>"
        "<th style='padding:10px 12px'>Asset value</th>"
        "<th style='padding:10px 12px;text-align:center'>Endangered value</th>"
        "<th style='padding:10px 12px'>Endangers</th>"
        f"</tr></thead><tbody>\n{rows}</tbody></table></section>\n"
    )


def _fleet_correlation_html(reports: list[ScanReport]) -> str:
    """Cross-target attack-path section for the fleet dashboard (Theme D / D1)."""
    import fleet_correlation
    links = fleet_correlation.correlate_fleet(reports)
    if not links:
        return ""

    rows = ""
    for link in links:
        bg, fg, _ = _SEV_CSS[link.severity]
        targets = ", ".join(_e(t) for t in link.targets)
        rows += (
            "<tr style='border-bottom:1px solid #e2e8f0;vertical-align:top'>"
            f"<td style='padding:10px 12px;white-space:nowrap'>"
            f"<span style='display:inline-block;padding:1px 7px;border-radius:4px;font-size:.72rem;"
            f"font-weight:700;background:{bg};color:{fg}'>{_e(link.label)}</span></td>"
            f"<td style='padding:10px 12px;font-weight:600'>{targets}</td>"
            f"<td style='padding:10px 12px;font-size:.85rem;color:#475569'>"
            f"{_e(link.detail)}<br><span style='color:#b91c1c'>{_e(link.attack_note)}</span></td>"
            "</tr>\n"
        )

    return (
        "<section style='margin-top:32px'>"
        "<h2 style='font-size:1.1rem;font-weight:700;color:#b91c1c;border-bottom:2px solid #fecaca;"
        "padding-bottom:8px;margin-bottom:8px'>&#128279; Cross-Target Attack Paths</h2>"
        "<p style='font-size:.8rem;color:#64748b;margin-top:0;margin-bottom:16px'>"
        "Shared infrastructure and trust relationships that let one weak host endanger the rest of the fleet.</p>"
        "<table style='width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden'>"
        "<thead style='background:#f1f5f9;font-size:.8rem;color:#475569;text-align:left'><tr>"
        "<th style='padding:10px 12px'>Relationship</th>"
        "<th style='padding:10px 12px'>Targets</th>"
        "<th style='padding:10px 12px'>Detail &amp; attacker abuse</th>"
        f"</tr></thead><tbody>\n{rows}</tbody></table></section>\n"
    )

