"""Interactive single-target HTML report renderer."""
from __future__ import annotations

import html as _html
from typing import Any

from models import (
    Confidence,
    Finding,
    ScanReport,
    Severity,
    cve_priority,
)
from vuln_correlation import tools_for_category
from diffing import compute_trend
import analysis_kb
import mitre
import attack_graph
import reachability
import provenance

from .scoring import (
    _CONSEQUENCE_LADDER,
    _SEV_ORDER,
    _SEVERITY_LABEL,
    _age_phrase,
    _exploitability_key,
    finding_anchor_map,
    _intel_freshness_summary,
    _mitre_url,
    _poc_validation_checks,
    _remediation_for,
    _risk_score,
    estimate_effort,
)


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

def _poc_evidence_html(f: Finding) -> str:
    """Collapsible block of captured live-validation evidence (Theme E / E2)."""
    checks = _poc_validation_checks(f)
    if not checks:
        return ""
    blocks = ""
    for c in checks:
        status = c.get("http_status")
        if status is not None:
            code = f"HTTP {status}"
        elif c.get("exit_code") is None:
            code = "timed out"
        else:
            code = f"exit {c.get('exit_code')}"
        captured = (str(c.get("stdout", "")) + str(c.get("stderr", ""))).strip()
        body = _e(captured) if captured else "<em>no output</em>"
        blocks += (
            f'<div style="margin-top:8px"><code style="font-size:.82rem;color:#0f172a">'
            f'$ {_e(str(c.get("command", "")))}</code> '
            f'<span style="color:#64748b;font-size:.78rem">({_e(code)})</span>'
            f'<pre style="margin-top:4px;padding:10px;background:#0f172a;color:#e2e8f0;'
            f'border-radius:6px;font-size:.8rem;line-height:1.5;overflow-x:auto;'
            f'white-space:pre-wrap">{body}</pre></div>'
        )
    return (
        f'<details style="margin-top:8px" open>'
        f'<summary style="cursor:pointer;font-weight:600;color:#16a34a;padding:4px 0">'
        f'&#9989; Live Validation Evidence</summary>{blocks}</details>'
    )


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


def render_html(
    report: ScanReport,
    *,
    attacker_pov: bool = False,
    fleet: "list[ScanReport] | None" = None,
) -> str:
    """Produce a self-contained HTML security report."""
    pov = attacker_pov or bool(report.config and report.config.attacker_pov)
    counts = report.summary_counts()
    score, grade = _risk_score(counts)
    exposure_idx = reachability.exposure_index(report)
    intel_line = _intel_freshness_summary(report)
    intel_stale = "STALE" in intel_line
    intel_header = (
        f'<div style="font-size:.78rem;margin-top:6px;color:{"#f87171" if intel_stale else "#64748b"}">'
        f'&#128225; {_e(intel_line)}</div>'
    ) if intel_line else ""
    story = attack_graph.attack_story(report, fleet=fleet)
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
    # Shared, render-unique anchors so the priority list and the detail cards
    # agree even when two findings hash to the same content anchor.
    anchors = finding_anchor_map(report.findings)
    matrix_rows = ""
    _EFFORT_COLOR = {"quick": "#16a34a", "planned": "#ea580c"}
    _EFFORT_LABEL = {"quick": "Quick fix", "planned": "Needs planning"}
    for idx, f in enumerate(sorted(actionable, key=sort_key), 1):
        poc_cell = "<td style='padding:6px 10px;color:#16a34a;font-weight:700'>✓</td>" if f.poc_command else "<td style='padding:6px 10px;color:#cbd5e1'>—</td>"
        effort = estimate_effort(f)
        effort_cell = (
            f"<td style='padding:6px 10px'><span style='padding:1px 7px;border-radius:4px;"
            f"font-size:.72rem;font-weight:700;background:{_EFFORT_COLOR[effort]}1a;"
            f"color:{_EFFORT_COLOR[effort]}'>{_EFFORT_LABEL[effort]}</span></td>"
        )
        anchor = anchors[id(f)]
        matrix_rows += (
            f"<tr>"
            f"<td style='padding:6px 10px;color:#64748b'>{idx}</td>"
            f"<td style='padding:6px 10px'>{_badge(f.severity)}</td>"
            f"<td style='padding:6px 10px;color:#64748b;font-size:.85rem'>{_e(f.category.value)}</td>"
            f"<td style='padding:6px 10px;font-weight:500'>"
            f"<a href='#{anchor}' style='color:#1e293b;text-decoration:none'>{_e(f.title)} &rarr;</a></td>"
            f"{poc_cell}"
            f"{effort_cell}"
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
            # Category-level fallback (mitre.techniques_for_finding) means almost
            # every non-INFO finding gets at least one "how this attack works"
            # link, not just the ones the KB explicitly tags.
            mitre_ids = mitre.techniques_for_finding(f)
            attack_scenario = f.attack_scenario or (kb.get("attack_scenario", "") if kb else "")
            poc = f.poc_command or (kb.get("poc_command", "") if kb else "")
            remediation_text = _remediation_for(f)

            rows = f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Category</td><td>{_e(f.category.value)}</td></tr>\n"
            if f.confidence is not Confidence.CONFIRMED:
                rows += f"<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Confidence</td><td>{_e(f.confidence.value)}</td></tr>\n"
            prov = provenance.finding_provenance(f)
            if prov:
                pc = "#16a34a" if prov.confirmed else "#64748b"
                rows += (
                    "<tr><td style='color:#64748b;white-space:nowrap;padding:4px 12px 4px 0'>Provenance</td>"
                    f"<td><span style='display:inline-block;padding:1px 7px;border-radius:4px;font-size:.72rem;"
                    f"font-weight:700;background:{pc}1a;color:{pc}'>{_e(prov.label)}</span></td></tr>\n"
                )
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
            if f.verification:
                rows += f"<tr><td style='color:#16a34a;white-space:nowrap;padding:4px 12px 4px 0;font-weight:600'>Verified</td><td>{_e(f.verification)}</td></tr>\n"
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
                    f'<pre class="copyable-code" style="margin-top:8px;padding:12px;background:#1e293b;color:#f8fafc;'
                    f'border-radius:6px;font-size:.82rem;line-height:1.6;overflow-x:auto;'
                    f'white-space:pre-wrap;font-family:\'SF Mono\',\'Fira Code\',monospace">'
                    f'{_e(poc)}</pre></details>'
                )
            analysis_html = ""
            if kb:
                analysis_html = (
                    f'<details style="margin-top:12px">'
                    f'<summary style="cursor:pointer;font-weight:600;color:#1e293b;padding:4px 0">'
                    f'&#128269; Issue Analysis</summary>'
                    f'<div style="margin-top:8px;padding:12px;background:#f8fafc;border-radius:6px;'
                    f'font-size:.9rem;line-height:1.7;white-space:pre-wrap;font-family:inherit">'
                    f'{_e(kb["analysis"])}</div></details>'
                )
            # Always present (unlike the KB-gated analysis/attack-scenario blocks
            # above) so every finding — not just the ones the KB recognizes — has
            # a concrete, copy-pasteable next step.
            remediation_html = (
                f'<details style="margin-top:8px" open>'
                f'<summary style="cursor:pointer;font-weight:600;color:#16a34a;padding:4px 0">'
                f'&#128295; How to Fix This</summary>'
                f'<div class="copyable-code" style="margin-top:8px;padding:12px;background:#f0fdf4;border-radius:6px;'
                f'font-size:.9rem;line-height:1.7;white-space:pre-wrap;font-family:inherit">'
                f'{_e(remediation_text)}</div></details>'
            )
            analysis_section = f'{analysis_html}{attack_html}{remediation_html}{poc_html}'

            tactics = sorted({mitre.technique_tactic(t) for t in mitre_ids})
            learn_more_html = ""
            if mitre_ids:
                learn_more_links = " ".join(
                    f'<a href="{_e(_mitre_url(t))}" target="_blank" rel="noopener" '
                    f'style="color:#7c3aed;text-decoration:none">{_e(mitre.technique_name(t))} ({_e(t)})</a>'
                    for t in mitre_ids
                )
                learn_more_html = (
                    f'<div style="margin-top:10px;font-size:.8rem;color:#64748b">'
                    f'&#128218; How this attack works: {learn_more_links}</div>'
                )

            anchor = anchors[id(f)]
            effort = estimate_effort(f)
            effort_color = "#16a34a" if effort == "quick" else "#ea580c"
            effort_label = "Quick fix" if effort == "quick" else "Needs planning"
            open_attr = " open" if sev in (Severity.CRITICAL, Severity.HIGH) else ""
            finding_cards += (
                f'<details id="{anchor}" class="finding-card" data-severity="{f.severity.value}" '
                f'data-category="{f.category.value}" data-confidence="{f.confidence.value}" '
                f'data-tactics="{_e("|".join(tactics))}" '
                f'style="margin-bottom:16px;border:1px solid {border};border-radius:8px;'
                f'background:{bg};overflow:hidden"{open_attr}>'
                f'<summary style="padding:10px 16px;display:flex;align-items:center;gap:10px;'
                f'border-bottom:1px solid {border};cursor:pointer">'
                f'{_badge(f.severity)}'
                f'<span style="font-weight:600;color:#1e293b">{_e(f.title)}</span>'
                f'<span style="margin-left:auto;padding:1px 7px;border-radius:4px;font-size:.7rem;'
                f'font-weight:700;background:{effort_color}1a;color:{effort_color}">{effort_label}</span>'
                f'</summary>'
                f'<div style="padding:12px 16px">'
                f'<table style="border-collapse:collapse;width:100%">{rows}</table>'
                f'{_poc_evidence_html(f)}'
                f'{analysis_section}'
                f'{learn_more_html}'
                f'</div>'
                f'</details>\n'
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

    # ---- drill-down navigation + copy-to-clipboard (layered single-file report) ----
    drilldown_js = (
        '<script>(function(){'
        'document.querySelectorAll(".copyable-code").forEach(function(el){'
        'var btn=document.createElement("button");'
        'btn.type="button";btn.textContent="Copy";'
        'btn.style.cssText="float:right;margin-left:8px;padding:2px 8px;font-size:.72rem;'
        'border:1px solid #cbd5e1;border-radius:4px;background:#fff;color:#334155;cursor:pointer";'
        'btn.addEventListener("click",function(e){e.preventDefault();'
        'navigator.clipboard.writeText(el.textContent.trim());'
        'btn.textContent="Copied!";setTimeout(function(){btn.textContent="Copy";},1500);});'
        'el.parentNode.insertBefore(btn, el);});'
        'function openHash(){var h=location.hash;if(!h)return;'
        'var el=document.querySelector(h);'
        'if(el&&el.tagName==="DETAILS"){el.open=true;el.scrollIntoView({block:"center"});}}'
        'window.addEventListener("hashchange",openHash);openHash();'
        '})();</script>'
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
        exploit_links_html = " ".join(
            f'<a href="{_e(url)}" target="_blank" rel="noopener" '
            'style="display:inline-block;margin:2px 3px 0 0;padding:1px 6px;border-radius:3px;'
            'background:#f1f5f9;color:#334155;font-size:.72rem;text-decoration:none;'
            'border:1px solid #cbd5e1">' + _e(label) + "</a>"
            for label, url in cve.exploit_links
        )
        cve_rows += (
            f"<tr style='border-bottom:1px solid #e2e8f0'>"
            f"<td style='padding:8px 10px;font-weight:600;white-space:nowrap'>{_e(cve.cve_id)}</td>"
            f"<td style='padding:8px 10px'>{_badge(cve.severity)} {cve.cvss_score:.1f}</td>"
            f"<td style='padding:8px 10px'>{epss_html}{exploit_html}</td>"
            f"<td style='padding:8px 10px'>{kev_badge} {age_str}</td>"
            f"<td style='padding:8px 10px;font-size:.9rem'>{_e(cve.description[:200])}</td>"
            f"<td style='padding:8px 10px'>{refs_html}<div>{exploit_links_html}</div></td>"
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
                f'<pre class="copyable-code" style="margin-top:6px;padding:10px;background:#1e293b;color:#f8fafc;border-radius:6px;'
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
            f'<section id="sec-attack-chains" style="margin-bottom:40px">'
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
            f'<section id="sec-attack-coverage" style="margin-bottom:40px">'
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
        _confirmed_badge = (
            '<span style="display:inline-block;margin-left:8px;padding:1px 6px;'
            'border-radius:4px;font-size:.7rem;font-weight:700;background:#dc2626;'
            'color:#fff;vertical-align:middle">CONFIRMED</span>'
        )
        goal_rows = "".join(
            f'<tr style="border-bottom:1px solid #fecaca">'
            f'<td style="padding:6px 10px;font-weight:700;color:#b91c1c;white-space:nowrap">{g.value}</td>'
            f'<td style="padding:6px 10px;font-weight:600">{_e(g.label)}'
            + (_confirmed_badge if g.confirmed else "")
            + "</td>"
            f'<td style="padding:6px 10px;font-size:.85rem;color:#475569">'
            + _e(" → ".join(["External"] + [attack_graph.STATE_LABEL.get(e.to, e.to) for e in g.path]))
            + "</td></tr>"
            for g in graph.goals
        )
        mermaid_def = attack_graph.to_mermaid(graph)
        attack_graph_section = (
            f'<section id="sec-attack-graph" style="margin-bottom:40px">'
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

    # ---- persistent section nav (layered single-file report) ----
    nav_candidates = [
        ("Summary", "sec-summary", True),
        ("Fix These First", "sec-fix", True),
        ("Findings", "sec-findings", True),
        ("Attack Graph", "sec-attack-graph", not graph.empty),
        ("Attack Chains", "sec-attack-chains", bool(report.attack_chains)),
        ("ATT&CK Coverage", "sec-attack-coverage", bool(hits)),
        ("CVEs", "sec-cves", bool(report.cve_records)),
        ("Misconfigs", "sec-misconfigs", bool(report.misconfigurations)),
        ("Threat Intel", "sec-intel", bool(report.intel_sources)),
        ("Errors", "sec-errors", bool(report.errors)),
    ]
    nav_html = "".join(
        f'<a href="#{aid}" style="color:#e2e8f0;text-decoration:none;font-size:.82rem;'
        f'font-weight:600;padding:4px 10px;border-radius:5px;white-space:nowrap">{_e(label)}</a>'
        for label, aid, present in nav_candidates if present
    )
    section_nav = (
        f'<nav style="position:sticky;top:0;z-index:20;background:#0f172a;'
        f'padding:8px 24px;display:flex;gap:4px;flex-wrap:nowrap;overflow-x:auto;'
        f'border-bottom:1px solid #1e293b" aria-label="Report sections">{nav_html}</nav>'
    )

    # ---- error list ----
    error_items = "".join(f"<li style='color:#dc2626'>{_e(e)}</li>" for e in report.errors)
    errors_section = (
        f'<section id="sec-errors" style="margin-bottom:40px">'
        f'<h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">Scan Errors</h2>'
        f'<ul style="margin:0;padding-left:20px">{error_items}</ul>'
        f'</section>'
        if report.errors else ""
    )

    # ---- threat-intel freshness (F1) ----
    intel_section = ""
    if report.intel_sources:
        intel_rows = ""
        for s in report.intel_sources:
            as_of = _e(s.as_of) if s.as_of else "<span style='color:#94a3b8'>unknown</span>"
            flag = (
                "<span style='color:#dc2626;font-weight:600'>stale — refresh</span>"
                if s.stale else "<span style='color:#16a34a'>fresh</span>"
            )
            count = str(s.item_count) if s.item_count else "—"
            intel_rows += (
                "<tr style='border-bottom:1px solid #e2e8f0'>"
                f"<td style='padding:6px 10px;font-weight:600'>{_e(s.name)}</td>"
                f"<td style='padding:6px 10px'>{as_of}</td>"
                f"<td style='padding:6px 10px;color:#475569'>{_e(s.detail)}</td>"
                f"<td style='padding:6px 10px;text-align:right'>{count}</td>"
                f"<td style='padding:6px 10px'>{flag}</td></tr>\n"
            )
        intel_section = (
            '<section id="sec-intel" style="margin-bottom:40px">'
            '<h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">Threat Intelligence</h2>'
            '<p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:12px">'
            'Freshness of the external feeds consulted for this scan — stale intel is a silent false-negative.</p>'
            '<table style="width:100%;border-collapse:collapse;font-size:.9rem">'
            '<thead><tr style="background:#f8fafc;border-bottom:2px solid #e2e8f0">'
            '<th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Source</th>'
            '<th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">As of</th>'
            '<th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Detail</th>'
            '<th style="padding:8px 10px;text-align:right;color:#64748b;font-weight:600">Records</th>'
            '<th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600">Status</th>'
            f"</tr></thead><tbody>{intel_rows}</tbody></table></section>"
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
  nav a:hover {{ background: #1e293b; }}
</style>
</head>
<body>

{section_nav}

{pov_banner}

<!-- Header -->
<header style="background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:#f8fafc;padding:32px 40px">
  <div style="max-width:1100px;margin:0 auto">
    <div style="font-size:1.4rem;font-weight:800;letter-spacing:.05em;color:#38bdf8">
      &#128273; INQUISITION
    </div>
    <div style="font-size:.9rem;color:#94a3b8;margin-top:4px">Security Reconnaissance Report</div>
    {intel_header}
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
<section id="sec-summary" style="margin-bottom:40px">
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
<section id="sec-fix" style="margin-bottom:40px">
  <h2 style="font-size:1.1rem;font-weight:700;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:8px;margin-bottom:16px">&#9989; Fix These First</h2>
  <p style="font-size:.85rem;color:#64748b;margin-top:-8px;margin-bottom:12px">
    Ranked by real-world exploit risk. Click a title to jump straight to its remediation steps below.
  </p>
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
        <th style="padding:8px 10px;text-align:left;color:#64748b;font-weight:600" title="Rough effort to remediate">Effort</th>
      </tr>
    </thead>
    <tbody>{{matrix_rows}}</tbody>
  </table>
  </div>'''.format(matrix_rows=matrix_rows)}
</section>

<!-- Detailed Findings -->
<section id="sec-findings" style="margin-bottom:40px">
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
{f'''<section id="sec-cves" style="margin-bottom:40px">
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
{f'''<section id="sec-misconfigs" style="margin-bottom:40px">
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

{intel_section}

{errors_section}

</main>

<footer style="background:#0f172a;color:#475569;text-align:center;padding:16px;font-size:.8rem;margin-top:40px">
  Generated by Inquisition &nbsp;·&nbsp; {_e(report.target)} &nbsp;·&nbsp; {report.started_at:%Y-%m-%d %H:%M UTC}
</footer>
{mermaid_script}
{findings_filter_js}
{drilldown_js}
</body>
</html>"""

    return html_doc
