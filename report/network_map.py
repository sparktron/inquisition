"""Interactive network-topology map renderer.

Turns a multi-host scan (typically a subnet/CIDR discovery sweep) into a single
self-contained HTML page: a hub-and-spoke diagram with the gateway/router at the
centre and every live host arranged around it, coloured by role
(gateway / server / endpoint / unknown) so you can see at a glance which IPs are
network devices and which are user machines. Dependency-free — inline SVG, CSS
and JS, no external libraries — matching the rest of the report package.
"""
from __future__ import annotations

import math
from datetime import datetime

from host_classification import HostProfile, HostRole, classify_reports
from models import ScanReport

from .html import _e

# Role -> (fill colour, display label)
_ROLE_STYLE: dict[HostRole, tuple[str, str]] = {
    HostRole.GATEWAY: ("#7c3aed", "Gateway / router"),
    HostRole.SERVER: ("#2563eb", "Server"),
    HostRole.ENDPOINT: ("#16a34a", "Endpoint / user device"),
    HostRole.UNKNOWN: ("#64748b", "Unknown"),
}


def _layout(n: int) -> tuple[list[tuple[float, float]], float, float, float]:
    """Positions for n spokes on concentric rings; returns (points, size, cx, cy)."""
    rings: list[int] = []
    remaining = n
    ring = 1
    while remaining > 0:
        take = min(6 * ring, remaining)
        rings.append(take)
        remaining -= take
        ring += 1
    r0, gap = 130.0, 100.0
    max_ring = len(rings)
    max_radius = r0 + (max_ring - 1) * gap if max_ring else r0
    size = 2 * (max_radius + 80.0)
    cx = cy = size / 2
    points: list[tuple[float, float]] = []
    for ring_idx, count in enumerate(rings, start=1):
        radius = r0 + (ring_idx - 1) * gap
        for k in range(count):
            angle = (2 * math.pi * k / count) - math.pi / 2
            points.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
    return points, size, cx, cy


def _node_svg(x: float, y: float, profile: HostProfile, *, hub: bool = False) -> str:
    color, _label = _ROLE_STYLE[profile.role]
    r = 30.0 if hub else 21.0
    ip = profile.target
    ports = ", ".join(str(p) for p in profile.open_ports)
    signals = " | ".join(profile.signals)
    short = ip.rsplit(".", 1)[-1] if ip.count(".") == 3 else ip
    data = (
        f'class="node" tabindex="0" data-role="{_e(profile.role.value)}" '
        f'data-ip="{_e(ip)}" data-host="{_e(profile.hostname or "")}" '
        f'data-rolelabel="{_e(_ROLE_STYLE[profile.role][1])}" '
        f'data-conf="{_e(profile.confidence)}" data-ports="{_e(ports)}" '
        f'data-signals="{_e(signals)}"'
    )
    caption = _e(profile.hostname or ip)
    return (
        f'<g {data} style="cursor:pointer">'
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{color}" '
        f'stroke="#fff" stroke-width="2"></circle>'
        f'<text x="{x:.1f}" y="{y + 4:.1f}" text-anchor="middle" '
        f'font-size="{11 if hub else 10}" fill="#fff" font-weight="700">{_e(str(short))}</text>'
        f'<text x="{x:.1f}" y="{y + r + 13:.1f}" text-anchor="middle" '
        f'font-size="9.5" fill="#334155">{caption}</text>'
        f"</g>"
    )


def _topology_svg(hub: HostProfile | None, spokes: list[HostProfile], subnet_label: str) -> str:
    points, size, cx, cy = _layout(len(spokes))
    pos: dict[str, tuple[float, float]] = {}
    edges: list[str] = []
    nodes: list[str] = []

    for profile, (x, y) in zip(spokes, points):
        pos[profile.target] = (x, y)
        edges.append(
            f'<line data-role="{_e(profile.role.value)}" x1="{cx:.1f}" y1="{cy:.1f}" '
            f'x2="{x:.1f}" y2="{y:.1f}" stroke="#cbd5e1" stroke-width="1.5"></line>'
        )
        nodes.append(_node_svg(x, y, profile))

    # Central hub: the gateway if we found one, else a neutral subnet marker.
    if hub is not None:
        pos[hub.target] = (cx, cy)
        hub_svg = _node_svg(cx, cy, hub, hub=True)
    else:
        hub_svg = (
            f'<g><circle cx="{cx:.1f}" cy="{cy:.1f}" r="34" fill="#0f172a" '
            f'stroke="#fff" stroke-width="2"></circle>'
            f'<text x="{cx:.1f}" y="{cy + 4:.1f}" text-anchor="middle" font-size="10" '
            f'fill="#fff" font-weight="700">subnet</text>'
            f'<text x="{cx:.1f}" y="{cy + 50:.1f}" text-anchor="middle" font-size="10" '
            f'fill="#334155">{_e(subnet_label)}</text></g>'
        )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="100%" viewBox="0 0 {size:.0f} {size:.0f}" '
        f'role="img" aria-label="network topology map" style="max-width:{size:.0f}px">'
        + "".join(edges)
        + hub_svg
        + "".join(nodes)
        + "</svg>"
    )


def _legend(profiles: list[HostProfile]) -> str:
    counts: dict[HostRole, int] = {role: 0 for role in HostRole}
    for p in profiles:
        counts[p.role] += 1
    items = ""
    for role, (color, label) in _ROLE_STYLE.items():
        n = counts.get(role, 0)
        items += (
            f'<label style="display:inline-flex;align-items:center;gap:6px;margin-right:16px;cursor:pointer">'
            f'<input type="checkbox" class="rolefilter" data-role="{role.value}" checked>'
            f'<span style="width:12px;height:12px;border-radius:50%;background:{color};display:inline-block"></span>'
            f'<span style="font-size:.85rem">{_e(label)} ({n})</span></label>'
        )
    return items


def _role_tables(profiles: list[HostProfile]) -> str:
    """A grouped, authoritative host list (also a fallback when the SVG is dense)."""
    out = ""
    for role, (color, label) in _ROLE_STYLE.items():
        members = [p for p in profiles if p.role is role]
        if not members:
            continue
        rows = ""
        for p in members:
            ports = ", ".join(str(x) for x in p.open_ports) or "—"
            rows += (
                f"<tr style='border-bottom:1px solid #e2e8f0'>"
                f"<td style='padding:6px 10px;font-weight:600'>{_e(p.target)}</td>"
                f"<td style='padding:6px 10px'>{_e(p.hostname or '—')}</td>"
                f"<td style='padding:6px 10px'>{_e(ports)}</td>"
                f"<td style='padding:6px 10px;color:#64748b'>{_e(' | '.join(p.signals))}</td>"
                f"</tr>"
            )
        out += (
            f"<h3 style='margin:20px 0 6px;font-size:1rem'>"
            f"<span style='width:11px;height:11px;border-radius:50%;background:{color};"
            f"display:inline-block;margin-right:8px'></span>{_e(label)} ({len(members)})</h3>"
            f"<table style='width:100%;border-collapse:collapse;background:#fff;"
            f"border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;font-size:.85rem'>"
            f"<thead style='background:#f1f5f9;color:#475569;text-align:left'><tr>"
            f"<th style='padding:6px 10px'>Address</th><th style='padding:6px 10px'>Hostname</th>"
            f"<th style='padding:6px 10px'>Open ports</th><th style='padding:6px 10px'>Why</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )
    return out


_PANEL_JS = """
(function(){
  var panel = document.getElementById('nm-detail');
  function show(n){
    var rows = [
      ['Address', n.getAttribute('data-ip')],
      ['Hostname', n.getAttribute('data-host') || '—'],
      ['Role', n.getAttribute('data-rolelabel')],
      ['Confidence', n.getAttribute('data-conf')],
      ['Open ports', n.getAttribute('data-ports') || 'none'],
      ['Why', n.getAttribute('data-signals') || '—']
    ];
    panel.replaceChildren();
    rows.forEach(function(r){
      var d = document.createElement('div');
      d.style.margin = '2px 0';
      var k = document.createElement('span');
      k.textContent = r[0] + ': ';
      k.style.color = '#64748b';
      var v = document.createElement('span');
      v.textContent = r[1];
      v.style.fontWeight = '600';
      d.appendChild(k); d.appendChild(v); panel.appendChild(d);
    });
  }
  document.querySelectorAll('.node').forEach(function(n){
    n.addEventListener('mouseenter', function(){ show(n); });
    n.addEventListener('focus', function(){ show(n); });
    n.addEventListener('click', function(){ show(n); });
  });
  document.querySelectorAll('.rolefilter').forEach(function(cb){
    cb.addEventListener('change', function(){
      var role = cb.getAttribute('data-role');
      var on = cb.checked;
      document.querySelectorAll('[data-role="' + role + '"]').forEach(function(el){
        el.style.display = on ? '' : 'none';
      });
    });
  });
})();
"""


def _classify_and_split(
    reports: list[ScanReport], default_gateway: str | None
) -> tuple[list[HostProfile], list[HostProfile], HostProfile | None, list[HostProfile]]:
    """Classify reports and split into (live, dead, hub gateway, spokes)."""
    profiles = classify_reports(reports, default_gateway=default_gateway)
    live = [p for p in profiles if p.live]
    dead = [p for p in profiles if not p.live]
    gateways = [p for p in live if p.role is HostRole.GATEWAY]
    hub = gateways[0] if gateways else None
    spokes = [p for p in live if p is not hub]
    return live, dead, hub, spokes


def _render_block(
    live: list[HostProfile], hub: HostProfile | None, spokes: list[HostProfile], label: str
) -> str:
    """Interactive topology content (legend + SVG + detail panel + tables + script)."""
    svg = _topology_svg(hub, spokes, label)
    return f"""<div style="margin-bottom:12px">{_legend(live)}</div>
  <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start">
    <div style="flex:1 1 560px;min-width:320px;overflow:auto;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px">
      {svg}
    </div>
    <aside style="flex:0 1 260px;min-width:220px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:14px">
      <div style="font-size:.7rem;text-transform:uppercase;color:#94a3b8;margin-bottom:8px">Host detail</div>
      <div id="nm-detail" style="font-size:.85rem;color:#334155">Hover or tap a node to see its details.</div>
    </aside>
  </div>
  {_role_tables(live)}
  <script>{_PANEL_JS}</script>"""


def topology_block_html(
    reports: list[ScanReport], *, default_gateway: str | None = None, subnet_label: str | None = None
) -> str:
    """The interactive topology block only (no page shell) — for embedding in a dashboard."""
    live, _dead, hub, spokes = _classify_and_split(reports, default_gateway)
    label = subnet_label or f"{len(live)} live host(s)"
    return _render_block(live, hub, spokes, label)


def render_network_map(
    reports: list[ScanReport], *, default_gateway: str | None = None, subnet_label: str | None = None
) -> str:
    """Render a full standalone interactive HTML topology page for a multi-host scan."""
    live, dead, hub, spokes = _classify_and_split(reports, default_gateway)
    label = subnet_label or f"{len(live)} live host(s)"
    block = _render_block(live, hub, spokes, label)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    gateway_note = (
        f"gateway {_e(hub.target)}" if hub is not None else "no gateway identified"
    )
    scope = f"{_e(subnet_label)} · " if subnet_label else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Inquisition Network Map</title>
</head>
<body style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;color:#1e293b">
<header style="background:#0f172a;color:#fff;padding:24px">
  <div style="max-width:1100px;margin:0 auto">
    <div style="font-size:1.4rem;font-weight:800">Inquisition Network Map</div>
    <div style="font-size:.85rem;color:#cbd5e1">{scope}{len(live)} live · {len(dead)} not responding · {gateway_note} · generated {generated}</div>
  </div>
</header>
<main style="max-width:1100px;margin:0 auto;padding:24px">
  {block}
  <p style="margin-top:20px;font-size:.78rem;color:#94a3b8">
    Roles are heuristic (open ports, reverse-DNS names, gateway address, WAF/proxy signatures) and best-effort.
    A host that never answered on a scanned port is counted as not responding and is not drawn.
  </p>
</main>
</body>
</html>"""
