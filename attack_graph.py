"""Attacker-state graph: connect findings into reachable objectives.

Where attack *chains* are hand-authored end-to-end narratives, the attack
*graph* is emergent: attacker **states** are nodes, and each misconfiguration (or
combination) is an **edge** that moves the attacker from one state to another. A
breadth-first traversal from the ``external`` start state then reveals every
objective an attacker can actually reach given the current findings — including
multi-step paths nobody wrote down — plus the shortest path to each.

The result drives a Mermaid diagram in the HTML report and a text summary.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models import Finding, ScanReport

START = "external"

# Human-readable labels for attacker states.
STATE_LABEL: dict[str, str] = {
    "external": "External attacker",
    "on_path": "On-path / MITM",
    "recon": "Internal recon",
    "credentials": "Credentials obtained",
    "code_exec": "Code execution (RCE)",
    "data_access": "Data access / exfiltration",
    "cloud_account": "Cloud account takeover",
    "lateral": "Lateral movement / pivot",
    "session_hijack": "Session / account takeover",
    "phishing": "Trusted-domain phishing",
}

# Objective states an attacker wants to reach, with a relative value weight.
GOAL_VALUE: dict[str, int] = {
    "code_exec": 100,
    "cloud_account": 90,
    "data_access": 80,
    "lateral": 70,
    "session_hijack": 60,
    "credentials": 50,
    "phishing": 40,
}

# misconfiguration name -> (from_state, to_state, edge label)
_MISCONFIG_EDGES: dict[str, tuple[str, str, str]] = {
    "HSTS not enabled": ("external", "on_path", "SSL strip (no HSTS)"),
    "Unencrypted HTTP served": ("external", "on_path", "cleartext HTTP intercept"),
    "Legacy TLS enabled": ("external", "on_path", "TLS downgrade"),
    "Weak TLS cipher suite in use": ("external", "on_path", "weak-cipher decryption"),
    "Self-signed certificate in use": ("external", "on_path", "cert-warning MITM"),
    "Expired TLS certificate": ("external", "on_path", "cert-warning MITM"),
    "Telnet service exposed": ("external", "credentials", "sniff cleartext Telnet creds"),
    "DNS zone transfer unrestricted": ("external", "recon", "AXFR zone dump"),
    "Environment file publicly accessible": ("external", "credentials", "read .env secrets"),
    "Git repository exposed": ("external", "credentials", "reconstruct repo + secrets"),
    "Sensitive file publicly accessible": ("external", "credentials", "download exposed secrets"),
    "PHP configuration page exposed": ("external", "recon", "phpinfo disclosure"),
    "Redis exposed to internet": ("external", "code_exec", "Redis webshell write"),
    "SMB exposed to internet": ("external", "code_exec", "EternalBlue RCE"),
    "RDP exposed to internet": ("external", "code_exec", "BlueKeep / brute force"),
    "VNC exposed to internet": ("external", "code_exec", "unauthenticated VNC"),
    "Elasticsearch exposed to internet": ("external", "data_access", "open index dump"),
    "Admin panel publicly accessible": ("external", "data_access", "credential stuffing"),
    "GraphQL introspection enabled in production": ("external", "data_access", "schema enum + IDOR"),
    "Overly permissive CORS policy": ("external", "data_access", "cross-origin data theft"),
    "HTTP TRACE method enabled": ("external", "session_hijack", "XST cookie theft"),
    "Potential subdomain takeover via dangling CNAME": ("external", "phishing", "claim dangling CNAME"),
}

# Edges requiring SEVERAL misconfigurations together.
_COMBO_EDGES: list[tuple[tuple[str, ...], tuple[str, str, str]]] = [
    (
        ("CSP not configured", "Session cookies lack security flags"),
        ("external", "session_hijack", "XSS → cookie theft (no CSP/HttpOnly)"),
    ),
]

# Logical consequence edges: once the ``from`` state is reached, the ``to`` state
# follows. Added to the graph but only meaningful when ``from`` is reachable.
_CONSEQUENCE_EDGES: list[tuple[str, str, str]] = [
    ("on_path", "credentials", "intercept submitted credentials"),
    ("on_path", "session_hijack", "replay captured session cookie"),
    ("credentials", "data_access", "authenticate to data stores"),
    ("credentials", "cloud_account", "use leaked cloud keys"),
    ("code_exec", "data_access", "read application data"),
    ("code_exec", "lateral", "pivot from compromised host"),
    ("recon", "lateral", "reach internal hosts"),
]


# Confirmed active-scan vuln classes (Theme E / E3). When the active engine
# (Nuclei/ZAP) *sends a payload and it matches*, the resulting finding is proof,
# not theory — so it becomes a **confirmed** edge that walks at full feasibility
# and outranks merely-modeled paths. Each class lists title-keyword markers
# (matched first) and MITRE technique IDs (exact-match fallback), then the
# attacker state it grants and the edge label. Order is precedence.
_ACTIVE_VULN_CLASSES: list[tuple[tuple[str, ...], tuple[str, ...], str, str]] = [
    (("rce", "remote code", "code execution", "command injection", "ssti",
      "template injection", "deserial", "log4j", "spring4shell"),
     ("T1059",), "code_exec", "confirmed RCE"),
    (("sql injection", "sqli"),
     ("T1059.003",), "data_access", "confirmed SQL injection"),
    (("lfi", "local file", "path traversal", "directory traversal",
      "file read", "arbitrary file", "xxe"),
     ("T1083",), "data_access", "confirmed file read"),
    (("ssrf", "server-side request"),
     ("T1090.002",), "recon", "confirmed SSRF (internal reach)"),
    (("xss", "cross-site scripting", "cross site scripting"),
     ("T1059.007",), "session_hijack", "confirmed XSS → cookie/session theft"),
    (("auth bypass", "authentication bypass", "default login",
      "default credential", "idor", "insecure direct object"),
     ("T1078",), "credentials", "confirmed access-control bypass"),
    (("exposure", "disclosure", "secret", "credential leak", "api key"),
     ("T1552",), "credentials", "confirmed secret exposure"),
]


# How feasible an edge is for an external attacker (1.0 = trivial). Edges that
# require an on-path position or a victim's interaction are harder, so paths that
# rely on them rank below remote/unauthenticated routes to the same objective.
def _edge_feasibility(frm: str, to: str, label: str) -> float:
    low = label.lower()
    if to == "on_path":
        return 0.4
    if to == "phishing":
        return 0.5
    if "xss" in low or "xst" in low or "clickjack" in low:
        return 0.6
    return 1.0


@dataclass(frozen=True)
class Edge:
    frm: str
    to: str
    label: str
    via: str = ""  # the misconfiguration/finding name that created the edge (if any)
    feasibility: float = 1.0
    confirmed: bool = False  # backed by a live active-scan match, not just modeled


@dataclass
class GoalPath:
    """A reachable objective and the shortest edge path that reaches it."""

    state: str
    value: int
    path: list[Edge] = field(default_factory=list)

    @property
    def label(self) -> str:
        return STATE_LABEL.get(self.state, self.state)

    @property
    def feasibility(self) -> float:
        """Cumulative feasibility of the path (product of its edges)."""
        score = 1.0
        for edge in self.path:
            score *= edge.feasibility
        return round(score, 3)

    @property
    def priority(self) -> int:
        """Objective value discounted by how feasible the path is to walk."""
        return round(self.value * self.feasibility)

    @property
    def confirmed(self) -> bool:
        """True when any edge on the path was proven by a live active-scan match."""
        return any(edge.confirmed for edge in self.path)


@dataclass
class AttackGraph:
    edges: list[Edge] = field(default_factory=list)
    reachable: set[str] = field(default_factory=set)
    goals: list[GoalPath] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.goals


def _all_candidate_edges(active_names: set[str]) -> list[Edge]:
    edges: list[Edge] = []
    for name, (frm, to, label) in _MISCONFIG_EDGES.items():
        if name in active_names:
            edges.append(Edge(frm, to, label, via=name, feasibility=_edge_feasibility(frm, to, label)))
    for names, (frm, to, label) in _COMBO_EDGES:
        if all(n in active_names for n in names):
            edges.append(Edge(frm, to, label, via=" + ".join(names), feasibility=_edge_feasibility(frm, to, label)))
    for frm, to, label in _CONSEQUENCE_EDGES:
        edges.append(Edge(frm, to, label, feasibility=_edge_feasibility(frm, to, label)))
    return edges


def _classify_active(finding: "Finding") -> tuple[str, str] | None:
    """Map a confirmed active-scan finding to the (state, label) it grants.

    Title keywords take precedence over MITRE technique IDs so the strongest
    available signal wins. Returns ``None`` for findings that don't correspond to
    a modeled attacker capability.
    """
    title = finding.title.lower()
    for title_markers, _mitre, to_state, label in _ACTIVE_VULN_CLASSES:
        if any(marker in title for marker in title_markers):
            return to_state, label
    techniques = set(finding.mitre_techniques)
    for _title, mitre_markers, to_state, label in _ACTIVE_VULN_CLASSES:
        if any(tech in techniques for tech in mitre_markers):
            return to_state, label
    return None


def _active_finding_edges(report: "ScanReport") -> list[Edge]:
    """Confirmed edges contributed by active-scan (Nuclei/ZAP) findings.

    Active findings exist only because an external engine sent a payload and it
    matched, so each becomes a confirmed external→objective edge at full
    feasibility. Deduplicated by (state, label) so one template matched on many
    URLs adds a single edge.
    """
    from models import FindingCategory

    edges: list[Edge] = []
    seen: set[tuple[str, str]] = set()
    for f in report.findings:
        if f.category != FindingCategory.VULNERABILITY:
            continue
        classified = _classify_active(f)
        if classified is None:
            continue
        to_state, label = classified
        key = (to_state, label)
        if key in seen:
            continue
        seen.add(key)
        edges.append(Edge("external", to_state, label, via=f.title, feasibility=1.0, confirmed=True))
    return edges


def _bfs_reachable(edges: list[Edge]) -> tuple[set[str], dict[str, Edge]]:
    """Return reachable states and the predecessor edge used to first reach each."""
    adjacency: dict[str, list[Edge]] = {}
    for e in edges:
        adjacency.setdefault(e.frm, []).append(e)
    reachable = {START}
    predecessor: dict[str, Edge] = {}
    queue: deque[str] = deque([START])
    while queue:
        state = queue.popleft()
        for edge in adjacency.get(state, []):
            if edge.to not in reachable:
                reachable.add(edge.to)
                predecessor[edge.to] = edge
                queue.append(edge.to)
    return reachable, predecessor


def _path_to(state: str, predecessor: dict[str, Edge]) -> list[Edge]:
    path: list[Edge] = []
    cur = state
    while cur in predecessor:
        edge = predecessor[cur]
        path.append(edge)
        cur = edge.frm
    path.reverse()
    return path


def build_attack_graph(report: "ScanReport") -> AttackGraph:
    """Build the attacker-state graph for a scan report."""
    active_names = {mc.name for mc in report.misconfigurations}
    candidates = _all_candidate_edges(active_names)
    candidates += _active_finding_edges(report)
    # Prefer confirmed edges as BFS predecessors so a proven route to a state is
    # the one reported (stable sort keeps modeled-edge ordering otherwise).
    candidates.sort(key=lambda e: not e.confirmed)
    reachable, predecessor = _bfs_reachable(candidates)

    # Only keep edges whose source state is actually reachable.
    active_edges = [e for e in candidates if e.frm in reachable]

    goals = [
        GoalPath(state=state, value=GOAL_VALUE[state], path=_path_to(state, predecessor))
        for state in reachable
        if state in GOAL_VALUE
    ]
    # Confirmed (live-proven) objectives rank above merely-modeled ones; within
    # each tier, by feasibility-discounted value — a remote/unauth route to a
    # high-value objective beats one needing an on-path position or victim action.
    goals.sort(key=lambda g: (0 if g.confirmed else 1, -g.priority, -g.value, len(g.path)))

    return AttackGraph(edges=active_edges, reachable=reachable, goals=goals)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _mermaid_id(state: str) -> str:
    return state.replace("-", "_")


def to_mermaid(graph: AttackGraph) -> str:
    """Render the graph as a Mermaid ``flowchart LR`` definition.

    Goal nodes are styled distinctly so the objectives stand out.
    """
    lines = ["flowchart LR"]
    for state in sorted(graph.reachable):
        label = STATE_LABEL.get(state, state)
        lines.append(f'    {_mermaid_id(state)}["{label}"]')
    for e in graph.edges:
        if e.frm in graph.reachable and e.to in graph.reachable:
            safe = e.label.replace('"', "'")
            # Confirmed (live-proven) edges render thick and flagged.
            arrow = "==>" if e.confirmed else "-->"
            prefix = "✓ " if e.confirmed else ""
            lines.append(f'    {_mermaid_id(e.frm)} {arrow}|"{prefix}{safe}"| {_mermaid_id(e.to)}')
    # Style start and goal nodes.
    lines.append(f"    style {_mermaid_id(START)} fill:#e2e8f0,stroke:#475569")
    for goal in graph.goals:
        lines.append(
            f"    style {_mermaid_id(goal.state)} fill:#fee2e2,stroke:#dc2626,color:#7f1d1d"
        )
    return "\n".join(lines)


def attack_story(report: "ScanReport", *, narrator: "object | None" = None) -> str:
    """Narrate the single most dangerous reachable attack path in plain English.

    Deterministic by default: stitches the top-priority objective's shortest path
    (from :func:`build_attack_graph`) together with the matching misconfiguration's
    attack scenario for color. Pass ``narrator`` (a callable taking a prompt
    string and returning prose) to delegate phrasing to an LLM; the tool stays
    fully offline when it is omitted.
    """
    import reachability

    graph = build_attack_graph(report)
    if graph.empty:
        return ""
    top = graph.goals[0]

    scenarios = {mc.name: mc.attack_scenario for mc in report.misconfigurations if mc.attack_scenario}

    if callable(narrator):
        prompt = _story_prompt(report.target, top, scenarios)
        return str(narrator(prompt))

    effort = reachability.feasibility_label(top.feasibility)
    parts: list[str] = [
        f"Against {report.target}, the most dangerous reachable objective is "
        f"\"{top.label}\" (attacker value {top.value}/100, {effort} to carry out)."
    ]
    if top.confirmed:
        parts.append(
            "This path is confirmed exploitable — an active-scan payload matched "
            "it live, so it is proven, not merely modeled."
        )
    if top.path:
        steps: list[str] = []
        for i, edge in enumerate(top.path):
            lead = "Starting from an external position, the attacker uses" if i == 0 else "Then they use"
            steps.append(f"{lead} {edge.label} to reach {STATE_LABEL.get(edge.to, edge.to).lower()}.")
        parts.append(" ".join(steps))
        # Add the concrete scenario behind the first enabling weakness, if known.
        first_via = top.path[0].via
        scenario = scenarios.get(first_via.split(" + ")[0]) if first_via else ""
        if scenario:
            parts.append(f"Concretely: {scenario}")
    if len(graph.goals) > 1:
        others = ", ".join(g.label.lower() for g in graph.goals[1:4])
        parts.append(f"Other reachable objectives include {others}.")
    return " ".join(parts)


def _story_prompt(target: str, top: GoalPath, scenarios: dict[str, str]) -> str:
    """Build a structured prompt describing the top path for an LLM narrator."""
    path = " -> ".join([STATE_LABEL[START]] + [STATE_LABEL.get(e.to, e.to) for e in top.path])
    edges = "; ".join(f"{e.label} ({e.via})" if e.via else e.label for e in top.path)
    return (
        f"Write a short executive paragraph describing how an attacker compromises {target}.\n"
        f"Objective: {top.label} (value {top.value}).\n"
        f"State path: {path}\n"
        f"Enabling weaknesses: {edges}\n"
        f"Scenario notes: {' | '.join(scenarios.values())}"
    )


def summary_lines(graph: AttackGraph) -> list[str]:
    """Plain-text summary of reachable objectives and their shortest paths."""
    if graph.empty:
        return ["  No attacker objectives are reachable from the current findings."]
    import reachability
    out: list[str] = []
    for goal in graph.goals:
        effort = reachability.feasibility_label(goal.feasibility)
        proven = "  [CONFIRMED via active scan]" if goal.confirmed else ""
        out.append(f"  [priority {goal.priority:>3}] {goal.label}  (value {goal.value}, {effort} to reach){proven}")
        if goal.path:
            chain = "external"
            for edge in goal.path:
                chain += f" --({edge.label})--> {STATE_LABEL.get(edge.to, edge.to)}"
            out.append(f"        path: {chain}")
    return out
