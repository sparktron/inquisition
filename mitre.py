"""MITRE ATT&CK mapping, coverage, and Navigator layer export.

Findings, misconfigurations, and attack chains carry ATT&CK technique IDs. This
module supplies the technique metadata (name + tactic), resolves a technique set
for any finding (falling back to category-level defaults so every meaningful
finding is mapped), aggregates a per-scan coverage view, and serializes a
`MITRE ATT&CK Navigator <https://mitre-attack.github.io/attack-navigator/>`_
layer JSON so findings overlay on the standard matrix.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from models import FindingCategory, Severity

if TYPE_CHECKING:
    from models import Finding, ScanReport


# Technique ID -> (display name, primary ATT&CK tactic). Covers the techniques
# referenced by Inquisition's knowledge base; unknown IDs degrade gracefully via
# ``technique_name`` / ``technique_tactic``.
_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1040": ("Network Sniffing", "Credential Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.007": ("JavaScript", "Execution"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.004": ("Credential Stuffing", "Credential Access"),
    "T1185": ("Browser Session Hijacking", "Collection"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1204.001": ("User Execution: Malicious Link", "Execution"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1530": ("Data from Cloud Storage", "Collection"),
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
    "T1557.002": ("Adversary-in-the-Middle: ARP Cache Poisoning", "Credential Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1570": ("Lateral Tool Transfer", "Lateral Movement"),
    "T1584.001": ("Compromise Infrastructure: Domains", "Resource Development"),
    "T1590.002": ("Gather Victim Network Information: DNS", "Reconnaissance"),
    "T1608": ("Stage Capabilities", "Resource Development"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.005": ("Remote Services: VNC", "Lateral Movement"),
}

# Category-level fallback techniques, applied to any non-INFO finding that has no
# explicit techniques of its own, so coverage reflects the full attack surface.
_CATEGORY_TECHNIQUES: dict[FindingCategory, list[str]] = {
    FindingCategory.DNS: ["T1590.002"],
    FindingCategory.PORT: ["T1046"],
    FindingCategory.TLS: ["T1040"],
    FindingCategory.HTTP_HEADER: ["T1185"],
    FindingCategory.TECH_STACK: ["T1082"],
    FindingCategory.APPLICATION: ["T1190"],
    FindingCategory.VULNERABILITY: ["T1190"],
    FindingCategory.MISCONFIGURATION: ["T1190"],
}

# Canonical tactic ordering, kill-chain left to right.
TACTIC_ORDER: list[str] = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def technique_name(technique_id: str) -> str:
    """Human-readable name for a technique ID (the ID itself if unknown)."""
    entry = _TECHNIQUES.get(technique_id)
    return entry[0] if entry else technique_id


def technique_tactic(technique_id: str) -> str:
    """Primary ATT&CK tactic for a technique ID ('Unknown' if unmapped)."""
    entry = _TECHNIQUES.get(technique_id)
    return entry[1] if entry else "Unknown"


def techniques_for_finding(finding: "Finding") -> list[str]:
    """Resolve the ATT&CK techniques for a finding.

    Explicit techniques (from the KB or misconfiguration rules) win. Otherwise a
    category-level default is used for any finding above INFO severity, so the
    coverage view is not blank for findings the KB does not enumerate.
    """
    if finding.mitre_techniques:
        return list(finding.mitre_techniques)
    if finding.severity is Severity.INFO:
        return []
    return list(_CATEGORY_TECHNIQUES.get(finding.category, []))


@dataclass
class TechniqueHit:
    """A technique observed in a scan, with how many findings exercised it."""

    technique_id: str
    name: str
    tactic: str
    count: int


def coverage(report: "ScanReport") -> list[TechniqueHit]:
    """Aggregate ATT&CK techniques across findings, misconfigs, and chains.

    Returns hits sorted by tactic kill-chain order, then by descending count.
    """
    counts: dict[str, int] = {}
    for f in report.findings:
        for tid in techniques_for_finding(f):
            counts[tid] = counts.get(tid, 0) + 1
    for mc in report.misconfigurations:
        for tid in mc.mitre_techniques:
            counts[tid] = counts.get(tid, 0) + 1
    for chain in report.attack_chains:
        for tid in getattr(chain, "mitre_techniques", []):
            counts[tid] = counts.get(tid, 0) + 1

    hits = [
        TechniqueHit(tid, technique_name(tid), technique_tactic(tid), n)
        for tid, n in counts.items()
    ]

    def _key(h: TechniqueHit) -> tuple[int, int]:
        tactic_rank = TACTIC_ORDER.index(h.tactic) if h.tactic in TACTIC_ORDER else len(TACTIC_ORDER)
        return (tactic_rank, -h.count)

    return sorted(hits, key=_key)


_NAVIGATOR_GRADIENT = ["#ffe8e8", "#ff6b6b", "#b30000"]


def build_navigator_layer(reports: list["ScanReport"], *, name: str = "") -> dict[str, object]:
    """Build a MITRE ATT&CK Navigator layer covering one or more scan reports.

    Technique scores are summed finding counts across all supplied reports, so a
    single layer can represent a whole fleet. Importable at
    https://mitre-attack.github.io/attack-navigator/.
    """
    counts: dict[str, int] = {}
    targets: list[str] = []
    for report in reports:
        targets.append(report.target)
        for hit in coverage(report):
            counts[hit.technique_id] = counts.get(hit.technique_id, 0) + hit.count

    max_score = max(counts.values(), default=0)
    techniques = [
        {
            "techniqueID": tid,
            "score": score,
            "comment": f"{technique_name(tid)} — {score} finding(s)",
            "enabled": True,
        }
        for tid, score in sorted(counts.items(), key=lambda kv: -kv[1])
    ]

    layer_name = name or ("Inquisition: " + ", ".join(targets[:3]) + ("…" if len(targets) > 3 else ""))
    return {
        "name": layer_name or "Inquisition ATT&CK Coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Observed attacker techniques mapped from Inquisition findings.",
        "techniques": techniques,
        "gradient": {
            "colors": _NAVIGATOR_GRADIENT,
            "minValue": 0,
            "maxValue": max_score if max_score > 0 else 1,
        },
        "legendItems": [
            {"label": "1 finding", "color": _NAVIGATOR_GRADIENT[0]},
            {"label": "most findings", "color": _NAVIGATOR_GRADIENT[-1]},
        ],
        "sorting": 3,
        "hideDisabled": False,
    }


def render_navigator_layer(reports: list["ScanReport"], *, name: str = "") -> str:
    """Serialize a Navigator layer (see :func:`build_navigator_layer`) to JSON."""
    return json.dumps(build_navigator_layer(reports, name=name), indent=2)
