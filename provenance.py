"""Provenance of attacker claims (Theme F / F2).

Inquisition makes assertions about how an attacker would exploit a finding — an
``attack_scenario``, a ``poc_command``, a chain, a reachable attack-graph goal.
Those assertions come from very different places, and a reader must be able to
tell them apart: a step *modeled* from the static knowledge base is a hypothesis,
while one *confirmed* by a live read-only probe or an active-scan payload match is
proof. Conflating the two is how a security report overclaims.

This module assigns each finding's attacker claim a small provenance record —
*modeled* (knowledge base) vs *confirmed* (live PoC validation or active scan) —
so the report renderers and the attack story can label every claim with where it
came from. It pairs with E2 (evidence bundles): E2 attaches the evidence, F2 says
what kind of evidence it is.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from models import FindingCategory, is_active_scan_finding

if TYPE_CHECKING:
    from models import Finding

# Provenance tiers, weakest to strongest.
MODELED = "modeled"      # asserted from the static knowledge base / rules
CONFIRMED = "confirmed"  # proven against the live target


@dataclass(frozen=True)
class ClaimProvenance:
    """Where a finding's attacker claim came from."""

    tier: str       # MODELED | CONFIRMED
    source: str     # "knowledge base" | "live PoC validation" | "active scan"
    label: str      # short human-readable badge text

    @property
    def confirmed(self) -> bool:
        return self.tier == CONFIRMED


_LIVE_VALIDATION = ClaimProvenance(
    CONFIRMED, "live PoC validation", "Confirmed — live PoC validation"
)
_ACTIVE_SCAN = ClaimProvenance(
    CONFIRMED, "active scan", "Confirmed — active-scan payload match"
)
_KNOWLEDGE_BASE = ClaimProvenance(
    MODELED, "knowledge base", "Modeled — knowledge base"
)


def finding_provenance(finding: "Finding") -> ClaimProvenance | None:
    """Classify the provenance of a finding's attacker claim.

    Returns ``None`` when the finding carries no attacker claim (no scenario,
    PoC, or technique mapping) — there is nothing to attribute. Strongest
    available evidence wins: a live-validated PoC, then an active-scan match,
    then a modeled knowledge-base assertion.
    """
    bundle = finding.metadata.get("poc_validation")
    if isinstance(bundle, dict) and bundle.get("confirmed"):
        return _LIVE_VALIDATION

    if (
        finding.category == FindingCategory.VULNERABILITY
        and is_active_scan_finding(finding)
    ):
        return _ACTIVE_SCAN

    if finding.attack_scenario or finding.poc_command or finding.mitre_techniques:
        return _KNOWLEDGE_BASE

    return None
