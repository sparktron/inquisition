"""Fleet-level cross-target correlation (Theme D / D1).

Per-target scans answer "how secure is *this* host?". A fleet of related targets
(same org, configured together via ``--targets-file`` / ``--fleet-config``) has a
second, larger question: **how does one weak host endanger the rest?** This module
connects the independent per-target reports into an *org-level* view by spotting
shared infrastructure and trust relationships that turn a single foothold into a
fleet-wide problem:

* **Shared origin IP** — two or more targets resolve to the same address, so they
  are very likely co-hosted; compromising that one host yields all of them and a
  pivot between them.
* **Shared TLS certificate** — targets presenting the identical certificate share
  a private key (or a wildcard/multi-SAN cert), so one key compromise impersonates
  every target that uses it.
* **Subdomain-takeover pivot** — a takeover-able target lets an attacker serve
  attacker-controlled content from a name the org's users (and same-site security
  controls) already trust, enabling phishing and same-org trust abuse against its
  siblings.

The correlation is derived purely from signals already present in the findings
(no new network traffic), so it is deterministic and unit-testable from synthetic
reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from models import Severity

if TYPE_CHECKING:
    from models import ScanReport

# Relative attacker value of each cross-target relationship, mirroring the
# attack-graph weighting: co-hosting (one box = many sites + pivot) is worst,
# then a takeover pivot into the trusted org perimeter, then a shared key.
_LINK_VALUE: dict[str, int] = {
    "shared_ip": 80,
    "takeover_pivot": 70,
    "shared_cert": 60,
}

_LINK_SEVERITY: dict[str, Severity] = {
    "shared_ip": Severity.HIGH,
    "takeover_pivot": Severity.HIGH,
    "shared_cert": Severity.MEDIUM,
}

_LINK_LABEL: dict[str, str] = {
    "shared_ip": "Shared origin IP (co-hosted)",
    "takeover_pivot": "Subdomain-takeover pivot",
    "shared_cert": "Shared TLS certificate",
}

_SHA256_RE = re.compile(r"SHA-?256:\s*([0-9a-fA-F]{64})")
_RESOLVES_RE = re.compile(r"resolves to:\s*(.+)$")


@dataclass(frozen=True)
class CrossTargetLink:
    """A relationship that lets a weakness on one target endanger others."""

    kind: str                       # shared_ip | shared_cert | takeover_pivot
    targets: tuple[str, ...]        # the targets the link spans
    shared: str                     # the shared artifact (IP, cert fp, takeover host)
    detail: str                     # human-readable explanation
    attack_note: str                # how an attacker abuses the relationship

    @property
    def value(self) -> int:
        return _LINK_VALUE.get(self.kind, 0)

    @property
    def severity(self) -> Severity:
        return _LINK_SEVERITY.get(self.kind, Severity.INFO)

    @property
    def label(self) -> str:
        return _LINK_LABEL.get(self.kind, self.kind)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "label": self.label,
            "targets": list(self.targets),
            "shared": self.shared,
            "detail": self.detail,
            "attack_note": self.attack_note,
            "severity": self.severity.value,
            "value": self.value,
        }


def _target_ips(report: "ScanReport") -> set[str]:
    """Resolved IP addresses for a target, parsed from its DNS findings."""
    ips: set[str] = set()
    for f in report.findings:
        if f.title == "DNS A/AAAA records":
            m = _RESOLVES_RE.search(f.evidence)
            if m:
                ips.update(p.strip() for p in m.group(1).split(",") if p.strip())
    return ips


def _target_cert_fingerprints(report: "ScanReport") -> set[str]:
    """SHA-256 certificate fingerprints presented by a target."""
    fps: set[str] = set()
    for f in report.findings:
        if f.title == "Certificate fingerprint":
            m = _SHA256_RE.search(f.evidence)
            if m:
                fps.add(m.group(1).lower())
    return fps


def _has_takeover(report: "ScanReport") -> bool:
    return any(
        f.title.lower().startswith("potential subdomain takeover")
        for f in report.findings
    )


def _group_links(
    kind: str,
    attribute: dict[str, set[str]],
    *,
    detail: str,
    attack_note: str,
) -> list[CrossTargetLink]:
    """Emit one link per shared attribute value held by 2+ targets."""
    by_value: dict[str, list[str]] = {}
    for target, values in attribute.items():
        for value in values:
            by_value.setdefault(value, []).append(target)

    links: list[CrossTargetLink] = []
    for value, targets in sorted(by_value.items()):
        unique = sorted(set(targets))
        if len(unique) < 2:
            continue
        links.append(CrossTargetLink(
            kind=kind,
            targets=tuple(unique),
            shared=value,
            detail=detail.format(value=value, targets=", ".join(unique)),
            attack_note=attack_note,
        ))
    return links


def correlate_fleet(reports: list["ScanReport"]) -> list[CrossTargetLink]:
    """Find cross-target relationships across a fleet of scan reports.

    Returns links ordered by attacker value (worst first). Returns an empty list
    for a single-target run (nothing to correlate).
    """
    if len(reports) < 2:
        return []

    ip_by_target = {r.target: _target_ips(r) for r in reports}
    cert_by_target = {r.target: _target_cert_fingerprints(r) for r in reports}

    links: list[CrossTargetLink] = []
    links += _group_links(
        "shared_ip", ip_by_target,
        detail="{targets} all resolve to {value}",
        attack_note=(
            "These targets are co-hosted on one machine — compromising that host "
            "yields every site on it and a pivot between them."
        ),
    )
    links += _group_links(
        "shared_cert", cert_by_target,
        detail="{targets} present the same TLS certificate ({value})",
        attack_note=(
            "A shared certificate means a shared private key — stealing it lets an "
            "attacker impersonate every target that uses it."
        ),
    )

    # Subdomain-takeover pivot: a takeover-able target can serve attacker content
    # from a name the rest of the fleet's users and same-org controls trust.
    takeover_targets = sorted(r.target for r in reports if _has_takeover(r))
    siblings = sorted(r.target for r in reports)
    for taken in takeover_targets:
        others = [t for t in siblings if t != taken]
        if not others:
            continue
        links.append(CrossTargetLink(
            kind="takeover_pivot",
            targets=tuple([taken] + others),
            shared=taken,
            detail=f"{taken} is takeover-able and shares the org trust boundary with {', '.join(others)}",
            attack_note=(
                "Claiming the dangling host lets an attacker serve trusted-origin "
                "content for phishing and same-org trust abuse against its siblings."
            ),
        ))

    links.sort(key=lambda link: (-link.value, link.kind, link.shared))
    return links


@dataclass
class FleetCorrelation:
    """Container for the cross-target analysis of a fleet run."""

    links: list[CrossTargetLink] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.links

    def as_dict(self) -> dict[str, object]:
        return {"links": [link.as_dict() for link in self.links]}


def analyze(reports: list["ScanReport"]) -> FleetCorrelation:
    """Convenience wrapper returning a :class:`FleetCorrelation`."""
    return FleetCorrelation(links=correlate_fleet(reports))
