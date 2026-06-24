"""Data-driven attack knowledge base: misconfiguration rules and attack chains.

The misconfiguration rules and multi-step attack chains live as structured YAML
data (``modules/data/*.yaml``) rather than hardcoded Python, so the knowledge
base can grow and be audited without touching logic.

Attack chains are matched by a small **predicate DSL** instead of brittle
exact-string coupling. Each chain lists ``requires`` conditions; a chain
triggers when *every* condition is satisfied by the current set of
misconfigurations and findings. A condition is a dict with one or more of:

* ``misconfig``      — an active misconfiguration with this exact name
* ``category``       — a finding in this category (e.g. ``"port"``)
* ``title_contains`` — a finding whose title contains this substring (ci)
* ``min_severity``   — restrict the above to findings at least this severe
* ``cpe_contains``   — a finding whose CPE contains this substring (ci)
* ``mitre``          — a finding/misconfig tagged with this ATT&CK technique

Conditions combine their own keys with AND; the list of conditions also ANDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import TYPE_CHECKING, Any

import yaml  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from vuln_correlation import AttackChain

from models import (
    Finding,
    FindingCategory,
    MisconfigurationCheck,
    Severity,
    severity_at_least,
)

_MISCONFIG_RESOURCE = "data/misconfig_rules.yaml"
_CHAINS_RESOURCE = "data/attack_chains.yaml"


# ---------------------------------------------------------------------------
# Loading + validation
# ---------------------------------------------------------------------------

def _load_yaml(resource: str) -> Any:
    data_path = resources.files("modules").joinpath(resource)
    return yaml.safe_load(data_path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_misconfig_rules() -> tuple[dict[str, Any], ...]:
    """Load and validate misconfiguration rules from structured data."""
    raw = _load_yaml(_MISCONFIG_RESOURCE)
    if not isinstance(raw, list):
        raise ValueError("misconfig_rules.yaml must be a list of rules")
    rules: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each misconfiguration rule must be a mapping")
        for key in ("categories", "title_contains", "name", "description", "severity", "remediation"):
            if key not in item:
                raise ValueError(f"misconfiguration rule missing required field {key!r}")
        rules.append({
            "categories": [FindingCategory(c) for c in item["categories"]],
            "title_contains": str(item["title_contains"]),
            "name": str(item["name"]),
            "description": str(item["description"]),
            "severity": Severity(item["severity"]),
            "remediation": str(item["remediation"]),
            "attack_scenario": str(item.get("attack_scenario", "")),
            "mitre_techniques": list(item.get("mitre_techniques", [])),
            "poc_command": str(item.get("poc_command", "")),
        })
    return tuple(rules)


@dataclass(frozen=True)
class Condition:
    """A single predicate over the active misconfigurations and findings."""

    misconfig: str = ""
    category: str = ""
    title_contains: str = ""
    min_severity: str = ""
    cpe_contains: str = ""
    mitre: str = ""

    def matches(self, misconfigs: list[MisconfigurationCheck], findings: list[Finding]) -> bool:
        if self.misconfig:
            if not any(mc.name == self.misconfig for mc in misconfigs):
                return False
        # Finding-attribute predicates only apply when at least one is set.
        if self.category or self.title_contains or self.cpe_contains or self.mitre or self.min_severity:
            threshold = Severity(self.min_severity) if self.min_severity else None
            if not any(self._finding_ok(f, threshold) for f in findings):
                return False
        return True

    def _finding_ok(self, f: Finding, threshold: Severity | None) -> bool:
        if self.category and f.category.value != self.category:
            return False
        if self.title_contains and self.title_contains.lower() not in f.title.lower():
            return False
        if self.cpe_contains and self.cpe_contains.lower() not in f.cpe.lower():
            return False
        if self.mitre and self.mitre not in f.mitre_techniques:
            return False
        if threshold is not None and not severity_at_least(f.severity, threshold):
            return False
        return True


@dataclass(frozen=True)
class ChainRule:
    """A chain definition plus the conditions that must all hold to trigger it."""

    chain: "AttackChain"  # imported under TYPE_CHECKING to avoid an import cycle
    conditions: tuple[Condition, ...] = field(default_factory=tuple)

    def triggered(self, misconfigs: list[MisconfigurationCheck], findings: list[Finding]) -> bool:
        return all(c.matches(misconfigs, findings) for c in self.conditions)


_CONDITION_KEYS = {"misconfig", "category", "title_contains", "min_severity", "cpe_contains", "mitre"}


@lru_cache(maxsize=1)
def load_chain_rules() -> tuple[ChainRule, ...]:
    """Load and validate attack-chain rules from structured data."""
    from vuln_correlation import AttackChain  # lazy: avoids an import cycle

    raw = _load_yaml(_CHAINS_RESOURCE)
    if not isinstance(raw, list):
        raise ValueError("attack_chains.yaml must be a list of chains")
    rules: list[ChainRule] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each attack chain must be a mapping")
        for key in ("name", "description", "steps", "requires"):
            if key not in item:
                raise ValueError(f"attack chain missing required field {key!r}")
        conditions: list[Condition] = []
        for cond in item["requires"]:
            if not isinstance(cond, dict):
                raise ValueError("each chain condition must be a mapping")
            unknown = set(cond) - _CONDITION_KEYS
            if unknown:
                raise ValueError(f"unknown chain condition field(s): {sorted(unknown)}")
            conditions.append(Condition(**{k: str(v) for k, v in cond.items()}))
        chain = AttackChain(
            name=str(item["name"]),
            description=str(item["description"]),
            steps=list(item["steps"]),
            mitre_techniques=list(item.get("mitre_techniques", [])),
            required_misconfig_names=[c.misconfig for c in conditions if c.misconfig],
        )
        rules.append(ChainRule(chain=chain, conditions=tuple(conditions)))
    return tuple(rules)
