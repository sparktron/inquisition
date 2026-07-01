"""Core data models for scan configuration, findings, and reports."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanDepth(enum.Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class Confidence(enum.Enum):
    """How sure the scanner is that a finding is real.

    Deterministic observations (a header is present, a port answered, a cert
    expired) are CONFIRMED. Heuristic/signature matches carry HIGH/MEDIUM/LOW
    so the report can communicate certainty instead of overclaiming.
    """

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReportFormat(enum.Enum):
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"
    MARKDOWN = "markdown"


# Severity ranking, most to least severe. Used for thresholds (--fail-on) and
# for finding the highest severity present in a report.
SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]


def severity_at_least(value: Severity, threshold: Severity) -> bool:
    """Return True if ``value`` is at least as severe as ``threshold``."""
    return SEVERITY_ORDER.index(value) <= SEVERITY_ORDER.index(threshold)


# Confidence ranking, most to least certain.
CONFIDENCE_ORDER: list[Confidence] = [
    Confidence.CONFIRMED, Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW,
]


def combine_confidence(confidences: list[Confidence]) -> Confidence:
    """Merge corroborating signals into a single confidence.

    Takes the strongest individual signal, then promotes it one tier when two or
    more independent signals agree (a single weak hint stays weak; two weak hints
    that point at the same conclusion are worth more than either alone).
    """
    if not confidences:
        return Confidence.LOW
    best_index = min(CONFIDENCE_ORDER.index(c) for c in confidences)
    if len(confidences) >= 2 and best_index > 0:
        best_index -= 1
    return CONFIDENCE_ORDER[best_index]


class FindingCategory(enum.Enum):
    DNS = "dns"
    PORT = "port"
    TLS = "tls"
    HTTP_HEADER = "http_header"
    TECH_STACK = "tech_stack"
    APPLICATION = "application"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScanConfig:
    """Immutable scan configuration built from CLI flags."""

    target: str
    depth: ScanDepth = ScanDepth.STANDARD
    report_format: ReportFormat = ReportFormat.TEXT
    max_threads: int = 10
    safe_mode: bool = True
    dry_run: bool = False
    rate_limit: float = 0.1  # seconds between requests
    timeout: float = 10.0  # per-request timeout in seconds
    connect_timeout: float = 2.0  # TCP connect timeout in seconds
    ports: tuple[int, ...] = (
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
    )
    # Active testing (Phase 4) — OFF by default. When True, Inquisition may send
    # active payloads (via an external engine such as Nuclei). This crosses the
    # read-only boundary and requires explicit authorization.
    active: bool = False
    active_engine: str = "nuclei"
    # PoC auto-validation (Theme E / E1) — OFF by default. When True, the
    # read-only verification subset of each finding's ``poc_command`` (curl -sI,
    # dig, openssl s_client, status probes) is executed to capture live evidence
    # and upgrade modeled findings to confirmed. Mutating PoCs are never run.
    validate_poc: bool = False
    # Authenticated scanning — credentials injected into every HTTP request so
    # modules and the active engine see the logged-in surface.
    auth_header: str = ""   # e.g. "Authorization: Bearer <token>"
    auth_cookie: str = ""   # e.g. "session=<value>; other=<value>"
    # Internal scanner handoff: populated after the crawler pre-discovery pass
    # so path-aware modules can inspect real site URLs, not only fixed lists.
    discovered_urls: tuple[str, ...] = ()
    # SLA alerting: warn/notify when a finding has stayed open beyond this many
    # consecutive scans (0 = disabled). ``sla_severity_overrides`` sets stricter
    # per-severity thresholds (e.g. critical=2); the global value is the fallback.
    sla_max_age: int = 0
    sla_severity_overrides: tuple[tuple[str, int], ...] = ()
    # Report rendering options
    attacker_pov: bool = False  # reorder findings by exploitability for attacker perspective
    # Fleet crown-jewel tagging (Theme D / D2): the business value of this target,
    # one of crown/high/medium/low (or "" = unset). Drives blast-radius analysis,
    # which ranks remediation by the high-value assets a weak host endangers.
    asset_value: str = ""


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single observation produced by a fingerprinting module."""

    title: str
    category: FindingCategory
    severity: Severity
    evidence: str
    impact: str = ""
    remediation: str = ""
    verification: str = ""
    cpe: str = ""
    confidence: Confidence = Confidence.CONFIRMED
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Cross-scan age, populated from the persisted state on non-dry-run scans.
    first_seen: str = ""   # ISO timestamp this finding was first observed
    age_scans: int = 0     # consecutive scans this finding has been present (incl. current)
    # Attack-context fields populated from the knowledge base.
    attack_scenario: str = ""          # step-by-step attacker exploitation narrative
    mitre_techniques: list[str] = field(default_factory=list)  # e.g. ["T1557", "T1040"]
    poc_command: str = ""              # illustrative command/payload an attacker would use
    # Reachability / preconditions — what an attacker needs to actually use this.
    # ``network_position`` is one of reachability.NetworkPosition values
    # ("remote", "adjacent", "on_path", "local"). These weight the attack graph
    # so a remote/unauth issue outranks one that needs a privileged position.
    network_position: str = "remote"
    auth_required: bool = False        # attacker needs valid credentials first
    user_interaction: bool = False     # exploitation needs a victim to act (click, visit)
    preconditions: list[str] = field(default_factory=list)  # free-form notes


def is_active_scan_finding(finding: "Finding") -> bool:
    """True when a finding was produced by the active-scan engine (Nuclei/ZAP).

    Active findings are proof — an external engine sent a payload and it matched
    — so consumers (provenance, the attack graph) treat them as confirmed rather
    than modeled. The canonical signal is ``metadata["active_scan"]``, stamped at
    creation in ``active_scan.py``. The legacy ``"[active] "`` title prefix is
    accepted as a fallback so snapshots persisted before the flag existed still
    classify correctly.
    """
    if finding.metadata.get("active_scan"):
        return True
    return finding.title.lower().startswith("[active]")


# ---------------------------------------------------------------------------
# Vulnerability / CVE correlation
# ---------------------------------------------------------------------------

@dataclass
class CVERecord:
    cve_id: str
    description: str
    severity: Severity
    cvss_score: float = 0.0
    references: list[str] = field(default_factory=list)
    days_since_disclosure: int = 0  # days between published date and scan date
    in_cisa_kev: bool = False        # True when CVE appears in CISA Known Exploited Vulnerabilities catalog
    # Exploitability intelligence (Theme A). EPSS is the FIRST.org-published
    # probability [0,1] that a CVE will be exploited in the next 30 days, with a
    # percentile rank against all scored CVEs. ``exploit_public`` is True when a
    # public exploit/PoC is known to exist, with ``exploit_sources`` naming where.
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    exploit_public: bool = False
    exploit_sources: list[str] = field(default_factory=list)
    # Clickable (label, url) pairs pointing at where a PoC/exploit can be found —
    # Exploit-DB / GitHub code search always present, a Metasploit module link when
    # a local Metasploit checkout has one, NVD references surfaced alongside.
    exploit_links: list[tuple[str, str]] = field(default_factory=list)


def cve_priority(cve: "CVERecord") -> tuple[int, int, float, float]:
    """Sort key (descending) ranking a CVE by real-world exploitation risk.

    KEV membership (known exploited in the wild) dominates, then public-exploit
    availability, then EPSS probability, then raw CVSS. Use with
    ``sorted(..., key=cve_priority, reverse=True)`` so the CVEs an attacker is
    most likely to actually use rise to the top.
    """
    return (
        1 if cve.in_cisa_kev else 0,
        1 if cve.exploit_public else 0,
        cve.epss_score,
        cve.cvss_score,
    )


@dataclass
class IntelSource:
    """Freshness/provenance of one threat-intel feed used during a scan (F1).

    Stale intel in a security tool is a silent false-negative, so each external
    source records when its data is current as of, plus a short detail (catalog
    version, item count) for the report's "Threat Intelligence" section.
    """

    name: str                # e.g. "CISA KEV", "FIRST.org EPSS", "Nuclei templates"
    as_of: str = ""          # human date/time the data is current as of ("" = unknown)
    detail: str = ""         # e.g. "catalog 2026.06.01", "fetched live"
    item_count: int = 0      # number of records the source contributed
    stale: bool = False      # True when the data is older than its freshness budget


@dataclass
class MisconfigurationCheck:
    """A detected misconfiguration with a risk rating."""

    name: str
    description: str
    severity: Severity
    evidence: str
    remediation: str
    attack_scenario: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    poc_command: str = ""


# ---------------------------------------------------------------------------
# Tool reference mapping
# ---------------------------------------------------------------------------

TOOL_REFERENCE: dict[FindingCategory, list[str]] = {
    FindingCategory.DNS: ["Nmap (dns-brute)", "dnsrecon", "dig"],
    FindingCategory.PORT: ["Nmap", "masscan", "Rustscan"],
    FindingCategory.TLS: ["testssl.sh", "sslyze", "Nmap (ssl-enum-ciphers)"],
    FindingCategory.HTTP_HEADER: ["Nuclei", "ZAP", "curl"],
    FindingCategory.TECH_STACK: ["WPScan", "Wappalyzer", "WhatWeb", "BuiltWith"],
    FindingCategory.APPLICATION: ["Nuclei", "ZAP", "Nikto"],
    FindingCategory.VULNERABILITY: ["Nuclei", "Nmap NSE", "ZAP"],
    FindingCategory.MISCONFIGURATION: ["Nuclei", "Scout Suite", "Prowler"],
}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    """Complete scan report combining all module results."""

    target: str
    started_at: datetime
    finished_at: datetime | None = None
    config: ScanConfig | None = None
    findings: list[Finding] = field(default_factory=list)
    cve_records: list[CVERecord] = field(default_factory=list)
    misconfigurations: list[MisconfigurationCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    report_path: str = ""  # filesystem path the rendered report was written to
    # Rolling trend window for this target (chronological compact snapshots:
    # {taken_at, total, counts}). Empty on dry runs / first scan.
    history: list[dict[str, Any]] = field(default_factory=list)
    # Attack chains detected from the combination of misconfigurations present.
    attack_chains: list[Any] = field(default_factory=list)
    # Threat-intel freshness/provenance for the feeds consulted this scan (F1).
    intel_sources: list[IntelSource] = field(default_factory=list)

    # Convenience helpers -----------------------------------------------

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    def summary_counts(self) -> dict[str, int]:
        by_sev = self.findings_by_severity()
        return {s.value: len(fs) for s, fs in by_sev.items()}

    def highest_severity(self) -> Severity | None:
        """Return the most severe finding severity present, or None if empty."""
        present = {f.severity for f in self.findings}
        for sev in SEVERITY_ORDER:
            if sev in present:
                return sev
        return None
