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


class ReportFormat(enum.Enum):
    TEXT = "text"
    JSON = "json"
    HTML = "html"


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
    ports: tuple[int, ...] = (
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
    )


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
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


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


@dataclass
class MisconfigurationCheck:
    """A detected misconfiguration with a risk rating."""

    name: str
    description: str
    severity: Severity
    evidence: str
    remediation: str


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

    # Convenience helpers -----------------------------------------------

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    def summary_counts(self) -> dict[str, int]:
        by_sev = self.findings_by_severity()
        return {s.value: len(fs) for s, fs in by_sev.items()}
