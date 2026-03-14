"""Vulnerability correlation — CPE-based CVE lookup and misconfiguration checks."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import quote

import requests

from models import (
    CVERecord,
    Finding,
    FindingCategory,
    MisconfigurationCheck,
    Severity,
    TOOL_REFERENCE,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NVD API CVE lookup (public, rate-limited)
# ---------------------------------------------------------------------------

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_RATE_LIMIT = 6.0  # seconds between NVD calls (public API limit)


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def lookup_cves_for_cpe(cpe: str, timeout: float = 15.0) -> list[CVERecord]:
    """Query the NVD API for CVEs matching a CPE string.

    This is a best-effort lookup.  Returns an empty list on any error.
    """
    if not cpe:
        return []

    # Normalize partial CPEs
    cpe_match = cpe
    if not cpe_match.startswith("cpe:2.3:"):
        return []

    params: dict[str, str] = {
        "cpeName": cpe_match,
        "resultsPerPage": "10",
    }

    try:
        time.sleep(_NVD_RATE_LIMIT)  # respect rate limit
        resp = requests.get(
            _NVD_API,
            params=params,
            timeout=timeout,
            headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
        )
        if resp.status_code != 200:
            logger.debug("NVD API returned %d for CPE %s", resp.status_code, cpe)
            return []

        data: dict[str, Any] = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("NVD lookup failed for CPE %s: %s", cpe, exc)
        return []

    records: list[CVERecord] = []
    for vuln in data.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        cve_id = cve_item.get("id", "")
        descriptions = cve_item.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available",
        )

        # Extract CVSS score
        metrics = cve_item.get("metrics", {})
        score = 0.0
        for metric_version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_version, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                break

        refs = [
            r.get("url", "")
            for r in cve_item.get("references", [])[:5]
            if r.get("url")
        ]

        records.append(CVERecord(
            cve_id=cve_id,
            description=desc[:500],
            severity=_cvss_to_severity(score),
            cvss_score=score,
            references=refs,
        ))

    return records


# ---------------------------------------------------------------------------
# Misconfiguration checks derived from findings
# ---------------------------------------------------------------------------

_MISCONFIG_RULES: list[dict[str, Any]] = [
    {
        "categories": [FindingCategory.HTTP_HEADER],
        "title_contains": "Missing header: Strict-Transport-Security",
        "name": "HSTS not enabled",
        "description": "HTTP Strict Transport Security header missing",
        "severity": Severity.MEDIUM,
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
        "categories": [FindingCategory.HTTP_HEADER],
        "title_contains": "Missing header: Content-Security-Policy",
        "name": "CSP not configured",
        "description": "Content-Security-Policy header missing",
        "severity": Severity.MEDIUM,
        "remediation": "Implement a Content-Security-Policy that restricts script sources",
    },
    {
        "categories": [FindingCategory.TLS],
        "title_contains": "Deprecated TLS version",
        "name": "Legacy TLS enabled",
        "description": "Server supports deprecated TLS protocol versions",
        "severity": Severity.HIGH,
        "remediation": "Disable TLS 1.0 and TLS 1.1; require TLS 1.2+",
    },
    {
        "categories": [FindingCategory.TLS],
        "title_contains": "Self-signed certificate",
        "name": "Self-signed certificate in use",
        "description": "Certificate not issued by a trusted CA",
        "severity": Severity.MEDIUM,
        "remediation": "Obtain a certificate from a trusted CA (e.g. Let's Encrypt)",
    },
    {
        "categories": [FindingCategory.TLS],
        "title_contains": "Certificate EXPIRED",
        "name": "Expired TLS certificate",
        "description": "The TLS certificate has expired",
        "severity": Severity.CRITICAL,
        "remediation": "Renew the certificate immediately",
    },
    {
        "categories": [FindingCategory.TECH_STACK],
        "title_contains": ".env",
        "name": "Environment file publicly accessible",
        "description": ".env file exposed — may contain secrets",
        "severity": Severity.CRITICAL,
        "remediation": "Block access to .env via web-server configuration",
    },
    {
        "categories": [FindingCategory.TECH_STACK],
        "title_contains": ".git",
        "name": "Git repository exposed",
        "description": ".git directory accessible over HTTP",
        "severity": Severity.HIGH,
        "remediation": "Block access to .git/ via web-server configuration",
    },
    {
        "categories": [FindingCategory.PORT],
        "title_contains": "Telnet",
        "name": "Telnet service exposed",
        "description": "Telnet transmits data in cleartext",
        "severity": Severity.HIGH,
        "remediation": "Disable Telnet and migrate to SSH",
    },
]


def derive_misconfigurations(findings: list[Finding]) -> list[MisconfigurationCheck]:
    """Walk through findings and flag known misconfiguration patterns."""
    results: list[MisconfigurationCheck] = []
    seen: set[str] = set()

    for rule in _MISCONFIG_RULES:
        for finding in findings:
            if finding.category not in rule["categories"]:
                continue
            if rule["title_contains"].lower() not in finding.title.lower():
                continue
            if rule["name"] in seen:
                continue
            seen.add(rule["name"])
            results.append(MisconfigurationCheck(
                name=rule["name"],
                description=rule["description"],
                severity=rule["severity"],
                evidence=finding.evidence,
                remediation=rule["remediation"],
            ))

    return results


# ---------------------------------------------------------------------------
# Tool reference helper
# ---------------------------------------------------------------------------

def tools_for_category(category: FindingCategory) -> list[str]:
    """Return the list of open-source tools relevant to a finding category."""
    return TOOL_REFERENCE.get(category, [])
