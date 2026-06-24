"""Vulnerability correlation — CPE-based CVE lookup and misconfiguration checks."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests  # type: ignore[import-untyped]

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

# CISA Known Exploited Vulnerabilities catalog (public JSON feed)
_CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# FIRST.org EPSS — probability a CVE will be exploited in the next 30 days.
_EPSS_API = "https://api.first.org/data/v1/epss"
# Most generous single-request batch the API accepts comfortably.
_EPSS_BATCH = 100

# In-process cache: CPE string → list[CVERecord]
_cve_cache: dict[str, list[CVERecord]] = {}
# CISA KEV set: CVE IDs known to be actively exploited
_kev_cache: set[str] | None = None
# EPSS cache: CVE ID → (score, percentile)
_epss_cache: dict[str, tuple[float, float]] = {}
# Nuclei template CVE coverage (local templates dir), loaded lazily.
_nuclei_cve_cache: set[str] | None = None


def _normalize_cpe23(cpe: str) -> str:
    """Return a full 13-field CPE 2.3 string, padding omitted fields with '*'.

    The scanner often detects products without exact versions. NVD's
    virtualMatchString parameter accepts wildcarded CPE 2.3 values, so we
    normalize partial product identifiers instead of dropping CVE correlation.
    """
    parts = cpe.split(":")
    if len(parts) < 5 or parts[:2] != ["cpe", "2.3"]:
        return ""
    if len(parts) > 13:
        return ""
    return ":".join(parts + ["*"] * (13 - len(parts)))


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


def _load_cisa_kev(timeout: float = 10.0) -> set[str]:
    """Fetch the CISA KEV catalog and return a set of CVE IDs. Cached per process."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = requests.get(
            _CISA_KEV_API,
            timeout=timeout,
            headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
        )
        if resp.status_code == 200:
            data = resp.json()
            _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", [])}
            logger.info("Loaded %d CVEs from CISA KEV catalog", len(_kev_cache))
            return _kev_cache
    except Exception as exc:
        logger.warning("Could not fetch CISA KEV catalog: %s", exc)
    _kev_cache = set()
    return _kev_cache


def _load_epss(cve_ids: list[str], timeout: float = 10.0) -> dict[str, tuple[float, float]]:
    """Return ``{cve_id: (epss_score, percentile)}`` for the given CVEs.

    Results are cached per process and fetched from FIRST.org in batches.
    Missing/unknown CVEs are simply absent from the returned mapping.
    """
    result: dict[str, tuple[float, float]] = {}
    missing: list[str] = []
    for cid in cve_ids:
        if cid in _epss_cache:
            result[cid] = _epss_cache[cid]
        elif cid:
            missing.append(cid)

    for start in range(0, len(missing), _EPSS_BATCH):
        batch = missing[start:start + _EPSS_BATCH]
        try:
            resp = requests.get(
                _EPSS_API,
                params={"cve": ",".join(batch)},
                timeout=timeout,
                headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
            )
            if resp.status_code != 200:
                logger.warning("EPSS API returned HTTP %d — exploit probability unavailable", resp.status_code)
                continue
            for row in resp.json().get("data", []):
                cid = row.get("cve", "")
                if not cid:
                    continue
                try:
                    pair = (float(row.get("epss", 0) or 0), float(row.get("percentile", 0) or 0))
                except (TypeError, ValueError):
                    continue
                _epss_cache[cid] = pair
                result[cid] = pair
        except (requests.RequestException, ValueError) as exc:
            logger.warning("EPSS lookup failed: %s — exploit probability unavailable", exc)
    return result


def _nuclei_template_dirs() -> list[Path]:
    """Candidate directories that may hold Nuclei CVE templates."""
    candidates = [
        os.environ.get("NUCLEI_TEMPLATES", ""),
        os.path.expanduser("~/nuclei-templates"),
        os.path.expanduser("~/.local/nuclei-templates"),
    ]
    return [Path(c) for c in candidates if c]


def _load_nuclei_cve_ids() -> set[str]:
    """CVE IDs covered by locally-installed Nuclei templates (empty if none).

    A Nuclei template named ``CVE-2021-44228.yaml`` is a strong signal that a
    weaponized check (hence a public exploit) exists for that CVE. Scanning the
    local templates directory keeps this offline and dependency-free.
    """
    global _nuclei_cve_cache
    if _nuclei_cve_cache is not None:
        return _nuclei_cve_cache
    found: set[str] = set()
    for base in _nuclei_template_dirs():
        try:
            if not base.is_dir():
                continue
            for path in base.rglob("CVE-*.yaml"):
                found.add(path.stem.upper())
        except OSError as exc:
            logger.warning("Could not scan Nuclei templates in %s: %s", base, exc)
    _nuclei_cve_cache = found
    return found


def enrich_exploitability(records: list[CVERecord], timeout: float = 10.0) -> None:
    """Annotate CVE records in place with EPSS probability and exploit availability.

    Adds the FIRST.org EPSS score/percentile and marks records that have a known
    public exploit (a local Nuclei template, or in-the-wild use per CISA KEV).
    """
    if not records:
        return
    epss = _load_epss([c.cve_id for c in records], timeout=timeout)
    nuclei_cves = _load_nuclei_cve_ids()
    for rec in records:
        if rec.cve_id in epss:
            rec.epss_score, rec.epss_percentile = epss[rec.cve_id]
        sources: list[str] = []
        if rec.cve_id.upper() in nuclei_cves:
            sources.append("Nuclei template")
        if rec.in_cisa_kev:
            sources.append("CISA KEV (in-the-wild)")
        rec.exploit_sources = sources
        rec.exploit_public = bool(sources)


def lookup_cves_for_cpe(cpe: str, timeout: float = 15.0) -> list[CVERecord]:
    """Query the NVD API for CVEs matching a CPE string.

    This is a best-effort lookup.  Returns an empty list on any error.
    """
    if not cpe:
        return []

    cpe_match = _normalize_cpe23(cpe)
    if not cpe_match:
        return []

    if cpe_match in _cve_cache:
        return _cve_cache[cpe_match]

    params: dict[str, str] = {
        "virtualMatchString": cpe_match,
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
            logger.warning("NVD API returned HTTP %d for CPE %s — CVE data may be incomplete", resp.status_code, cpe)
            return []

        data: dict[str, Any] = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("NVD lookup failed for CPE %s: %s — CVE data may be incomplete", cpe, exc)
        return []

    kev_ids = _load_cisa_kev(timeout=timeout)
    now = datetime.now(timezone.utc)

    records: list[CVERecord] = []
    for vuln in data.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        cve_id = cve_item.get("id", "")
        descriptions = cve_item.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available",
        )

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

        # Compute days since public disclosure
        days_since = 0
        published_str = cve_item.get("published", "")
        if published_str:
            try:
                published = datetime.fromisoformat(published_str.rstrip("Z")).replace(tzinfo=timezone.utc)
                days_since = max(0, (now - published).days)
            except ValueError:
                pass

        records.append(CVERecord(
            cve_id=cve_id,
            description=desc[:500],
            severity=_cvss_to_severity(score),
            cvss_score=score,
            references=refs,
            days_since_disclosure=days_since,
            in_cisa_kev=cve_id in kev_ids,
        ))

    enrich_exploitability(records, timeout=timeout)

    _cve_cache[cpe_match] = records
    return records


# ---------------------------------------------------------------------------
# Misconfiguration checks derived from findings
# ---------------------------------------------------------------------------

def derive_misconfigurations(findings: list[Finding]) -> list[MisconfigurationCheck]:
    """Walk through findings and flag known misconfiguration patterns.

    Rules are loaded from structured data (``modules/data/misconfig_rules.yaml``)
    via :mod:`attack_rules`.
    """
    import attack_rules  # lazy import: attack_rules depends on this module

    results: list[MisconfigurationCheck] = []
    seen: set[str] = set()

    for rule in attack_rules.load_misconfig_rules():
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
                attack_scenario=rule.get("attack_scenario", ""),
                mitre_techniques=list(rule.get("mitre_techniques", [])),
                poc_command=rule.get("poc_command", ""),
            ))

    return results


# ---------------------------------------------------------------------------
# Attack chain detection
# ---------------------------------------------------------------------------

@dataclass
class AttackChain:
    """A multi-step kill chain derived from a combination of findings."""

    name: str
    description: str
    steps: list[str]
    mitre_techniques: list[str]
    required_misconfig_names: list[str]  # legacy: names that must ALL be present


def detect_attack_chains(
    misconfigs: list[MisconfigurationCheck],
    findings: list[Finding] | None = None,
) -> list[AttackChain]:
    """Return attack chains triggered by the current findings/misconfigurations.

    Chains and their trigger conditions are loaded from structured data
    (``modules/data/attack_chains.yaml``) and evaluated through the predicate
    DSL in :mod:`attack_rules`, so they are decoupled from any single finding's
    display string. ``findings`` enables attribute-level conditions (category /
    title / severity / CPE / technique); when omitted only misconfiguration-name
    conditions can match.
    """
    import attack_rules  # lazy import: attack_rules depends on this module

    finding_list = findings or []
    triggered: list[AttackChain] = []
    for rule in attack_rules.load_chain_rules():
        if rule.triggered(misconfigs, finding_list):
            triggered.append(rule.chain)
    return triggered


# ---------------------------------------------------------------------------
# Tool reference helper
# ---------------------------------------------------------------------------

def tools_for_category(category: FindingCategory) -> list[str]:
    """Return the list of open-source tools relevant to a finding category."""
    return TOOL_REFERENCE.get(category, [])
