"""Structured report serializers — JSON and SARIF, single-target and combined."""
from __future__ import annotations

import json
import re
from typing import Any

from models import (
    Finding,
    ScanReport,
    Severity,
    TOOL_REFERENCE,
    cve_priority,
)
from vuln_correlation import tools_for_category
from diffing import compute_trend
import analysis_kb
import reachability
import provenance

from .scoring import _poc_validation_checks


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    d: dict[str, Any] = {
        "title": f.title,
        "category": f.category.value,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "evidence": f.evidence,
    }
    if f.impact:
        d["impact"] = f.impact
    if f.remediation:
        d["remediation"] = f.remediation
    if f.verification:
        d["verification"] = f.verification
    if isinstance(f.metadata.get("poc_validation"), dict):
        d["poc_validation"] = f.metadata["poc_validation"]
    prov = provenance.finding_provenance(f)
    if prov:
        d["provenance"] = {"tier": prov.tier, "source": prov.source}
    if f.cpe:
        d["cpe"] = f.cpe
    if f.age_scans:
        d["first_seen"] = f.first_seen
        d["age_scans"] = f.age_scans
    if f.references:
        d["references"] = f.references
    d["tools"] = tools_for_category(f.category)
    kb = analysis_kb.lookup(f.title)
    if kb:
        d["deep_analysis"] = kb["analysis"]
        d["deep_remediation"] = kb["remediation"]
    return d


def _json_report_dict(report: ScanReport) -> dict[str, Any]:
    """The per-report JSON body, reused by single and combined renderers."""
    data: dict[str, Any] = {
        "target": report.target,
        "started_at": report.started_at.isoformat(),
        "finished_at": report.finished_at.isoformat() if report.finished_at else None,
        "summary": report.summary_counts(),
        "exposure_index": reachability.exposure_index(report),
        "findings": [_finding_to_dict(f) for f in report.findings],
        "cve_records": [
            {
                "cve_id": c.cve_id,
                "description": c.description,
                "severity": c.severity.value,
                "cvss_score": c.cvss_score,
                "epss_score": c.epss_score,
                "epss_percentile": c.epss_percentile,
                "in_cisa_kev": c.in_cisa_kev,
                "exploit_public": c.exploit_public,
                "exploit_sources": c.exploit_sources,
                "references": c.references,
            }
            for c in sorted(report.cve_records, key=cve_priority, reverse=True)
        ],
        "misconfigurations": [
            {
                "name": m.name,
                "description": m.description,
                "severity": m.severity.value,
                "evidence": m.evidence,
                "remediation": m.remediation,
            }
            for m in report.misconfigurations
        ],
        "errors": report.errors,
    }
    if report.intel_sources:
        data["threat_intel"] = [
            {
                "name": s.name,
                "as_of": s.as_of,
                "detail": s.detail,
                "item_count": s.item_count,
                "stale": s.stale,
            }
            for s in report.intel_sources
        ]
    if report.history:
        trend = compute_trend(report.history)
        data["history"] = report.history
        data["trend"] = {
            "direction": trend.direction,
            "span": trend.span,
            "total_delta": trend.total_delta,
            "crit_high_delta": trend.crit_high_delta,
        }
    return data


def render_json(report: ScanReport) -> str:
    """Produce a JSON report."""
    data = _json_report_dict(report)
    data["tool_reference"] = {cat.value: tools for cat, tools in TOOL_REFERENCE.items()}
    return json.dumps(data, indent=2)


_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub sorts code-scanning alerts by a 0.0–10.0 numeric band.
_SARIF_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

_TOOL_VERSION = "0.1.0"
_TOOL_URI = "https://github.com/sparktron/inquisition"


def _sarif_rule_id(f: Finding) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", f.title.lower()).strip("-")
    return f"{f.category.value}/{slug}" if slug else f.category.value


def _sarif_run(report: ScanReport) -> dict[str, Any]:
    """Build a single SARIF ``run`` for one target's report."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in report.findings:
        rule_id = _sarif_rule_id(f)
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.impact or f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {
                    "category": f.category.value,
                    "security-severity": _SARIF_SECURITY_SEVERITY[f.severity],
                },
            }
            if f.remediation:
                rule["help"] = {"text": f.remediation}
            rules[rule_id] = rule

        message = f.evidence or f.title
        if f.remediation:
            message = f"{message}\nRemediation: {f.remediation}"

        # Carry live PoC-validation evidence (Theme E / E2) into SARIF
        # properties so confirmed findings are auditable in code scanning.
        props: dict[str, Any] = {}
        checks = _poc_validation_checks(f)
        if checks:
            bundle = f.metadata.get("poc_validation")
            confirmed = bool(isinstance(bundle, dict) and bundle.get("confirmed"))
            props["confirmed"] = confirmed
            props["pocValidation"] = [
                {
                    "command": c.get("command", ""),
                    "exitCode": c.get("exit_code"),
                    "httpStatus": c.get("http_status"),
                    "output": (
                        str(c.get("stdout", "")) + str(c.get("stderr", ""))
                    ).strip(),
                }
                for c in checks
            ]
            if confirmed:
                message = f"[CONFIRMED via live validation] {message}"

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.target},
                }
            }],
            "partialFingerprints": {"inquisitionFingerprint": rule_id},
        }
        if props:
            result["properties"] = props
        results.append(result)

    return {
        "tool": {
            "driver": {
                "name": "Inquisition",
                "informationUri": _TOOL_URI,
                "version": _TOOL_VERSION,
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }


def render_sarif(report: ScanReport) -> str:
    """Produce a SARIF 2.1.0 report for CI ingestion / GitHub code scanning."""
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [_sarif_run(report)],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------------
# Combined (fleet) structured reports
# ---------------------------------------------------------------------------

def _fleet_summary(reports: list[ScanReport]) -> dict[str, Any]:
    """Aggregate severity counts across every report in a fleet run."""
    totals: dict[str, int] = {sev.value: 0 for sev in Severity}
    for report in reports:
        for sev_value, count in report.summary_counts().items():
            totals[sev_value] += count
    return {
        "targets": [r.target for r in reports],
        "target_count": len(reports),
        "total_findings": sum(totals.values()),
        "counts": totals,
    }


def render_json_combined(reports: list[ScanReport]) -> str:
    """One JSON document holding every target's report plus a fleet summary."""
    import fleet_correlation
    data: dict[str, Any] = {
        "tool": "inquisition",
        "report_type": "fleet",
        "fleet_summary": _fleet_summary(reports),
        "cross_target_correlation": fleet_correlation.analyze(reports).as_dict(),
        "reports": [_json_report_dict(r) for r in reports],
        "tool_reference": {cat.value: tools for cat, tools in TOOL_REFERENCE.items()},
    }
    return json.dumps(data, indent=2)


def render_sarif_combined(reports: list[ScanReport]) -> str:
    """One SARIF 2.1.0 document with one run per target (GitHub accepts many runs)."""
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [_sarif_run(r) for r in reports],
    }
    return json.dumps(sarif, indent=2)
