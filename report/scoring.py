"""Shared scoring, severity, and finding-metadata helpers.

These pure helpers are used by every renderer (text / markdown / json / sarif /
html / fleet), so they live in one place to avoid cross-renderer coupling.
"""
from __future__ import annotations

from typing import Any

from models import Finding, Severity


_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

# "What Could Happen" consequence ladder — maps letter grade to real-world outcome language.
_CONSEQUENCE_LADDER: list[tuple[str, str, str]] = [
    # (grade, headline, detail)
    ("A+", "No material risk",
     "No actionable findings. Continue routine monitoring."),
    ("A",  "Minimal risk",
     "Minor configuration gaps. Low attacker value; schedule routine hardening."),
    ("B",  "Limited impact if exploited",
     "Information leakage or minor disruption likely. An opportunistic attacker gains reconnaissance advantage."),
    ("C",  "Credential theft or data exposure likely",
     "A motivated attacker can intercept sessions, steal credentials, or access sensitive data without advanced tools."),
    ("D",  "Account takeover or significant breach probable",
     "Active exploitation is straightforward. Expect lateral movement, data exfiltration, or service disruption if targeted."),
    ("F",  "Full system compromise and mass data exfiltration",
     "Critical exposures present that require no credentials to exploit. Ransomware, backdoor installation, and supply-chain attacks are viable immediately."),
]

_MITRE_BASE_URL = "https://attack.mitre.org/techniques/"


def _mitre_url(technique_id: str) -> str:
    """Return the MITRE ATT&CK URL for a technique ID like T1557 or T1557.002."""
    base = technique_id.replace(".", "/")
    return f"{_MITRE_BASE_URL}{base}/"


def _exploitability_key(f: Finding) -> tuple[int, int, int]:
    """Sort key for attacker-POV ordering: most exploitable first.

    Primary: severity (lower index = more severe).
    Secondary: findings with a PoC command rank higher (attacker already has a tool).
    Tertiary: findings with MITRE tags rank higher (known attack path).
    """
    return (
        _SEV_ORDER.index(f.severity),
        0 if f.poc_command else 1,
        0 if f.mitre_techniques else 1,
    )


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

# User-facing graded risk score, tuned to map onto _GRADE_THRESHOLDS below.
# Distinct from ``diffing._SEVERITY_WEIGHT`` (an internal trend-direction signal);
# both are kept monotonic in severity so a worsening trend never shows a better
# grade. See the note in diffing.py for why they are not shared.
_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high": 15,
    "medium": 5,
    "low": 1,
    "info": 0,
}

_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (0,   "A+"),
    (9,   "A"),
    (24,  "B"),
    (49,  "C"),
    (99,  "D"),
    (999, "F"),
]


def _risk_score(counts: dict[str, int]) -> tuple[int, str]:
    """Return (numeric_score, letter_grade) derived from severity counts."""
    score = sum(counts.get(sev, 0) * weight for sev, weight in _SEVERITY_WEIGHTS.items())
    grade = "F"
    for threshold, g in _GRADE_THRESHOLDS:
        if score <= threshold:
            grade = g
            break
    return score, grade

def _age_phrase(f: Finding) -> str:
    """Human phrase for a finding's cross-scan age, e.g. 'new' or 'open 4 scans since 2026-06-01'."""
    if f.age_scans <= 1:
        return "new this scan"
    day = f.first_seen[:10] if f.first_seen else "?"
    return f"open {f.age_scans} scans (since {day})"


def _poc_validation_checks(f: Finding) -> list[dict[str, Any]]:
    """Return the executed PoC-validation checks recorded on a finding, if any."""
    bundle = f.metadata.get("poc_validation")
    if not isinstance(bundle, dict):
        return []
    checks = bundle.get("checks")
    if not isinstance(checks, list):
        return []
    return [c for c in checks if isinstance(c, dict) and c.get("ran")]
