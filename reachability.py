"""Reachability / precondition modeling and exposure scoring.

A finding's severity says how bad it is; its *reachability* says how plausibly an
attacker can actually use it. This module annotates findings with the attacker
preconditions they imply (network position, authentication, user interaction) and
turns those into a 0..1 feasibility score that weights the attack graph and goal
ranking — so a remote, unauthenticated issue outranks one that needs an on-path
position or stolen credentials.

It also computes a per-target **exposure index** (0..100): how much attack
surface is actually open, distinct from the severity-weighted risk score.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from models import FindingCategory, Severity

if TYPE_CHECKING:
    from models import Finding, ScanReport


class NetworkPosition:
    """Where an attacker must sit to use a finding (easiest to hardest)."""

    REMOTE = "remote"        # anywhere on the internet
    ADJACENT = "adjacent"    # same network segment / subnet
    ON_PATH = "on_path"      # man-in-the-middle on the victim's traffic
    LOCAL = "local"          # already has a foothold on the host


# How feasible each position is for an external attacker (1.0 = trivial).
POSITION_FEASIBILITY: dict[str, float] = {
    NetworkPosition.REMOTE: 1.0,
    NetworkPosition.ADJACENT: 0.6,
    NetworkPosition.ON_PATH: 0.4,
    NetworkPosition.LOCAL: 0.3,
}


# Title substrings that imply an on-path (MITM) precondition. These map to the
# TLS/transport findings whose exploitation requires intercepting traffic.
_ON_PATH_HINTS = (
    "deprecated tls", "legacy tls", "weak cipher", "self-signed",
    "certificate expired", "hostname", "no http-to-https", "strict-transport-security",
    "insecure cookie", "mixed content",
)

# Title substrings that imply the attacker needs a victim to act.
_USER_INTERACTION_HINTS = (
    "clickjacking", "x-frame-options", "content-security-policy", "csp",
    "cors", "trace method", "cross-site",
)


def annotate(finding: "Finding") -> None:
    """Fill in a finding's reachability preconditions in place (heuristic).

    Explicit values already set by a module/KB are preserved; only defaults are
    refined. Network position is inferred from the finding category and title,
    user-interaction from known client-side issue patterns.
    """
    title = finding.title.lower()

    # Network position: only refine the default ("remote"). Transport/cookie
    # issues are exploited by an on-path attacker.
    if finding.network_position == NetworkPosition.REMOTE:
        if finding.category is FindingCategory.TLS or any(h in title for h in _ON_PATH_HINTS):
            finding.network_position = NetworkPosition.ON_PATH

    if not finding.user_interaction and any(h in title for h in _USER_INTERACTION_HINTS):
        finding.user_interaction = True

    # Record human-readable preconditions if none were supplied.
    if not finding.preconditions:
        notes: list[str] = []
        if finding.network_position != NetworkPosition.REMOTE:
            notes.append(f"attacker position: {finding.network_position}")
        if finding.auth_required:
            notes.append("valid credentials required")
        if finding.user_interaction:
            notes.append("victim interaction required")
        finding.preconditions = notes


def feasibility(finding: "Finding") -> float:
    """Combine a finding's preconditions into a 0..1 feasibility score."""
    score = POSITION_FEASIBILITY.get(finding.network_position, 1.0)
    if finding.auth_required:
        score *= 0.5
    if finding.user_interaction:
        score *= 0.7
    return round(score, 3)


def feasibility_label(score: float) -> str:
    """Bucket a feasibility score into an attacker-effort label."""
    if score >= 0.8:
        return "trivial"
    if score >= 0.55:
        return "easy"
    if score >= 0.35:
        return "moderate"
    return "hard"


# ---------------------------------------------------------------------------
# Exposure index (A3)
# ---------------------------------------------------------------------------

# Signal weight by category of exposure. Counts of matching findings are summed
# (with diminishing returns) and capped at 100.
_EXPOSURE_WEIGHTS: dict[str, int] = {
    "unauth_service": 22,   # exposed datastore/remote-admin service w/o auth
    "admin_panel": 14,      # internet-reachable management interface
    "secret_file": 18,      # .env/.git/backup/sensitive file in web root
    "risky_port": 8,        # risky port open (telnet/smb/rdp/db/etc.)
    "weak_tls": 8,          # deprecated protocol / weak cipher / bad cert
    "missing_control": 4,   # missing security header / hardening control
    "info_leak": 6,         # phpinfo, zone transfer, introspection, debug
}

_UNAUTH_SERVICE_HINTS = ("redis", "elasticsearch", "vnc", "smb", "rdp", "mongodb", "memcached")
_SECRET_FILE_HINTS = (".env", ".git", "backup", "sensitive file", "wp-config", "config.php")
_INFO_LEAK_HINTS = ("phpinfo", "zone transfer", "introspection", "debug", "directory listing")
_WEAK_TLS_HINTS = ("deprecated tls", "legacy tls", "weak cipher", "self-signed", "certificate expired")


def _classify_exposure(finding: "Finding") -> str | None:
    title = finding.title.lower()
    if any(h in title for h in _UNAUTH_SERVICE_HINTS) and "exposed" in title:
        return "unauth_service"
    if "admin panel" in title or "management interface" in title:
        return "admin_panel"
    if any(h in title for h in _SECRET_FILE_HINTS):
        return "secret_file"
    if any(h in title for h in _INFO_LEAK_HINTS):
        return "info_leak"
    if any(h in title for h in _WEAK_TLS_HINTS):
        return "weak_tls"
    if finding.category is FindingCategory.PORT and finding.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM):
        return "risky_port"
    if finding.category is FindingCategory.HTTP_HEADER and "missing" in title:
        return "missing_control"
    return None


def exposure_index(report: "ScanReport") -> int:
    """Return a 0..100 attack-surface exposure score for a scan.

    Measures *how much door is open* (open services, exposed files, weak
    transport, missing controls) rather than severity. Repeated signals of the
    same kind add with diminishing returns so one noisy category cannot dominate.

    The result is memoized on the report instance — the renderers call this
    several times per render (text/markdown/json/html), and the score is a pure
    function of the findings. The cache key includes the findings-list identity
    and length so it self-invalidates if the findings are replaced or appended.
    """
    token = (id(report.findings), len(report.findings))
    cached = getattr(report, "_exposure_index_cache", None)
    if cached is not None and cached[0] == token:
        return int(cached[1])
    value = _compute_exposure_index(report)
    setattr(report, "_exposure_index_cache", (token, value))
    return value


def _compute_exposure_index(report: "ScanReport") -> int:
    buckets: dict[str, int] = {}
    for f in report.findings:
        kind = _classify_exposure(f)
        if kind:
            buckets[kind] = buckets.get(kind, 0) + 1

    total = 0.0
    for kind, count in buckets.items():
        weight = _EXPOSURE_WEIGHTS[kind]
        # Diminishing returns: full weight for the first, half for each extra.
        total += weight + weight * 0.5 * (count - 1) if count else 0
    return min(100, round(total))
