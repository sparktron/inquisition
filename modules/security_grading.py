"""Quality grading for email-authentication DNS records.

Presence of an SPF or DMARC record is necessary but not sufficient. A domain
can publish ``v=spf1 ?all`` (neutral — no protection) or ``v=DMARC1; p=none``
(monitor only — spoofed mail still delivered) and pass a presence check while
providing little real anti-spoofing protection.

These functions are deliberately **pure**: they take a record string and return
a list of :class:`Issue` objects. ``dns_recon`` turns issues into ``Finding``
objects. Keeping the logic side-effect free makes it directly unit-testable
without DNS fixtures.

HTTP response-header quality grading lives inline in ``http_headers`` —
this module is scoped to the email-auth records ``dns_recon`` collects.
"""

from __future__ import annotations

from dataclasses import dataclass

from models import Severity


@dataclass(frozen=True)
class Issue:
    """A single weakness found while grading a present control."""

    summary: str
    severity: Severity
    impact: str
    remediation: str


def grade_spf(record: str) -> list[Issue]:
    """Grade an SPF (``v=spf1 ...``) TXT record's enforcement strength."""
    tokens = [_clean_token(token) for token in record.split()]
    all_mechanisms = [t for t in tokens if t.lstrip("+-~?").lower() == "all"]

    if not all_mechanisms:
        return [Issue(
            "SPF record has no 'all' mechanism",
            Severity.MEDIUM,
            "Without a terminating 'all', receivers default to neutral — spoofed mail is not rejected.",
            "End the SPF record with -all (fail) once all legitimate senders are listed.",
        )]

    last = all_mechanisms[-1]
    qualifier = last[0] if last[0] in "+-~?" else "+"
    if qualifier == "-":
        return []
    if qualifier == "~":
        return [Issue(
            "SPF uses softfail (~all)",
            Severity.LOW,
            "Softfail asks receivers to accept-but-mark spoofed mail rather than reject it.",
            "Move to -all (hardfail) once you have confirmed all legitimate senders pass.",
        )]
    if qualifier == "?":
        return [Issue(
            "SPF uses neutral (?all)",
            Severity.MEDIUM,
            "A neutral policy provides no protection — spoofed mail passes SPF evaluation.",
            "Replace ?all with -all after enumerating legitimate senders.",
        )]
    return [Issue(
        "SPF uses +all (passes everyone)",
        Severity.HIGH,
        "+all authorizes any host on the internet to send mail as your domain — trivial spoofing.",
        "Replace +all with -all immediately.",
    )]


def grade_dmarc(record: str) -> list[Issue]:
    """Grade a DMARC (``v=DMARC1; ...``) TXT record's enforcement strength."""
    issues: list[Issue] = []
    record = record.strip().strip('"')
    tags = {
        k.strip().lower(): v.strip().strip('"')
        for k, _, v in (part.partition("=") for part in record.split(";"))
        if k.strip()
    }

    policy = tags.get("p", "").lower()
    if not policy:
        issues.append(Issue(
            "DMARC record missing required p= policy",
            Severity.MEDIUM,
            "A DMARC record without p= is invalid and ignored by receivers.",
            "Add p=reject (or p=quarantine) to the DMARC record.",
        ))
    elif policy == "none":
        issues.append(Issue(
            "DMARC policy is p=none (monitor only)",
            Severity.MEDIUM,
            "p=none collects reports but takes no action — spoofed mail is still delivered.",
            "Move to p=quarantine then p=reject after reviewing aggregate reports.",
        ))
    elif policy == "quarantine":
        issues.append(Issue(
            "DMARC policy is p=quarantine (not enforcing reject)",
            Severity.LOW,
            "Quarantine sends failing mail to spam rather than rejecting it outright.",
            "Advance to p=reject once quarantine shows no false positives.",
        ))

    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100:
        issues.append(Issue(
            f"DMARC applies to only {pct}% of mail (pct={pct})",
            Severity.LOW,
            "A pct below 100 leaves the remaining fraction of spoofed mail unfiltered.",
            "Set pct=100 (or remove the pct tag) once rollout is complete.",
        ))

    if tags.get("sp", "").lower() == "none" and policy in ("quarantine", "reject"):
        issues.append(Issue(
            "DMARC subdomain policy is sp=none",
            Severity.LOW,
            "Subdomains are exempt from enforcement and can be used to spoof mail.",
            "Remove sp=none (subdomains inherit p=) or set sp to match the main policy.",
        ))

    if "rua" not in tags:
        issues.append(Issue(
            "DMARC has no rua= aggregate report address",
            Severity.INFO,
            "Without rua you receive no aggregate reports, making abuse or misconfiguration hard to detect.",
            "Add rua=mailto:dmarc-reports@yourdomain to receive aggregate reports.",
        ))

    return issues


def _clean_token(token: str) -> str:
    return token.strip().strip('"')
