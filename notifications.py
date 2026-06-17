"""Outbound scan notifications.

The diff engine (``diffing.py``) classifies what changed between scans. This
module turns those changes into a webhook notification so a team learns about a
security regression — or a clean run, or any change — without watching scan
output.

Three policies control *when* a notification fires (``--notify-on``):
- ``regression`` (default): only a new or worsened finding at/above a severity
  threshold. Backward-compatible with the original behavior.
- ``changes``: any delta vs the previous scan (new, fixed, regressed, improved).
- ``always``: every scan, even when nothing changed — useful for a scheduled
  "still green" heartbeat.

Two payload shapes are supported, chosen by the destination URL:
- Slack incoming webhooks (``hooks.slack.com``) get a ``{"text": ...}`` message.
- Any other URL gets a structured JSON payload.

Payload building is pure and unit-tested; the network send is injectable so the
trigger logic can be tested without a real endpoint.
"""

from __future__ import annotations

from typing import Any, Callable, Protocol

from diffing import DiffResult, FindingDelta
from models import ScanReport, Severity, severity_at_least

# Notification policies (values accepted by --notify-on).
NOTIFY_REGRESSION = "regression"
NOTIFY_CHANGES = "changes"
NOTIFY_ALWAYS = "always"
NOTIFY_POLICIES = (NOTIFY_REGRESSION, NOTIFY_CHANGES, NOTIFY_ALWAYS)


class _Sender(Protocol):
    def __call__(self, url: str, json: dict[str, Any], timeout: float) -> Any:
        ...


def _at_least(severity: str, threshold: Severity) -> bool:
    try:
        return severity_at_least(Severity(severity), threshold)
    except ValueError:
        return False


def collect_regressions(
    diff: DiffResult, threshold: Severity
) -> tuple[list[FindingDelta], list[FindingDelta]]:
    """Return (new, regressed) findings at or above ``threshold``."""
    new = [d for d in diff.new if _at_least(d.severity, threshold)]
    regressed = [d for d in diff.regressed if _at_least(d.severity, threshold)]
    return new, regressed


def should_notify(
    diff: DiffResult, threshold: Severity, policy: str = NOTIFY_REGRESSION
) -> bool:
    """Decide whether a notification should fire under ``policy``."""
    if policy == NOTIFY_ALWAYS:
        return True
    if policy == NOTIFY_CHANGES:
        return diff.has_changes()
    # regression (default)
    if diff.is_baseline:
        return False
    new, regressed = collect_regressions(diff, threshold)
    return bool(new or regressed)


def select_deltas(
    diff: DiffResult, threshold: Severity, policy: str
) -> tuple[list[FindingDelta], list[FindingDelta], list[FindingDelta], list[FindingDelta]]:
    """Return (new, regressed, fixed, improved) to report for ``policy``.

    ``regression`` reports only threshold-qualifying new/regressed findings (the
    bad news). ``changes`` and ``always`` report everything that moved, including
    fixes and improvements.
    """
    if policy == NOTIFY_REGRESSION:
        new, regressed = collect_regressions(diff, threshold)
        return new, regressed, [], []
    return list(diff.new), list(diff.regressed), list(diff.fixed), list(diff.improved)


def build_summary(report: ScanReport) -> dict[str, Any]:
    """A compact severity summary for inclusion in notification payloads."""
    counts = report.summary_counts()
    highest = report.highest_severity()
    return {
        "counts": counts,
        "total": sum(counts.values()),
        "highest_severity": highest.value if highest else None,
    }


def _summary_line(summary: dict[str, Any]) -> str:
    counts = summary.get("counts", {})
    parts = [f"{counts.get(sev.value, 0)} {sev.value}" for sev in Severity if counts.get(sev.value)]
    body = ", ".join(parts) if parts else "no findings"
    highest = summary.get("highest_severity")
    return f"Findings: {body}" + (f" (highest: {highest})" if highest else "")


def build_slack_payload(
    target: str,
    new: list[FindingDelta],
    regressed: list[FindingDelta],
    *,
    fixed: list[FindingDelta] | None = None,
    improved: list[FindingDelta] | None = None,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fixed = fixed or []
    improved = improved or []
    icon = ":rotating_light:" if (new or regressed) else ":white_check_mark:"
    lines = [f"{icon} *Inquisition scan: {target}*"]
    if summary:
        lines.append(_summary_line(summary))
    for d in new:
        lines.append(f"• *NEW* [{d.severity}] {d.title}")
    for d in regressed:
        lines.append(f"• *REGRESSED* [{d.previous_severity}→{d.severity}] {d.title}")
    for d in improved:
        lines.append(f"• *IMPROVED* [{d.previous_severity}→{d.severity}] {d.title}")
    for d in fixed:
        lines.append(f"• *FIXED* [{d.severity}] {d.title}")
    if not (new or regressed or improved or fixed):
        lines.append("No change since the previous scan.")
    return {"text": "\n".join(lines)}


def _delta_dict(d: FindingDelta, *, with_previous: bool = False) -> dict[str, Any]:
    out = {"title": d.title, "category": d.category, "severity": d.severity}
    if with_previous:
        out["previous_severity"] = d.previous_severity or ""
    return out


def build_generic_payload(
    target: str,
    new: list[FindingDelta],
    regressed: list[FindingDelta],
    threshold: Severity,
    *,
    fixed: list[FindingDelta] | None = None,
    improved: list[FindingDelta] | None = None,
    summary: dict[str, Any] | None = None,
    policy: str = NOTIFY_REGRESSION,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool": "inquisition",
        "event": "security_regression" if policy == NOTIFY_REGRESSION else "scan_update",
        "policy": policy,
        "target": target,
        "threshold": threshold.value,
        "new": [_delta_dict(d) for d in new],
        "regressed": [_delta_dict(d, with_previous=True) for d in regressed],
    }
    if fixed:
        payload["fixed"] = [_delta_dict(d) for d in fixed]
    if improved:
        payload["improved"] = [_delta_dict(d, with_previous=True) for d in improved]
    if summary is not None:
        payload["summary"] = summary
    return payload


def build_payload(
    url: str,
    target: str,
    new: list[FindingDelta],
    regressed: list[FindingDelta],
    threshold: Severity,
    *,
    fixed: list[FindingDelta] | None = None,
    improved: list[FindingDelta] | None = None,
    summary: dict[str, Any] | None = None,
    policy: str = NOTIFY_REGRESSION,
) -> dict[str, Any]:
    if "hooks.slack.com" in url:
        return build_slack_payload(
            target, new, regressed, fixed=fixed, improved=improved, summary=summary
        )
    return build_generic_payload(
        target, new, regressed, threshold,
        fixed=fixed, improved=improved, summary=summary, policy=policy,
    )


def notify(
    url: str,
    target: str,
    diff: DiffResult,
    threshold: Severity,
    *,
    policy: str = NOTIFY_REGRESSION,
    report: ScanReport | None = None,
    timeout: float = 10.0,
    sender: Callable[..., Any] | None = None,
) -> bool:
    """Send a notification if the diff qualifies under ``policy``. Returns True if sent.

    ``sender`` defaults to ``requests.post``; inject a fake in tests.
    """
    if not should_notify(diff, threshold, policy):
        return False

    new, regressed, fixed, improved = select_deltas(diff, threshold, policy)
    summary = build_summary(report) if report is not None else None
    payload = build_payload(
        url, target, new, regressed, threshold,
        fixed=fixed, improved=improved, summary=summary, policy=policy,
    )

    post = sender
    if post is None:
        import requests  # type: ignore[import-untyped]
        post = requests.post

    post(url, json=payload, timeout=timeout)
    return True
