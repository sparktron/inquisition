"""Outbound regression notifications.

The diff engine (``diffing.py``) already classifies what changed between scans.
This module turns a notable change — a new or regressed finding at or above a
severity threshold — into a webhook notification so a team learns about a
security regression without watching scan output.

Two payload shapes are supported, chosen by the destination URL:
- Slack incoming webhooks (``hooks.slack.com``) get a ``{"text": ...}`` message.
- Any other URL gets a structured JSON payload.

Payload building is pure and unit-tested; the network send is injectable so the
trigger logic can be tested without a real endpoint.
"""

from __future__ import annotations

from typing import Any, Callable, Protocol

from diffing import DiffResult, FindingDelta
from models import Severity, severity_at_least


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


def should_notify(diff: DiffResult, threshold: Severity) -> bool:
    if diff.is_baseline:
        return False
    new, regressed = collect_regressions(diff, threshold)
    return bool(new or regressed)


def build_slack_payload(
    target: str, new: list[FindingDelta], regressed: list[FindingDelta]
) -> dict[str, Any]:
    lines = [f":rotating_light: *Inquisition: security regression on {target}*"]
    for d in new:
        lines.append(f"• *NEW* [{d.severity}] {d.title}")
    for d in regressed:
        lines.append(f"• *REGRESSED* [{d.previous_severity}→{d.severity}] {d.title}")
    return {"text": "\n".join(lines)}


def build_generic_payload(
    target: str,
    new: list[FindingDelta],
    regressed: list[FindingDelta],
    threshold: Severity,
) -> dict[str, Any]:
    return {
        "tool": "inquisition",
        "event": "security_regression",
        "target": target,
        "threshold": threshold.value,
        "new": [
            {"title": d.title, "category": d.category, "severity": d.severity}
            for d in new
        ],
        "regressed": [
            {
                "title": d.title,
                "category": d.category,
                "severity": d.severity,
                "previous_severity": d.previous_severity,
            }
            for d in regressed
        ],
    }


def build_payload(
    url: str,
    target: str,
    new: list[FindingDelta],
    regressed: list[FindingDelta],
    threshold: Severity,
) -> dict[str, Any]:
    if "hooks.slack.com" in url:
        return build_slack_payload(target, new, regressed)
    return build_generic_payload(target, new, regressed, threshold)


def notify(
    url: str,
    target: str,
    diff: DiffResult,
    threshold: Severity,
    *,
    timeout: float = 10.0,
    sender: Callable[..., Any] | None = None,
) -> bool:
    """Send a regression notification if the diff qualifies. Returns True if sent.

    ``sender`` defaults to ``requests.post``; inject a fake in tests.
    """
    if not should_notify(diff, threshold):
        return False

    new, regressed = collect_regressions(diff, threshold)
    payload = build_payload(url, target, new, regressed, threshold)

    post = sender
    if post is None:
        import requests  # type: ignore[import-untyped]
        post = requests.post

    post(url, json=payload, timeout=timeout)
    return True
