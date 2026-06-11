from __future__ import annotations

import unittest
from typing import Any

from diffing import DiffResult, FindingDelta
from models import Severity
from notifications import (
    build_generic_payload,
    build_slack_payload,
    collect_regressions,
    notify,
    should_notify,
)


def _delta(title: str, severity: str, previous: str | None = None) -> FindingDelta:
    return FindingDelta(
        fingerprint=f"http_header::{title}",
        title=title,
        category="http_header",
        severity=severity,
        previous_severity=previous,
    )


class RecordingSender:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, json: dict[str, Any], timeout: float) -> str:
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        return "ok"


class ShouldNotifyTests(unittest.TestCase):
    def test_baseline_never_notifies(self) -> None:
        diff = DiffResult(is_baseline=True, new=[_delta("X", "critical")])
        self.assertFalse(should_notify(diff, Severity.HIGH))

    def test_new_high_meets_high_threshold(self) -> None:
        diff = DiffResult(new=[_delta("X", "high")])
        self.assertTrue(should_notify(diff, Severity.HIGH))

    def test_new_low_below_high_threshold(self) -> None:
        diff = DiffResult(new=[_delta("X", "low")])
        self.assertFalse(should_notify(diff, Severity.HIGH))

    def test_regression_triggers_notification(self) -> None:
        diff = DiffResult(regressed=[_delta("Cert", "critical", previous="low")])
        self.assertTrue(should_notify(diff, Severity.HIGH))

    def test_collect_filters_by_threshold(self) -> None:
        diff = DiffResult(new=[_delta("A", "high"), _delta("B", "low")])
        new, regressed = collect_regressions(diff, Severity.HIGH)
        self.assertEqual([d.title for d in new], ["A"])
        self.assertEqual(regressed, [])


class PayloadTests(unittest.TestCase):
    def test_slack_payload_mentions_target_and_changes(self) -> None:
        payload = build_slack_payload(
            "example.com",
            [_delta("New CSP gap", "high")],
            [_delta("Cert", "critical", previous="medium")],
        )
        text = payload["text"]
        self.assertIn("example.com", text)
        self.assertIn("NEW", text)
        self.assertIn("REGRESSED", text)
        self.assertIn("medium→critical", text)

    def test_generic_payload_structure(self) -> None:
        payload = build_generic_payload(
            "example.com",
            [_delta("New", "high")],
            [],
            Severity.HIGH,
        )
        self.assertEqual(payload["event"], "security_regression")
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["new"][0]["severity"], "high")


class NotifyTests(unittest.TestCase):
    def test_qualifying_diff_sends_and_returns_true(self) -> None:
        sender = RecordingSender()
        diff = DiffResult(new=[_delta("X", "high")])
        sent = notify("https://example.test/hook", "example.com", diff, Severity.HIGH, sender=sender)
        self.assertTrue(sent)
        self.assertEqual(len(sender.calls), 1)

    def test_non_qualifying_diff_does_not_send(self) -> None:
        sender = RecordingSender()
        diff = DiffResult(new=[_delta("X", "low")])
        sent = notify("https://example.test/hook", "example.com", diff, Severity.HIGH, sender=sender)
        self.assertFalse(sent)
        self.assertEqual(sender.calls, [])

    def test_slack_url_gets_text_payload(self) -> None:
        sender = RecordingSender()
        diff = DiffResult(new=[_delta("X", "high")])
        notify("https://hooks.slack.com/services/abc", "example.com", diff, Severity.HIGH, sender=sender)
        self.assertIn("text", sender.calls[0]["json"])

    def test_generic_url_gets_structured_payload(self) -> None:
        sender = RecordingSender()
        diff = DiffResult(new=[_delta("X", "high")])
        notify("https://example.test/hook", "example.com", diff, Severity.HIGH, sender=sender)
        self.assertEqual(sender.calls[0]["json"]["event"], "security_regression")


if __name__ == "__main__":
    unittest.main()
