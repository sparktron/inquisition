from __future__ import annotations

import unittest
from typing import Any

from datetime import datetime, timezone

from diffing import DiffResult, FindingDelta
from models import Finding, FindingCategory, ScanReport, Severity
from notifications import (
    NOTIFY_ALWAYS,
    NOTIFY_CHANGES,
    build_generic_payload,
    build_slack_payload,
    build_summary,
    collect_regressions,
    notify,
    select_deltas,
    should_notify,
    sla_breaches,
)


def _aged_report(*ages: int) -> ScanReport:
    report = ScanReport(target="example.com", started_at=datetime.now(timezone.utc))
    for i, age in enumerate(ages):
        report.findings.append(Finding(
            title=f"finding-{i}",
            category=FindingCategory.TLS,
            severity=Severity.HIGH,
            evidence="e",
            age_scans=age,
        ))
    return report


def _report_with(*severities: Severity) -> ScanReport:
    report = ScanReport(target="example.com", started_at=datetime.now(timezone.utc))
    for i, sev in enumerate(severities):
        report.findings.append(Finding(
            title=f"f{i}",
            category=FindingCategory.HTTP_HEADER,
            severity=sev,
            evidence="e",
        ))
    return report


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


class PolicyTests(unittest.TestCase):
    def test_always_notifies_even_on_baseline(self) -> None:
        diff = DiffResult(is_baseline=True)
        self.assertTrue(should_notify(diff, Severity.HIGH, NOTIFY_ALWAYS))

    def test_changes_notifies_on_low_severity_change(self) -> None:
        diff = DiffResult(new=[_delta("X", "low")])
        # regression policy would skip this; changes policy reports it.
        self.assertFalse(should_notify(diff, Severity.HIGH))
        self.assertTrue(should_notify(diff, Severity.HIGH, NOTIFY_CHANGES))

    def test_changes_quiet_when_nothing_moved(self) -> None:
        diff = DiffResult(unchanged_count=5)
        self.assertFalse(should_notify(diff, Severity.HIGH, NOTIFY_CHANGES))

    def test_select_deltas_changes_includes_fixed_and_improved(self) -> None:
        diff = DiffResult(
            new=[_delta("N", "low")],
            fixed=[_delta("F", "high")],
            improved=[_delta("I", "low", previous="high")],
        )
        new, regressed, fixed, improved = select_deltas(diff, Severity.HIGH, NOTIFY_CHANGES)
        self.assertEqual([d.title for d in new], ["N"])  # not threshold-filtered
        self.assertEqual([d.title for d in fixed], ["F"])
        self.assertEqual([d.title for d in improved], ["I"])

    def test_select_deltas_regression_drops_below_threshold(self) -> None:
        diff = DiffResult(new=[_delta("N", "low")], fixed=[_delta("F", "high")])
        new, regressed, fixed, improved = select_deltas(diff, Severity.HIGH, "regression")
        self.assertEqual(new, [])
        self.assertEqual(fixed, [])


class SummaryPayloadTests(unittest.TestCase):
    def test_build_summary_counts_and_highest(self) -> None:
        summary = build_summary(_report_with(Severity.CRITICAL, Severity.LOW, Severity.LOW))
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["highest_severity"], "critical")
        self.assertEqual(summary["counts"]["low"], 2)

    def test_generic_payload_includes_fixed_and_summary(self) -> None:
        payload = build_generic_payload(
            "example.com",
            [_delta("N", "high")],
            [],
            Severity.HIGH,
            fixed=[_delta("F", "medium")],
            summary={"total": 1, "highest_severity": "high", "counts": {}},
            policy=NOTIFY_CHANGES,
        )
        self.assertEqual(payload["event"], "scan_update")
        self.assertEqual(payload["fixed"][0]["title"], "F")
        self.assertEqual(payload["summary"]["highest_severity"], "high")

    def test_slack_clean_run_uses_check_icon(self) -> None:
        payload = build_slack_payload("example.com", [], [], summary={"counts": {}, "total": 0})
        self.assertIn(":white_check_mark:", payload["text"])
        self.assertIn("No change", payload["text"])

    def test_notify_always_sends_with_summary(self) -> None:
        sender = RecordingSender()
        diff = DiffResult(is_baseline=True)
        sent = notify(
            "https://example.test/hook", "example.com", diff, Severity.HIGH,
            policy=NOTIFY_ALWAYS, report=_report_with(Severity.LOW), sender=sender,
        )
        self.assertTrue(sent)
        self.assertEqual(sender.calls[0]["json"]["summary"]["total"], 1)


class SlaTests(unittest.TestCase):
    def test_sla_breaches_filters_and_sorts(self) -> None:
        report = _aged_report(1, 5, 3, 8)  # threshold 3 -> ages 5 and 8 breach
        breaches = sla_breaches(report, sla_max_age=3)
        self.assertEqual([f.age_scans for f in breaches], [8, 5])  # worst-first

    def test_sla_disabled_returns_nothing(self) -> None:
        self.assertEqual(sla_breaches(_aged_report(9), sla_max_age=0), [])
        self.assertEqual(sla_breaches(None, sla_max_age=3), [])

    def test_per_severity_override_is_stricter(self) -> None:
        # All findings are HIGH (see _aged_report); global SLA off, high override = 2.
        report = _aged_report(1, 3, 5)
        breaches = sla_breaches(report, sla_max_age=0, overrides={"high": 2})
        self.assertEqual([f.age_scans for f in breaches], [5, 3])

    def test_override_zero_disables_that_severity(self) -> None:
        report = _aged_report(9, 9)  # HIGH findings
        # global threshold 3 would breach, but the high override of 0 disables it
        self.assertEqual(sla_breaches(report, sla_max_age=3, overrides={"high": 0}), [])

    def test_notify_fires_on_breach_even_with_quiet_diff(self) -> None:
        sender = RecordingSender()
        diff = DiffResult(unchanged_count=5)  # nothing changed
        sent = notify(
            "https://example.test/hook", "example.com", diff, Severity.HIGH,
            report=_aged_report(7), sla_max_age=3, sender=sender,
        )
        self.assertTrue(sent)
        self.assertEqual(sender.calls[0]["json"]["sla_breaches"][0]["age_scans"], 7)

    def test_no_breach_quiet_diff_does_not_send(self) -> None:
        sender = RecordingSender()
        diff = DiffResult(unchanged_count=5)
        sent = notify(
            "https://example.test/hook", "example.com", diff, Severity.HIGH,
            report=_aged_report(2), sla_max_age=3, sender=sender,
        )
        self.assertFalse(sent)

    def test_slack_payload_marks_breaches(self) -> None:
        payload = build_slack_payload(
            "example.com", [], [], breaches=_aged_report(6).findings
        )
        self.assertIn("SLA", payload["text"])
        self.assertIn("open 6 scans", payload["text"])


if __name__ == "__main__":
    unittest.main()
