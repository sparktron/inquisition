from __future__ import annotations

import unittest

from models import Severity
from modules.security_grading import grade_dmarc, grade_spf


class SecurityGradingTests(unittest.TestCase):
    def test_spf_hardfail_is_strong(self) -> None:
        self.assertEqual(grade_spf('"v=spf1 include:_spf.example.test -all"'), [])

    def test_spf_plus_all_is_high_severity(self) -> None:
        issues = grade_spf('"v=spf1 +all"')

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].summary, "SPF uses +all (passes everyone)")
        self.assertEqual(issues[0].severity, Severity.HIGH)

    def test_dmarc_none_and_partial_rollout_are_reported(self) -> None:
        issues = grade_dmarc('"v=DMARC1; p=none; pct=50"')
        summaries = {issue.summary for issue in issues}

        self.assertIn("DMARC policy is p=none (monitor only)", summaries)
        self.assertIn("DMARC applies to only 50% of mail (pct=50)", summaries)

    def test_dmarc_reject_with_rua_is_strong(self) -> None:
        self.assertEqual(grade_dmarc('"v=DMARC1; p=reject; rua=mailto:dmarc@example.test"'), [])

    def test_spf_softfail_is_low(self) -> None:
        issues = grade_spf("v=spf1 include:_spf.example.test ~all")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.LOW)
        self.assertIn("softfail", issues[0].summary.lower())

    def test_spf_neutral_is_medium(self) -> None:
        issues = grade_spf("v=spf1 ?all")
        self.assertEqual(issues[0].severity, Severity.MEDIUM)

    def test_spf_missing_all_mechanism_is_medium(self) -> None:
        issues = grade_spf("v=spf1 include:_spf.example.test")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.MEDIUM)
        self.assertIn("no 'all'", issues[0].summary.lower())

    def test_dmarc_quarantine_is_low(self) -> None:
        issues = grade_dmarc("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.test")
        quarantine = next(i for i in issues if "quarantine" in i.summary)
        self.assertEqual(quarantine.severity, Severity.LOW)

    def test_dmarc_missing_policy_is_flagged(self) -> None:
        issues = grade_dmarc("v=DMARC1; rua=mailto:dmarc@example.test")
        self.assertTrue(any("missing required p=" in i.summary for i in issues))

    def test_dmarc_subdomain_none_flagged_when_main_enforcing(self) -> None:
        issues = grade_dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.test")
        self.assertTrue(any("sp=none" in i.summary for i in issues))

    def test_dmarc_missing_rua_is_info(self) -> None:
        issues = grade_dmarc("v=DMARC1; p=reject")
        rua_issues = [i for i in issues if "rua" in i.summary.lower()]
        self.assertEqual(len(rua_issues), 1)
        self.assertEqual(rua_issues[0].severity, Severity.INFO)


if __name__ == "__main__":
    unittest.main()
