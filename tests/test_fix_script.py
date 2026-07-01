from __future__ import annotations

import unittest
from datetime import datetime, timezone

from fix_script import render_fix_script
from models import Finding, FindingCategory, ScanReport, Severity


def _report(target: str, findings: list[Finding]) -> ScanReport:
    return ScanReport(target=target, started_at=datetime(2026, 7, 1, tzinfo=timezone.utc), findings=findings)


class FixScriptTests(unittest.TestCase):
    def test_empty_when_no_quick_fix_findings(self) -> None:
        report = _report("example.com", [
            Finding(
                title="Exposed Redis instance with no authentication",
                category=FindingCategory.PORT,
                severity=Severity.CRITICAL,
                evidence="e",
            ),
        ])
        script = render_fix_script([report])
        self.assertIn("No quick-fix findings", script)
        self.assertNotIn("Redis", script)

    def test_includes_quick_fix_finding_as_commented_checklist(self) -> None:
        report = _report("example.com", [
            Finding(
                title="Missing HSTS header",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.HIGH,
                evidence="e",
            ),
        ])
        script = render_fix_script([report])
        self.assertIn("[HIGH] Missing HSTS header", script)
        self.assertIn("Remediation (review before applying", script)

    def test_excludes_low_and_info_severity_even_if_quick(self) -> None:
        report = _report("example.com", [
            Finding(
                title="Missing X-Content-Type-Options header",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.LOW,
                evidence="e",
            ),
        ])
        script = render_fix_script([report])
        self.assertNotIn("X-Content-Type-Options", script)

    def test_safe_verify_command_is_left_runnable(self) -> None:
        report = _report("example.com", [
            Finding(
                title="Missing HSTS header",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.HIGH,
                evidence="e",
                poc_command="curl -sI https://example.com/",
            ),
        ])
        script = render_fix_script([report])
        self.assertIn("Verify after fixing (safe, read-only check):", script)
        lines = script.splitlines()
        idx = next(i for i, l in enumerate(lines) if "safe, read-only check" in l)
        self.assertEqual(lines[idx + 1], "curl -sI https://example.com/")

    def test_unsafe_verify_command_stays_commented(self) -> None:
        report = _report("example.com", [
            Finding(
                title="Missing HSTS header",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.HIGH,
                evidence="e",
                poc_command="curl -sI https://example.com | grep -i strict",
            ),
        ])
        script = render_fix_script([report])
        self.assertIn("review before running", script)
        self.assertNotIn("\ncurl -sI https://example.com | grep -i strict\n", script)
        self.assertIn("# curl -sI https://example.com | grep -i strict", script)

    def test_ordered_worst_severity_first(self) -> None:
        report = _report("example.com", [
            Finding(title="Missing SPF record", category=FindingCategory.DNS, severity=Severity.MEDIUM, evidence="e"),
            Finding(title="Missing HSTS header", category=FindingCategory.HTTP_HEADER, severity=Severity.HIGH, evidence="e"),
        ])
        script = render_fix_script([report])
        self.assertLess(script.index("HSTS"), script.index("SPF"))

    def test_multi_target_labels_each_section(self) -> None:
        r1 = _report("a.example.com", [
            Finding(title="Missing HSTS header", category=FindingCategory.HTTP_HEADER, severity=Severity.HIGH, evidence="e"),
        ])
        r2 = _report("b.example.com", [
            Finding(title="Missing SPF record", category=FindingCategory.DNS, severity=Severity.MEDIUM, evidence="e"),
        ])
        script = render_fix_script([r1, r2])
        self.assertIn("Target: a.example.com", script)
        self.assertIn("Target: b.example.com", script)

    def test_single_target_omits_target_labels(self) -> None:
        report = _report("example.com", [
            Finding(title="Missing HSTS header", category=FindingCategory.HTTP_HEADER, severity=Severity.HIGH, evidence="e"),
        ])
        script = render_fix_script([report])
        self.assertNotIn("Target:", script)

    def test_script_has_shebang_and_safety_preamble(self) -> None:
        report = _report("example.com", [
            Finding(title="Missing HSTS header", category=FindingCategory.HTTP_HEADER, severity=Severity.HIGH, evidence="e"),
        ])
        script = render_fix_script([report])
        self.assertTrue(script.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("set -euo pipefail", script)
        self.assertIn("REVIEWABLE CHECKLIST, not an auto-fixer", script)


if __name__ == "__main__":
    unittest.main()
