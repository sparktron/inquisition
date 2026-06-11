from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

from active_scan import (
    build_nuclei_command,
    build_zap_command,
    parse_nuclei_output,
    parse_zap_output,
    run_active_scan,
)
from models import FindingCategory, ScanConfig, Severity


@dataclass
class FakeCompleted:
    stdout: str = ""
    returncode: int = 0


def _nuclei_line(template_id: str, name: str, severity: str, matched: str) -> str:
    return json.dumps({
        "template-id": template_id,
        "matched-at": matched,
        "info": {"name": name, "severity": severity, "description": f"{name} desc"},
    })


def _zap_report() -> str:
    return json.dumps({
        "site": [{
            "alerts": [
                {
                    "pluginid": "10020",
                    "name": "Missing Anti-clickjacking Header",
                    "riskdesc": "Medium (High)",
                    "desc": "<p>Frame protection is missing.</p>",
                    "solution": "<p>Add CSP frame-ancestors.</p>",
                    "reference": "https://www.zaproxy.org/docs/alerts/10020/",
                    "instances": [{"uri": "https://example.com/"}],
                },
                {
                    "pluginid": "10027",
                    "name": "Informational Thing",
                    "riskdesc": "Informational (Low)",
                    "instances": [{"uri": "https://example.com/info"}],
                },
            ],
        }],
    })


class ParseNucleiTests(unittest.TestCase):
    def test_parses_findings_with_severity_mapping(self) -> None:
        out = "\n".join([
            _nuclei_line("CVE-2021-1", "Critical RCE", "critical", "https://example.com/x"),
            _nuclei_line("exposure", "Token leak", "low", "https://example.com/y"),
        ])
        findings = parse_nuclei_output(out)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].title, "[active] Critical RCE")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].category, FindingCategory.VULNERABILITY)
        self.assertIn("CVE-2021-1", findings[0].evidence)
        self.assertEqual(findings[1].severity, Severity.LOW)

    def test_blank_and_invalid_lines_skipped(self) -> None:
        out = "\n".join([
            "",
            "not json",
            _nuclei_line("t", "Real", "medium", "https://example.com/"),
            "   ",
        ])
        findings = parse_nuclei_output(out)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_unknown_severity_defaults_to_info(self) -> None:
        out = _nuclei_line("t", "Weird", "totally-unknown", "https://example.com/")
        self.assertEqual(parse_nuclei_output(out)[0].severity, Severity.INFO)


class ParseZapTests(unittest.TestCase):
    def test_parses_zap_alerts_and_skips_info(self) -> None:
        findings = parse_zap_output(_zap_report())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "[active] Missing Anti-clickjacking Header")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertEqual(findings[0].category, FindingCategory.VULNERABILITY)
        self.assertIn("10020", findings[0].evidence)
        self.assertIn("https://example.com/", findings[0].evidence)
        self.assertIn("Frame protection", findings[0].impact)
        self.assertEqual(findings[0].references, ["https://www.zaproxy.org/docs/alerts/10020/"])

    def test_invalid_zap_json_returns_no_findings(self) -> None:
        self.assertEqual(parse_zap_output("not json"), [])


class BuildCommandTests(unittest.TestCase):
    def test_command_includes_safety_excludes_and_target(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10)
        self.assertIn("-u", cmd)
        self.assertIn("https://example.com", cmd)
        # Intrusive/DoS templates are excluded.
        idx = cmd.index("-exclude-tags")
        self.assertIn("dos", cmd[idx + 1])
        self.assertIn("intrusive", cmd[idx + 1])
        self.assertNotIn("-H", cmd)

    def test_auth_header_added_when_present(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10, auth_header="Authorization: Bearer x")
        self.assertIn("-H", cmd)
        self.assertIn("Authorization: Bearer x", cmd)

    def test_zap_command_uses_baseline_json_and_auth_replacer(self) -> None:
        cmd = build_zap_command(
            "https://example.com",
            timeout=90,
            auth_header="Authorization: Bearer x",
            auth_cookie="session=abc",
        )

        self.assertEqual(cmd[0], "zap-baseline.py")
        self.assertIn("-t", cmd)
        self.assertIn("https://example.com", cmd)
        self.assertIn("-J", cmd)
        self.assertIn("-", cmd)
        self.assertIn("-z", cmd)
        zap_config = cmd[cmd.index("-z") + 1]
        self.assertIn("matchstr=Authorization", zap_config)
        self.assertIn("replacement='Bearer x'", zap_config)
        self.assertIn("matchstr=Cookie", zap_config)
        self.assertIn("replacement=session=abc", zap_config)


class RunActiveScanTests(unittest.TestCase):
    def test_missing_nuclei_reports_error(self) -> None:
        with patch("active_scan.is_nuclei_available", return_value=False):
            findings, errors = run_active_scan(ScanConfig(target="example.com", active=True))
        self.assertEqual(findings, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("nuclei", errors[0].lower())

    def test_missing_zap_reports_error(self) -> None:
        with patch("active_scan.is_zap_available", return_value=False):
            findings, errors = run_active_scan(
                ScanConfig(target="example.com", active=True, active_engine="zap")
            )
        self.assertEqual(findings, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("zap", errors[0].lower())

    def test_runs_and_parses_when_available(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            captured["cmd"] = cmd
            return FakeCompleted(stdout=_nuclei_line("t", "Finding", "high", "https://example.com/"))

        with patch("active_scan.is_nuclei_available", return_value=True):
            findings, errors = run_active_scan(
                ScanConfig(target="example.com", active=True),
                runner=fake_runner,
            )
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(captured["cmd"][0], "nuclei")

    def test_runs_zap_engine_when_selected(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            captured["cmd"] = cmd
            return FakeCompleted(stdout=_zap_report())

        with patch("active_scan.is_zap_available", return_value=True):
            findings, errors = run_active_scan(
                ScanConfig(target="example.com", active=True, active_engine="zap"),
                runner=fake_runner,
            )
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertEqual(captured["cmd"][0], "zap-baseline.py")

    def test_defaults_to_https_url(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            captured["cmd"] = cmd
            return FakeCompleted(stdout="")

        with patch("active_scan.is_nuclei_available", return_value=True):
            run_active_scan(ScanConfig(target="example.com", active=True), runner=fake_runner)
        self.assertIn("https://example.com", captured["cmd"])


if __name__ == "__main__":
    unittest.main()
