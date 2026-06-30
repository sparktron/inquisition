from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

from active_scan import (
    _MIN_NUCLEI_VERSION,
    _mitre_from_tags,
    _nuclei_version,
    _templates_stale,
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
    stderr: str = ""
    returncode: int = 0


def _nuclei_line(
    template_id: str,
    name: str,
    severity: str,
    matched: str,
    *,
    tags: list[str] | None = None,
    cve_ids: list[str] | None = None,
    cvss_score: float | None = None,
    curl_command: str = "",
    description: str = "",
    remediation: str = "",
) -> str:
    classification: dict[str, Any] = {}
    if cve_ids is not None:
        classification["cve-id"] = cve_ids
    if cvss_score is not None:
        classification["cvss-score"] = cvss_score

    info: dict[str, Any] = {
        "name": name,
        "severity": severity,
        "description": description or f"{name} desc",
        "tags": tags or [],
    }
    if classification:
        info["classification"] = classification
    if remediation:
        info["remediation"] = remediation

    item: dict[str, Any] = {
        "template-id": template_id,
        "matched-at": matched,
        "info": info,
    }
    if curl_command:
        item["curl-command"] = curl_command
    return json.dumps(item)


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


# ---------------------------------------------------------------------------
# parse_nuclei_output
# ---------------------------------------------------------------------------

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

    def test_cve_ids_extracted_into_evidence_and_attack_scenario(self) -> None:
        out = _nuclei_line(
            "CVE-2021-44228", "Log4Shell", "critical", "https://example.com/api",
            cve_ids=["CVE-2021-44228"],
            cvss_score=10.0,
        )
        findings = parse_nuclei_output(out)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("CVE-2021-44228", f.evidence)
        self.assertIn("10.0", f.evidence)
        self.assertIn("CVE-2021-44228", f.attack_scenario)
        self.assertIn("10.0", f.attack_scenario)
        self.assertIn("https://example.com/api", f.attack_scenario)

    def test_mitre_techniques_derived_from_tags(self) -> None:
        out = _nuclei_line("t", "RCE via SSTI", "high", "https://example.com/",
                           tags=["rce", "ssti", "cve"])
        f = parse_nuclei_output(out)[0]
        self.assertIn("T1059", f.mitre_techniques)
        self.assertIn("T1190", f.mitre_techniques)

    def test_unknown_tags_produce_no_mitre(self) -> None:
        out = _nuclei_line("t", "Thing", "low", "https://example.com/",
                           tags=["panel", "wordpress"])
        f = parse_nuclei_output(out)[0]
        self.assertEqual(f.mitre_techniques, [])

    def test_curl_command_becomes_poc_command(self) -> None:
        poc = "curl -X POST https://example.com/api -d 'x=1'"
        out = _nuclei_line("t", "Injection", "high", "https://example.com/api",
                           curl_command=poc)
        f = parse_nuclei_output(out)[0]
        self.assertEqual(f.poc_command, poc)

    def test_no_curl_command_gives_empty_poc(self) -> None:
        out = _nuclei_line("t", "Thing", "low", "https://example.com/")
        self.assertEqual(parse_nuclei_output(out)[0].poc_command, "")

    def test_deduplication_keeps_first_match(self) -> None:
        line = _nuclei_line("t", "Same Finding", "high", "https://example.com/a")
        line2 = _nuclei_line("t", "Same Finding", "high", "https://example.com/b")
        findings = parse_nuclei_output(f"{line}\n{line2}")
        self.assertEqual(len(findings), 1)
        self.assertIn("/a", findings[0].evidence)

    def test_different_names_not_deduplicated(self) -> None:
        line1 = _nuclei_line("t1", "Finding A", "high", "https://example.com/a")
        line2 = _nuclei_line("t2", "Finding B", "high", "https://example.com/b")
        self.assertEqual(len(parse_nuclei_output(f"{line1}\n{line2}")), 2)

    def test_description_in_impact_and_attack_scenario(self) -> None:
        out = _nuclei_line("t", "XSS", "medium", "https://example.com/",
                           description="Reflected XSS allows script injection.")
        f = parse_nuclei_output(out)[0]
        self.assertIn("Reflected XSS", f.impact)
        self.assertIn("Reflected XSS", f.attack_scenario)

    def test_string_cve_id_accepted(self) -> None:
        item = {
            "template-id": "CVE-2022-1",
            "matched-at": "https://example.com/",
            "info": {
                "name": "Thing",
                "severity": "high",
                "classification": {"cve-id": "CVE-2022-1"},
            },
        }
        f = parse_nuclei_output(json.dumps(item))[0]
        self.assertIn("CVE-2022-1", f.evidence)

    def test_comma_separated_tags_string_parsed(self) -> None:
        item = {
            "template-id": "t",
            "matched-at": "https://example.com/",
            "info": {"name": "X", "severity": "medium", "tags": "rce,cve"},
        }
        f = parse_nuclei_output(json.dumps(item))[0]
        self.assertIn("T1059", f.mitre_techniques)


# ---------------------------------------------------------------------------
# parse_zap_output
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# build_nuclei_command
# ---------------------------------------------------------------------------

class BuildCommandTests(unittest.TestCase):
    def test_command_includes_safety_excludes_and_target(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10)
        self.assertIn("-u", cmd)
        self.assertIn("https://example.com", cmd)
        idx = cmd.index("-exclude-tags")
        self.assertIn("dos", cmd[idx + 1])
        self.assertIn("intrusive", cmd[idx + 1])
        self.assertNotIn("-H", cmd)

    def test_auth_header_added_when_present(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10,
                                   auth_header="Authorization: Bearer x")
        self.assertIn("-H", cmd)
        self.assertIn("Authorization: Bearer x", cmd)

    def test_auth_cookie_injected_as_cookie_header(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10,
                                   auth_cookie="session=abc")
        h_indices = [i for i, v in enumerate(cmd) if v == "-H"]
        cookie_headers = [cmd[i + 1] for i in h_indices]
        self.assertTrue(any("Cookie: session=abc" == h for h in cookie_headers))

    def test_rate_limit_converted_to_rps(self) -> None:
        # 0.5 s delay → 2 rps
        cmd = build_nuclei_command("https://example.com", timeout=10, rate_limit=0.5)
        self.assertIn("-rl", cmd)
        self.assertEqual(cmd[cmd.index("-rl") + 1], "2")

    def test_rate_limit_floor_is_one(self) -> None:
        # Very slow rate → at least 1 rps
        cmd = build_nuclei_command("https://example.com", timeout=10, rate_limit=999.0)
        self.assertEqual(cmd[cmd.index("-rl") + 1], "1")

    def test_no_rate_limit_flag_when_zero(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10, rate_limit=0.0)
        self.assertNotIn("-rl", cmd)

    def test_target_list_replaces_u_flag(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10,
                                   target_list_path="/tmp/targets.txt")
        self.assertNotIn("-u", cmd)
        self.assertIn("-list", cmd)
        self.assertEqual(cmd[cmd.index("-list") + 1], "/tmp/targets.txt")

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


# ---------------------------------------------------------------------------
# _nuclei_version
# ---------------------------------------------------------------------------

class NucleiVersionTests(unittest.TestCase):
    def test_parses_version_from_stdout(self) -> None:
        def fake_runner(cmd: list[str], **kw: Any) -> FakeCompleted:
            return FakeCompleted(stdout="Nuclei Engine Version: v3.2.1\n")
        self.assertEqual(_nuclei_version(fake_runner), (3, 2, 1))

    def test_parses_version_from_stderr(self) -> None:
        def fake_runner(cmd: list[str], **kw: Any) -> FakeCompleted:
            return FakeCompleted(stderr="nuclei v2.9.4\n")
        self.assertEqual(_nuclei_version(fake_runner), (2, 9, 4))

    def test_returns_none_on_unparseable_output(self) -> None:
        def fake_runner(cmd: list[str], **kw: Any) -> FakeCompleted:
            return FakeCompleted(stdout="no version here")
        self.assertIsNone(_nuclei_version(fake_runner))

    def test_returns_none_on_exception(self) -> None:
        def fake_runner(cmd: list[str], **kw: Any) -> FakeCompleted:
            raise OSError("binary not found")
        self.assertIsNone(_nuclei_version(fake_runner))


# ---------------------------------------------------------------------------
# _mitre_from_tags
# ---------------------------------------------------------------------------

class MitreFromTagsTests(unittest.TestCase):
    def test_known_tags_map_to_techniques(self) -> None:
        techniques = _mitre_from_tags(["rce", "xss"])
        self.assertIn("T1059", techniques)
        self.assertIn("T1059.007", techniques)

    def test_unknown_tags_return_empty(self) -> None:
        self.assertEqual(_mitre_from_tags(["panel", "wordpress", "cms"]), [])

    def test_deduplication_within_results(self) -> None:
        # "rce" and "cve" both map to T1190 — should appear once
        techniques = _mitre_from_tags(["rce", "cve"])
        self.assertEqual(techniques.count("T1190"), 1)

    def test_case_insensitive(self) -> None:
        self.assertEqual(_mitre_from_tags(["RCE"]), _mitre_from_tags(["rce"]))


# ---------------------------------------------------------------------------
# run_active_scan
# ---------------------------------------------------------------------------

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

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
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

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            run_active_scan(ScanConfig(target="example.com", active=True), runner=fake_runner)
        self.assertIn("https://example.com", captured["cmd"])

    def test_version_warning_added_when_outdated(self) -> None:
        def fake_runner(cmd: list[str], **kw: Any) -> FakeCompleted:
            return FakeCompleted(stdout="")

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=(2, 5, 0)),
            patch("active_scan._templates_stale", return_value=False),
        ):
            _, errors = run_active_scan(
                ScanConfig(target="example.com", active=True), runner=fake_runner
            )
        self.assertTrue(any("2.5.0" in e or "older" in e for e in errors))

    def test_stale_templates_warning_added(self) -> None:
        def fake_runner(cmd: list[str], **kw: Any) -> FakeCompleted:
            return FakeCompleted(stdout="")

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=True),
        ):
            _, errors = run_active_scan(
                ScanConfig(target="example.com", active=True), runner=fake_runner
            )
        self.assertTrue(any("template" in e.lower() for e in errors))

    def test_discovered_urls_written_to_list_file(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            captured["cmd"] = cmd
            if "-list" in cmd:
                list_path = cmd[cmd.index("-list") + 1]
                with open(list_path) as fh:
                    captured["targets"] = fh.read().splitlines()
            return FakeCompleted(stdout="")

        config = ScanConfig(
            target="example.com",
            active=True,
            discovered_urls=("https://example.com/login", "https://example.com/api"),
        )
        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            run_active_scan(config, runner=fake_runner)

        self.assertIn("-list", captured["cmd"])
        self.assertIn("https://example.com", captured.get("targets", []))
        self.assertIn("https://example.com/login", captured.get("targets", []))
        self.assertIn("https://example.com/api", captured.get("targets", []))

    def test_single_target_uses_u_flag_not_list(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            captured["cmd"] = cmd
            return FakeCompleted(stdout="")

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            run_active_scan(ScanConfig(target="example.com", active=True), runner=fake_runner)

        self.assertIn("-u", captured["cmd"])
        self.assertNotIn("-list", captured["cmd"])

    def test_meaningful_stderr_added_to_errors(self) -> None:
        def fake_runner(cmd: list[str], **kw: Any) -> FakeCompleted:
            return FakeCompleted(stdout="", stderr="[ERR] Template parse failed: bad.yaml\n")

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            _, errors = run_active_scan(
                ScanConfig(target="example.com", active=True), runner=fake_runner
            )
        self.assertTrue(any("stderr" in e.lower() for e in errors))

    def test_noisy_stderr_filtered_out(self) -> None:
        def fake_runner(cmd: list[str], **kw: Any) -> FakeCompleted:
            return FakeCompleted(
                stdout="",
                stderr="[INF] Current nuclei version: v3.0.0\n[INF] Templates loaded: 1000\n",
            )

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            _, errors = run_active_scan(
                ScanConfig(target="example.com", active=True), runner=fake_runner
            )
        self.assertFalse(any("stderr" in e.lower() for e in errors))

    def test_rate_limit_forwarded_to_command(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            captured["cmd"] = cmd
            return FakeCompleted(stdout="")

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            run_active_scan(
                ScanConfig(target="example.com", active=True, rate_limit=0.5),
                runner=fake_runner,
            )
        self.assertIn("-rl", captured["cmd"])
        self.assertEqual(captured["cmd"][captured["cmd"].index("-rl") + 1], "2")

    def test_auth_cookie_forwarded_to_nuclei(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            captured["cmd"] = cmd
            return FakeCompleted(stdout="")

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            run_active_scan(
                ScanConfig(target="example.com", active=True, auth_cookie="session=xyz"),
                runner=fake_runner,
            )
        cmd = captured["cmd"]
        h_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-H"]
        self.assertTrue(any("Cookie: session=xyz" == h for h in h_values))


if __name__ == "__main__":
    unittest.main()
