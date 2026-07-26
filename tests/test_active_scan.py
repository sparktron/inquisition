from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

from active_scan import (
    _MIN_NUCLEI_VERSION,
    _mitre_from_tags,
    _nuclei_version,
    _parse_zap_output,
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

    def test_malformed_nested_records_do_not_discard_valid_findings(self) -> None:
        out = "\n".join([
            json.dumps({"info": "bad"}),
            json.dumps({"info": {"name": "bad", "tags": 7, "classification": []}}),
            _nuclei_line("t", "Real", "high", "https://example.com/real"),
        ])
        findings = parse_nuclei_output(out)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[-1].title, "[active] Real")

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

    def test_distinct_endpoints_with_same_title_are_retained(self) -> None:
        line = _nuclei_line("t", "Same Finding", "high", "https://example.com/a")
        line2 = _nuclei_line("t", "Same Finding", "high", "https://example.com/b")
        findings = parse_nuclei_output(f"{line}\n{line2}")
        self.assertEqual(len(findings), 2)
        self.assertIn("/a", findings[0].evidence)
        self.assertIn("/b", findings[1].evidence)

    def test_exact_duplicate_template_endpoint_match_is_collapsed(self) -> None:
        line = _nuclei_line("t", "Same Finding", "high", "https://example.com/a")
        self.assertEqual(len(parse_nuclei_output(f"{line}\n{line}")), 1)

    def test_distinct_templates_with_same_title_are_retained(self) -> None:
        line1 = _nuclei_line("t1", "Same Finding", "high", "https://example.com/a")
        line2 = _nuclei_line("t2", "Same Finding", "high", "https://example.com/a")
        self.assertEqual(len(parse_nuclei_output(f"{line1}\n{line2}")), 2)

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

    def test_non_finite_or_out_of_range_cvss_is_ignored(self) -> None:
        for score in ("NaN", "Infinity", -1, 11):
            with self.subTest(score=score):
                item = json.loads(_nuclei_line(
                    "t", "Thing", "medium", "https://example.com/",
                ))
                item["info"]["classification"] = {"cvss-score": score}
                finding = parse_nuclei_output(json.dumps(item))[0]
                self.assertNotIn("CVSS:", finding.evidence)
                self.assertNotIn("CVSS score:", finding.attack_scenario)


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
        self.assertEqual(findings[0].metadata["scanner"], "zap")
        self.assertEqual(findings[0].metadata["plugin_id"], "10020")
        self.assertEqual(
            findings[0].metadata["matched_endpoints"],
            ["https://example.com/"],
        )

    def test_invalid_zap_json_returns_no_findings(self) -> None:
        self.assertEqual(parse_zap_output("not json"), [])

    def test_malformed_zap_records_do_not_discard_valid_alerts(self) -> None:
        payload = json.loads(_zap_report())
        payload["site"].append("bad")
        payload["site"][0]["alerts"].append(7)
        findings = parse_zap_output(json.dumps(payload))
        self.assertEqual(len(findings), 1)

    def test_scalar_site_field_is_reported_as_malformed(self) -> None:
        findings, errors = _parse_zap_output(json.dumps({"site": "invalid"}))
        self.assertEqual(findings, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("1 malformed record", errors[0])

    def test_zap_alert_preserves_all_distinct_instance_endpoints(self) -> None:
        payload = json.loads(_zap_report())
        payload["site"][0]["alerts"][0]["instances"] = [
            {"uri": "https://example.com/one"},
            {"uri": "https://example.com/two"},
            {"uri": "https://example.com/one"},
        ]

        finding = parse_zap_output(json.dumps(payload))[0]

        self.assertIn("https://example.com/one", finding.evidence)
        self.assertIn("https://example.com/two", finding.evidence)
        self.assertEqual(
            finding.metadata["matched_endpoints"],
            ["https://example.com/one", "https://example.com/two"],
        )


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

    def test_rate_limit_preserves_subsecond_delay(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10, rate_limit=0.5)
        self.assertEqual(cmd[cmd.index("-rl") + 1], "1")
        self.assertEqual(cmd[cmd.index("-rld") + 1], "0.5s")

    def test_rate_limit_preserves_multisecond_delay(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10, rate_limit=999.0)
        self.assertEqual(cmd[cmd.index("-rl") + 1], "1")
        self.assertEqual(cmd[cmd.index("-rld") + 1], "999s")

    def test_fractional_timeout_rounds_up_to_one_second(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=0.25)
        self.assertEqual(cmd[cmd.index("-timeout") + 1], "1")

    def test_no_rate_limit_flag_when_zero(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10, rate_limit=0.0)
        self.assertNotIn("-rl", cmd)

    def test_target_list_replaces_u_flag(self) -> None:
        cmd = build_nuclei_command("https://example.com", timeout=10,
                                   target_list_path="/tmp/targets.txt")
        self.assertNotIn("-u", cmd)
        self.assertIn("-list", cmd)
        self.assertEqual(cmd[cmd.index("-list") + 1], "/tmp/targets.txt")

    def test_zap_command_uses_full_scan_json_report_and_auth_replacer(self) -> None:
        cmd = build_zap_command(
            "https://example.com",
            timeout=90,
            report_path="/tmp/zap-report.json",
            auth_header="Authorization: Bearer x",
            auth_cookie="session=abc",
        )
        self.assertEqual(cmd[0], "zap-full-scan.py")
        self.assertIn("-t", cmd)
        self.assertIn("https://example.com", cmd)
        self.assertIn("-J", cmd)
        self.assertIn("/tmp/zap-report.json", cmd)
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

    def test_run_reports_malformed_nuclei_records_but_keeps_valid_results(self) -> None:
        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            return FakeCompleted(stdout=(
                '{"info":"bad"}\n'
                + _nuclei_line("t", "Finding", "high", "https://example.com/")
            ))

        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            findings, errors = run_active_scan(
                ScanConfig(target="example.com", active=True), runner=fake_runner
            )
        self.assertEqual(len(findings), 1)
        self.assertTrue(any("malformed record" in error for error in errors))

    def test_runs_zap_engine_when_selected(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            captured["cmd"] = cmd
            report_path = cmd[cmd.index("-J") + 1]
            Path(report_path).write_text(_zap_report(), encoding="utf-8")
            return FakeCompleted(stdout="ZAP console output is not the JSON report")

        with patch("active_scan.is_zap_available", return_value=True):
            findings, errors = run_active_scan(
                ScanConfig(target="example.com", active=True, active_engine="zap"),
                runner=fake_runner,
            )
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertEqual(captured["cmd"][0], "zap-full-scan.py")

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

    def test_out_of_origin_and_malformed_discovered_urls_are_skipped(self) -> None:
        captured: dict[str, Any] = {}

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            if "-list" in cmd:
                list_path = cmd[cmd.index("-list") + 1]
                with open(list_path) as fh:
                    captured["targets"] = fh.read().splitlines()
            return FakeCompleted(stdout="")

        config = ScanConfig(
            target="https://example.com",
            active=True,
            discovered_urls=(
                "https://example.com/login",
                "https://other.example/api",
                "http://example.com/insecure",
                "https://example.com/good\nhttps://other.example/injected",
            ),
        )
        with (
            patch("active_scan.is_nuclei_available", return_value=True),
            patch("active_scan._nuclei_version", return_value=_MIN_NUCLEI_VERSION),
            patch("active_scan._templates_stale", return_value=False),
        ):
            _, errors = run_active_scan(config, runner=fake_runner)

        self.assertEqual(
            captured["targets"],
            ["https://example.com", "https://example.com/login"],
        )
        self.assertTrue(any("Skipped 3" in error for error in errors))

    def test_malformed_root_url_is_rejected_before_scanner_launch(self) -> None:
        runner_called = False

        def fake_runner(cmd: list[str], **kwargs: Any) -> FakeCompleted:
            nonlocal runner_called
            runner_called = True
            return FakeCompleted()

        findings, errors = run_active_scan(
            ScanConfig(target="example.com\nhttps://other.example", active=True),
            runner=fake_runner,
        )

        self.assertEqual(findings, [])
        self.assertFalse(runner_called)
        self.assertTrue(any("valid HTTP(S) URL" in error for error in errors))

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
        self.assertEqual(captured["cmd"][captured["cmd"].index("-rl") + 1], "1")
        self.assertEqual(captured["cmd"][captured["cmd"].index("-rld") + 1], "0.5s")

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
