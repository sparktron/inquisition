from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from models import Finding, FindingCategory, ScanReport, Severity
from report import (
    _finding_anchor,
    _remediation_for,
    _risk_score,
    estimate_effort,
    render_html,
    render_json,
    render_markdown,
    render_text,
)


def _history(*totals: int) -> list[dict[str, object]]:
    return [
        {"taken_at": f"2026-06-{10 + i:02d}T00:00:00+00:00", "total": t,
         "counts": {"high": t, "info": 0}}
        for i, t in enumerate(totals)
    ]


class ModelsAndReportTests(unittest.TestCase):
    def test_summary_counts_includes_all_severities(self) -> None:
        report = ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 10, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="critical finding",
                    category=FindingCategory.TLS,
                    severity=Severity.CRITICAL,
                    evidence="expired cert",
                ),
                Finding(
                    title="medium finding",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.MEDIUM,
                    evidence="missing csp",
                ),
                Finding(
                    title="another medium finding",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.MEDIUM,
                    evidence="missing hsts",
                ),
            ],
        )

        self.assertEqual(
            report.summary_counts(),
            {"critical": 1, "high": 0, "medium": 2, "low": 0, "info": 0},
        )

    def test_risk_score_grade_thresholds_are_stable(self) -> None:
        self.assertEqual(_risk_score({"info": 5}), (0, "A+"))
        self.assertEqual(_risk_score({"low": 10}), (10, "B"))
        self.assertEqual(_risk_score({"high": 2, "medium": 4}), (50, "D"))
        self.assertEqual(_risk_score({"critical": 25}), (1000, "F"))

    def test_json_report_contains_machine_readable_finding_fields(self) -> None:
        report = ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 10, 12, tzinfo=timezone.utc),
            finished_at=datetime(2026, 6, 10, 12, 0, 1, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Detected: nginx 1.25",
                    category=FindingCategory.TECH_STACK,
                    severity=Severity.INFO,
                    evidence="Server: nginx/1.25",
                    cpe="cpe:2.3:a:f5:nginx:1.25:*:*:*:*:*:*:*",
                    references=["https://example.com/ref"],
                )
            ],
        )

        data = json.loads(render_json(report))

        self.assertEqual(data["target"], "example.com")
        self.assertEqual(data["summary"]["info"], 1)
        self.assertEqual(data["findings"][0]["cpe"], "cpe:2.3:a:f5:nginx:1.25:*:*:*:*:*:*:*")
        self.assertIn("tools", data["findings"][0])

    def test_brief_text_report_omits_deep_sections(self) -> None:
        report = ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 10, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Missing header: Content-Security-Policy",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.MEDIUM,
                    evidence="missing",
                    impact="impact text",
                    remediation="fix text",
                )
            ],
        )

        output = render_text(report, brief=True)

        self.assertIn("EXECUTIVE SUMMARY", output)
        self.assertIn("DETAILED FINDINGS", output)
        self.assertNotIn("DEEP ISSUE ANALYSIS", output)
        self.assertNotIn("REMEDIATION GUIDE", output)


class MarkdownReportTests(unittest.TestCase):
    def _report(self) -> ScanReport:
        return ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 23, 12, tzinfo=timezone.utc),
            finished_at=datetime(2026, 6, 23, 12, 0, 2, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Missing header: Content-Security-Policy",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.MEDIUM,
                    evidence="missing",
                    impact="impact text",
                    remediation="fix text",
                ),
            ],
        )

    def test_markdown_has_headings_and_summary_table(self) -> None:
        output = render_markdown(self._report())
        self.assertIn("# Inquisition — Security Reconnaissance Report", output)
        self.assertIn("## Executive Summary", output)
        self.assertIn("| Severity | Count |", output)
        self.assertIn("| --- | --- |", output)
        self.assertIn("#### Missing header: Content-Security-Policy", output)
        self.assertTrue(output.endswith("\n"))

    def test_markdown_escapes_pipes_in_table_cells(self) -> None:
        report = ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 23, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Weird | title",
                    category=FindingCategory.APPLICATION,
                    severity=Severity.HIGH,
                    evidence="e",
                ),
            ],
        )
        output = render_markdown(report)
        self.assertIn("Weird \\| title", output)

    def test_markdown_brief_omits_deep_sections(self) -> None:
        output = render_markdown(self._report(), brief=True)
        self.assertIn("## Detailed Findings", output)
        self.assertNotIn("## Deep Issue Analysis", output)
        self.assertNotIn("## Remediation Guide", output)


class AgeAndTrendRenderTests(unittest.TestCase):
    def _report(self) -> ScanReport:
        return ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 14, tzinfo=timezone.utc),
            finished_at=datetime(2026, 6, 14, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Old issue",
                    category=FindingCategory.TLS,
                    severity=Severity.HIGH,
                    evidence="e",
                    first_seen="2026-06-01T00:00:00+00:00",
                    age_scans=4,
                ),
            ],
            history=_history(5, 4, 3, 2),  # improving
        )

    def test_json_includes_age_history_and_trend(self) -> None:
        data = json.loads(render_json(self._report()))
        self.assertEqual(data["findings"][0]["age_scans"], 4)
        self.assertEqual(data["findings"][0]["first_seen"], "2026-06-01T00:00:00+00:00")
        self.assertEqual(len(data["history"]), 4)
        self.assertEqual(data["trend"]["direction"], "improving")
        self.assertEqual(data["trend"]["total_delta"], -3)

    def test_text_report_shows_finding_age(self) -> None:
        output = render_text(self._report())
        self.assertIn("open 4 scans (since 2026-06-01)", output)

    def test_html_report_has_sparkline_and_age(self) -> None:
        html = render_html(self._report())
        self.assertIn("<polyline", html)        # sparkline drawn
        self.assertIn("improving", html)        # trend label
        self.assertIn("open 4 scans", html)     # age row

    def test_html_no_sparkline_without_history(self) -> None:
        report = self._report()
        report.history = []
        self.assertNotIn("<polyline", render_html(report))

    def test_html_has_interactive_filter_and_data_attrs(self) -> None:
        html = render_html(self._report())
        self.assertIn('id="flt-search"', html)            # filter bar present
        self.assertIn('id="flt-severity"', html)
        self.assertIn('class="finding-card"', html)        # cards carry filter data
        self.assertIn('data-severity="high"', html)
        self.assertIn('data-tactics=', html)
        self.assertIn('addEventListener', html)            # filter JS wired

    def test_html_shows_exposure_and_story(self) -> None:
        html = render_html(self._report())
        self.assertIn("Exposure", html)
        # a TLS HIGH finding yields no reachable graph objective; story may be
        # empty, but the exposure metric is always rendered.
        self.assertIn("/100", html)

    def test_new_finding_reads_as_new(self) -> None:
        report = self._report()
        report.findings[0].age_scans = 1
        self.assertIn("new this scan", render_text(report))


class ActionabilityTests(unittest.TestCase):
    def test_estimate_effort_flags_header_findings_as_quick(self) -> None:
        f = Finding(
            title="Missing X-Frame-Options header",
            category=FindingCategory.HTTP_HEADER,
            severity=Severity.MEDIUM,
            evidence="e",
        )
        self.assertEqual(estimate_effort(f), "quick")

    def test_estimate_effort_flags_exposed_service_as_planned(self) -> None:
        f = Finding(
            title="Exposed Redis instance with no authentication",
            category=FindingCategory.PORT,
            severity=Severity.CRITICAL,
            evidence="e",
        )
        self.assertEqual(estimate_effort(f), "planned")

    def test_estimate_effort_keywords_match_on_word_boundaries(self) -> None:
        # "spf" must not fire inside an unrelated word like a plugin name, and a
        # PORT-category app bug that merely mentions "spfilter" stays planned.
        f = Finding(
            title="WordPress spfilter plugin remote code execution",
            category=FindingCategory.APPLICATION,
            severity=Severity.CRITICAL,
            evidence="e",
        )
        self.assertEqual(estimate_effort(f), "planned")

    def test_finding_anchor_map_disambiguates_duplicate_findings(self) -> None:
        from report import finding_anchor_map

        dup_a = Finding(title="X", category=FindingCategory.TLS, severity=Severity.HIGH, evidence="e")
        dup_b = Finding(title="X", category=FindingCategory.TLS, severity=Severity.HIGH, evidence="e")
        other = Finding(title="Y", category=FindingCategory.TLS, severity=Severity.HIGH, evidence="e")
        anchors = finding_anchor_map([dup_a, dup_b, other])
        # Same content would collide under _finding_anchor; the map keeps them unique.
        self.assertNotEqual(anchors[id(dup_a)], anchors[id(dup_b)])
        self.assertEqual(anchors[id(dup_a)], _finding_anchor(dup_a))
        self.assertEqual(anchors[id(dup_b)], f"{_finding_anchor(dup_b)}-2")
        self.assertEqual(len({anchors[id(dup_a)], anchors[id(dup_b)], anchors[id(other)]}), 3)

    def test_md_url_encodes_table_breaking_characters(self) -> None:
        from report.markdown import _md_url

        encoded = _md_url("https://vendor.example/adv/CVE-2021-1234)?x=a|b c")
        self.assertNotIn(")", encoded)
        self.assertNotIn("|", encoded)
        self.assertNotIn(" ", encoded)
        self.assertIn("%29", encoded)
        self.assertIn("%7C", encoded)

    def test_remediation_for_falls_back_when_no_kb_entry_and_no_finding_text(self) -> None:
        f = Finding(
            title="Totally unrecognized finding title xyz123",
            category=FindingCategory.APPLICATION,
            severity=Severity.LOW,
            evidence="e",
        )
        self.assertIn("No specific remediation guidance available", _remediation_for(f))

    def test_remediation_for_prefers_findings_own_text_over_fallback(self) -> None:
        f = Finding(
            title="Totally unrecognized finding title xyz123",
            category=FindingCategory.APPLICATION,
            severity=Severity.LOW,
            evidence="e",
            remediation="Do the specific thing.",
        )
        self.assertEqual(_remediation_for(f), "Do the specific thing.")

    def test_finding_anchor_is_stable_and_content_derived(self) -> None:
        f1 = Finding(title="X", category=FindingCategory.TLS, severity=Severity.HIGH, evidence="e1")
        f2 = Finding(title="X", category=FindingCategory.TLS, severity=Severity.HIGH, evidence="e1")
        f3 = Finding(title="X", category=FindingCategory.TLS, severity=Severity.HIGH, evidence="e2")
        self.assertEqual(_finding_anchor(f1), _finding_anchor(f2))
        self.assertNotEqual(_finding_anchor(f1), _finding_anchor(f3))
        self.assertTrue(_finding_anchor(f1).startswith("finding-"))


class DrillDownHtmlTests(unittest.TestCase):
    def _report(self) -> ScanReport:
        return ScanReport(
            target="example.com",
            started_at=datetime(2026, 6, 30, tzinfo=timezone.utc),
            findings=[
                Finding(
                    title="Missing HSTS header",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.HIGH,
                    evidence="no Strict-Transport-Security",
                ),
                Finding(
                    title="Exposed Redis instance with no authentication",
                    category=FindingCategory.PORT,
                    severity=Severity.CRITICAL,
                    evidence="6379/tcp open",
                ),
            ],
        )

    def test_fix_these_first_section_links_to_finding_anchors(self) -> None:
        report = self._report()
        html = render_html(report)
        self.assertIn("Fix These First", html)
        for f in report.findings:
            anchor = _finding_anchor(f)
            self.assertIn(f'id="{anchor}"', html)     # detail card carries the anchor
            self.assertIn(f'#{anchor}', html)          # priority list links to it (single- or double-quoted)

    def test_finding_cards_are_collapsible_details_elements(self) -> None:
        html = render_html(self._report())
        self.assertIn("<details id=\"finding-", html)
        self.assertIn("<summary", html)

    def test_high_and_critical_cards_default_open_others_closed(self) -> None:
        report = self._report()
        report.findings.append(Finding(
            title="Verbose server banner disclosed",
            category=FindingCategory.TECH_STACK,
            severity=Severity.LOW,
            evidence="Server: nginx/1.18.0",
        ))
        html = render_html(report)
        high_anchor = _finding_anchor(report.findings[0])
        low_anchor = _finding_anchor(report.findings[2])
        self.assertIn(f'id="{high_anchor}" class="finding-card"', html.replace("\n", ""))
        # The HIGH card should carry an "open" attribute before its closing '>'.
        high_tag_start = html.index(f'id="{high_anchor}"')
        high_tag_end = html.index(">", high_tag_start)
        self.assertIn(" open", html[high_tag_start:high_tag_end])
        low_tag_start = html.index(f'id="{low_anchor}"')
        low_tag_end = html.index(">", low_tag_start)
        self.assertNotIn(" open", html[low_tag_start:low_tag_end])

    def test_every_finding_card_has_a_fix_block(self) -> None:
        html = render_html(self._report())
        self.assertIn("How to Fix This", html)

    def test_copy_buttons_and_hash_navigation_js_present(self) -> None:
        html = render_html(self._report())
        self.assertIn("copyable-code", html)
        self.assertIn("navigator.clipboard.writeText", html)
        self.assertIn("hashchange", html)

    def test_effort_badges_render_in_priority_list_and_cards(self) -> None:
        html = render_html(self._report())
        self.assertIn("Quick fix", html)        # header finding
        self.assertIn("Needs planning", html)   # exposed service finding

    def test_learn_more_links_to_mitre_for_uncategorized_findings(self) -> None:
        html = render_html(self._report())
        self.assertIn("How this attack works", html)
        self.assertIn("attack.mitre.org", html)


if __name__ == "__main__":
    unittest.main()
