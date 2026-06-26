from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

import provenance
from models import Finding, FindingCategory, IntelSource, ScanReport, Severity
from report import render, render_html
from models import ReportFormat


def _f(**kw: object) -> Finding:
    base: dict[str, object] = dict(
        title="t", category=FindingCategory.HTTP_HEADER,
        severity=Severity.MEDIUM, evidence="e",
    )
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


class FindingProvenanceTests(unittest.TestCase):
    def test_no_claim_returns_none(self) -> None:
        self.assertIsNone(provenance.finding_provenance(_f()))

    def test_modeled_from_kb_claim(self) -> None:
        p = provenance.finding_provenance(_f(attack_scenario="attacker does X"))
        assert p is not None
        self.assertEqual(p.tier, provenance.MODELED)
        self.assertFalse(p.confirmed)

    def test_active_scan_is_confirmed(self) -> None:
        p = provenance.finding_provenance(_f(
            title="[active] Stored XSS", category=FindingCategory.VULNERABILITY,
            mitre_techniques=["T1059.007"],
        ))
        assert p is not None
        self.assertTrue(p.confirmed)
        self.assertEqual(p.source, "active scan")

    def test_active_scan_via_metadata_flag(self) -> None:
        # Structured signal classifies even without the legacy "[active]" title.
        p = provenance.finding_provenance(_f(
            title="Stored XSS", category=FindingCategory.VULNERABILITY,
            metadata={"active_scan": True},
        ))
        assert p is not None
        self.assertTrue(p.confirmed)
        self.assertEqual(p.source, "active scan")

    def test_live_validation_beats_active(self) -> None:
        f = _f(title="[active] thing", category=FindingCategory.VULNERABILITY)
        f.metadata["poc_validation"] = {"confirmed": True, "checks": []}
        p = provenance.finding_provenance(f)
        assert p is not None
        self.assertEqual(p.source, "live PoC validation")

    def test_unconfirmed_validation_falls_back_to_kb(self) -> None:
        f = _f(attack_scenario="x")
        f.metadata["poc_validation"] = {"confirmed": False, "checks": []}
        p = provenance.finding_provenance(f)
        assert p is not None
        self.assertEqual(p.tier, provenance.MODELED)


def _report(findings: list[Finding], *, intel: list[IntelSource] | None = None) -> ScanReport:
    r = ScanReport(
        target="example.com",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings=findings,
    )
    r.intel_sources = intel or []
    return r


class IntelFreshnessRenderTests(unittest.TestCase):
    def _intel(self) -> list[IntelSource]:
        return [
            IntelSource(name="CISA KEV", as_of="2026-06-20", detail="catalog 2026.06.20", item_count=1342),
            IntelSource(name="Nuclei templates", as_of="2026-05-01", detail="local", item_count=900, stale=True),
        ]

    def test_text_report_shows_intel_section(self) -> None:
        out = render(_report([_f()], intel=self._intel()), ReportFormat.TEXT)
        self.assertIn("THREAT INTELLIGENCE", out)
        self.assertIn("as of 2026-06-20", out)
        self.assertIn("STALE", out)

    def test_json_embeds_threat_intel(self) -> None:
        doc = json.loads(render(_report([_f()], intel=self._intel()), ReportFormat.JSON))
        self.assertEqual(len(doc["threat_intel"]), 2)
        self.assertTrue(doc["threat_intel"][1]["stale"])

    def test_no_intel_section_when_empty(self) -> None:
        self.assertNotIn("THREAT INTELLIGENCE", render(_report([_f()]), ReportFormat.TEXT))

    def test_html_shows_intel_and_provenance(self) -> None:
        html = render_html(_report([_f(attack_scenario="x")], intel=self._intel()))
        self.assertIn("Threat Intelligence", html)
        self.assertIn("stale — refresh", html)
        self.assertIn("Modeled — knowledge base", html)

    def test_header_freshness_line_uses_oldest_and_flags_stale(self) -> None:
        # The header line surfaces the oldest feed date and names stale feeds.
        out = render(_report([_f()], intel=self._intel()), ReportFormat.TEXT)
        self.assertIn("Intel    : intel current as of 2026-05-01", out)
        self.assertIn("STALE: Nuclei templates", out)

    def test_header_freshness_line_in_html(self) -> None:
        html = render_html(_report([_f()], intel=self._intel()))
        self.assertIn("intel current as of 2026-05-01", html)

    def test_header_freshness_omitted_without_intel(self) -> None:
        self.assertNotIn("intel current as of", render(_report([_f()]), ReportFormat.TEXT))


if __name__ == "__main__":
    unittest.main()
