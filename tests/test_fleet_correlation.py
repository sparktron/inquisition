from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

import fleet_correlation
from models import Finding, FindingCategory, ScanReport, Severity
from report import render_fleet_dashboard, render_json_combined


def _report(target: str, findings: list[Finding]) -> ScanReport:
    return ScanReport(
        target=target,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings=findings,
    )


def _dns(target: str, ips: str) -> Finding:
    return Finding(
        title="DNS A/AAAA records", category=FindingCategory.DNS,
        severity=Severity.INFO, evidence=f"{target} resolves to: {ips}",
    )


def _cert(fp: str) -> Finding:
    return Finding(
        title="Certificate fingerprint", category=FindingCategory.TLS,
        severity=Severity.INFO, evidence=f"SHA-256: {fp}",
    )


def _takeover(fqdn: str) -> Finding:
    return Finding(
        title=f"Potential subdomain takeover: {fqdn}", category=FindingCategory.DNS,
        severity=Severity.HIGH, evidence="dangling CNAME",
    )


_FP_A = "a" * 64
_FP_B = "b" * 64


class CorrelateFleetTests(unittest.TestCase):
    def test_single_target_has_no_links(self) -> None:
        self.assertEqual(fleet_correlation.correlate_fleet([_report("a.com", [])]), [])

    def test_shared_ip_links_cohosted_targets(self) -> None:
        reports = [
            _report("a.com", [_dns("a.com", "203.0.113.5")]),
            _report("b.com", [_dns("b.com", "203.0.113.5, 198.51.100.9")]),
            _report("c.com", [_dns("c.com", "198.51.100.1")]),
        ]
        links = fleet_correlation.correlate_fleet(reports)
        ip_links = [l for l in links if l.kind == "shared_ip"]
        self.assertEqual(len(ip_links), 1)
        self.assertEqual(ip_links[0].shared, "203.0.113.5")
        self.assertEqual(ip_links[0].targets, ("a.com", "b.com"))
        self.assertEqual(ip_links[0].severity, Severity.HIGH)

    def test_shared_cert_links_targets(self) -> None:
        reports = [
            _report("a.com", [_cert(_FP_A)]),
            _report("b.com", [_cert(_FP_A.upper())]),  # case-insensitive
            _report("c.com", [_cert(_FP_B)]),
        ]
        links = [l for l in fleet_correlation.correlate_fleet(reports) if l.kind == "shared_cert"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].targets, ("a.com", "b.com"))

    def test_takeover_pivots_to_siblings(self) -> None:
        reports = [
            _report("dev.x.com", [_takeover("dev.x.com")]),
            _report("www.x.com", []),
            _report("api.x.com", []),
        ]
        links = [l for l in fleet_correlation.correlate_fleet(reports) if l.kind == "takeover_pivot"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].shared, "dev.x.com")
        self.assertEqual(set(links[0].targets), {"dev.x.com", "www.x.com", "api.x.com"})

    def test_links_sorted_by_value(self) -> None:
        reports = [
            _report("a.com", [_dns("a.com", "203.0.113.5"), _cert(_FP_A)]),
            _report("b.com", [_dns("b.com", "203.0.113.5"), _cert(_FP_A)]),
        ]
        links = fleet_correlation.correlate_fleet(reports)
        # shared_ip (value 80) ranks before shared_cert (value 60)
        self.assertEqual(links[0].kind, "shared_ip")
        self.assertEqual(links[-1].kind, "shared_cert")

    def test_no_link_when_attribute_unique(self) -> None:
        reports = [
            _report("a.com", [_dns("a.com", "203.0.113.5"), _cert(_FP_A)]),
            _report("b.com", [_dns("b.com", "198.51.100.9"), _cert(_FP_B)]),
        ]
        self.assertEqual(fleet_correlation.correlate_fleet(reports), [])


class CorrelationRenderingTests(unittest.TestCase):
    def _fleet(self) -> list[ScanReport]:
        return [
            _report("a.com", [_dns("a.com", "203.0.113.5")]),
            _report("b.com", [_dns("b.com", "203.0.113.5")]),
        ]

    def test_json_combined_embeds_correlation(self) -> None:
        doc = json.loads(render_json_combined(self._fleet()))
        links = doc["cross_target_correlation"]["links"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["kind"], "shared_ip")
        self.assertEqual(links[0]["targets"], ["a.com", "b.com"])

    def test_dashboard_shows_correlation_section(self) -> None:
        html = render_fleet_dashboard(self._fleet())
        self.assertIn("Cross-Target Attack Paths", html)
        self.assertIn("Shared origin IP", html)
        self.assertIn("203.0.113.5", html)

    def test_dashboard_omits_section_when_no_links(self) -> None:
        reports = [
            _report("a.com", [_dns("a.com", "203.0.113.5")]),
            _report("b.com", [_dns("b.com", "198.51.100.9")]),
        ]
        self.assertNotIn("Cross-Target Attack Paths", render_fleet_dashboard(reports))


if __name__ == "__main__":
    unittest.main()
