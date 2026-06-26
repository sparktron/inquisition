from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

import fleet_correlation
from models import Finding, FindingCategory, ScanConfig, ScanReport, Severity
from report import render_fleet_dashboard, render_json_combined


def _report(target: str, findings: list[Finding], *, asset_value: str = "") -> ScanReport:
    return ScanReport(
        target=target,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings=findings,
        config=ScanConfig(target=target, asset_value=asset_value),
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


def _dns_structured(target: str, ips: list[str], *, evidence: str = "reworded prose") -> Finding:
    # Carries the structured metadata dns_recon now stamps, with deliberately
    # reworded evidence prose the legacy regex would NOT match.
    return Finding(
        title="DNS A/AAAA records", category=FindingCategory.DNS,
        severity=Severity.INFO, evidence=evidence,
        metadata={"resolved_ips": ips},
    )


def _cert_structured(fp: str, *, evidence: str = "reworded prose") -> Finding:
    return Finding(
        title="Certificate fingerprint", category=FindingCategory.TLS,
        severity=Severity.INFO, evidence=evidence,
        metadata={"cert_sha256": fp},
    )


class StructuredMetadataTests(unittest.TestCase):
    def test_shared_ip_from_metadata_ignores_prose(self) -> None:
        reports = [
            _report("a.com", [_dns_structured("a.com", ["203.0.113.5"])]),
            _report("b.com", [_dns_structured("b.com", ["203.0.113.5"])]),
        ]
        links = fleet_correlation.correlate_fleet(reports)
        self.assertEqual([l.kind for l in links], ["shared_ip"])
        self.assertEqual(links[0].shared, "203.0.113.5")

    def test_shared_cert_from_metadata_ignores_prose(self) -> None:
        reports = [
            _report("a.com", [_cert_structured(_FP_A)]),
            _report("b.com", [_cert_structured(_FP_A.upper())]),
        ]
        links = fleet_correlation.correlate_fleet(reports)
        self.assertEqual([l.kind for l in links], ["shared_cert"])
        self.assertEqual(links[0].shared, _FP_A)

    def test_legacy_prose_still_parsed_without_metadata(self) -> None:
        # No metadata → falls back to regex over the legacy evidence string.
        reports = [
            _report("a.com", [_dns("a.com", "203.0.113.5")]),
            _report("b.com", [_dns("b.com", "203.0.113.5")]),
        ]
        links = fleet_correlation.correlate_fleet(reports)
        self.assertEqual([l.kind for l in links], ["shared_ip"])


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


class BlastRadiusTests(unittest.TestCase):
    def test_empty_without_links(self) -> None:
        reports = [
            _report("a.com", [_dns("a.com", "203.0.113.5")]),
            _report("b.com", [_dns("b.com", "198.51.100.9")]),
        ]
        self.assertEqual(fleet_correlation.blast_radius(reports), [])

    def test_low_value_pivot_to_crown_ranks_first(self) -> None:
        # A low-value dev box co-hosted with a crown-jewel host: hardening the dev
        # box removes the pivot, so it must rank as top remediation priority.
        reports = [
            _report("dev.x.com", [_dns("dev.x.com", "203.0.113.5")], asset_value="low"),
            _report("crown.x.com", [_dns("crown.x.com", "203.0.113.5")], asset_value="crown"),
            _report("isolated.x.com", [_dns("isolated.x.com", "10.0.0.1")], asset_value="high"),
        ]
        ranked = fleet_correlation.blast_radius(reports)
        top = ranked[0]
        # dev.x.com endangers the crown jewel (weight 100)
        self.assertEqual(top.target, "dev.x.com")
        self.assertEqual(top.endangered, ("crown.x.com",))
        self.assertEqual(top.endangered_value, 100)
        # the isolated host is not part of any link -> not ranked
        self.assertNotIn("isolated.x.com", {b.target for b in ranked})

    def test_value_reflects_tier_weights(self) -> None:
        reports = [
            _report("a.com", [_dns("a.com", "203.0.113.5")], asset_value="medium"),
            _report("b.com", [_dns("b.com", "203.0.113.5")], asset_value="low"),
        ]
        by_target = {b.target: b for b in fleet_correlation.blast_radius(reports)}
        self.assertEqual(by_target["a.com"].endangered_value, 15)   # endangers low
        self.assertEqual(by_target["b.com"].endangered_value, 40)   # endangers medium

    def test_untagged_uses_baseline_weight(self) -> None:
        reports = [
            _report("a.com", [_dns("a.com", "203.0.113.5")]),
            _report("b.com", [_dns("b.com", "203.0.113.5")]),
        ]
        b = fleet_correlation.blast_radius(reports)[0]
        self.assertEqual(b.value, "")
        self.assertEqual(b.endangered_value, 30)  # baseline for one untagged peer


class CorrelationRenderingTests(unittest.TestCase):
    def _fleet(self) -> list[ScanReport]:
        return [
            _report("a.com", [_dns("a.com", "203.0.113.5")]),
            _report("b.com", [_dns("b.com", "203.0.113.5")]),
        ]

    def test_json_combined_embeds_correlation(self) -> None:
        doc = json.loads(render_json_combined(self._fleet()))
        corr = doc["cross_target_correlation"]
        links = corr["links"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["kind"], "shared_ip")
        self.assertEqual(links[0]["targets"], ["a.com", "b.com"])
        self.assertEqual(len(corr["blast_radius"]), 2)

    def test_dashboard_shows_blast_radius_section(self) -> None:
        reports = [
            _report("dev.com", [_dns("dev.com", "203.0.113.5")], asset_value="low"),
            _report("crown.com", [_dns("crown.com", "203.0.113.5")], asset_value="crown"),
        ]
        html = render_fleet_dashboard(reports)
        self.assertIn("Blast Radius &amp; Crown Jewels", html)
        self.assertIn("Endangered value", html)

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


class ObjectiveRollupTests(unittest.TestCase):
    def _active_rce(self) -> Finding:
        return Finding(
            title="[active] Remote Code Execution", category=FindingCategory.VULNERABILITY,
            severity=Severity.CRITICAL, evidence="matched",
            metadata={"active_scan": True},
        )

    def test_rollup_counts_confirmed_objective(self) -> None:
        reports = [
            _report("a.com", [self._active_rce()]),
            _report("b.com", [_dns("b.com", "203.0.113.5")]),
        ]
        html = render_fleet_dashboard(reports)
        self.assertIn("Confirmed objectives", html)
        self.assertIn("Modeled objectives", html)

    def test_rollup_omitted_when_no_objectives(self) -> None:
        reports = [_report("a.com", [_dns("a.com", "203.0.113.5")])]
        self.assertNotIn("Confirmed objectives", render_fleet_dashboard(reports))


if __name__ == "__main__":
    unittest.main()
