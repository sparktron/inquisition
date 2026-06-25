from __future__ import annotations

import unittest
from datetime import datetime, timezone

import reachability
from models import Finding, FindingCategory, MisconfigurationCheck, ScanReport, Severity


def _f(title: str, category: FindingCategory, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(title=title, category=category, severity=severity, evidence="e")


class AnnotateTests(unittest.TestCase):
    def test_tls_finding_becomes_on_path(self) -> None:
        f = _f("Deprecated TLS version supported", FindingCategory.TLS)
        reachability.annotate(f)
        self.assertEqual(f.network_position, reachability.NetworkPosition.ON_PATH)
        self.assertTrue(f.preconditions)

    def test_remote_service_stays_remote(self) -> None:
        f = _f("Open port 6379/Redis exposed", FindingCategory.PORT)
        reachability.annotate(f)
        self.assertEqual(f.network_position, reachability.NetworkPosition.REMOTE)

    def test_csp_implies_user_interaction(self) -> None:
        f = _f("Missing header: Content-Security-Policy", FindingCategory.HTTP_HEADER)
        reachability.annotate(f)
        self.assertTrue(f.user_interaction)

    def test_explicit_position_preserved(self) -> None:
        f = _f("Open port 6379/Redis exposed", FindingCategory.PORT)
        f.network_position = reachability.NetworkPosition.LOCAL
        reachability.annotate(f)
        self.assertEqual(f.network_position, reachability.NetworkPosition.LOCAL)


class FeasibilityTests(unittest.TestCase):
    def test_remote_unauth_is_trivial(self) -> None:
        f = _f("x", FindingCategory.PORT)
        self.assertEqual(reachability.feasibility(f), 1.0)
        self.assertEqual(reachability.feasibility_label(1.0), "trivial")

    def test_on_path_plus_auth_is_hard(self) -> None:
        f = _f("x", FindingCategory.TLS)
        f.network_position = reachability.NetworkPosition.ON_PATH
        f.auth_required = True
        score = reachability.feasibility(f)
        self.assertLess(score, 0.35)
        self.assertEqual(reachability.feasibility_label(score), "hard")


class ExposureIndexTests(unittest.TestCase):
    def _report(self, *findings: Finding) -> ScanReport:
        r = ScanReport(target="example.com", started_at=datetime.now(timezone.utc))
        r.findings = list(findings)
        return r

    def test_clean_report_zero(self) -> None:
        self.assertEqual(reachability.exposure_index(self._report()), 0)

    def test_unauth_service_scores_high(self) -> None:
        r = self._report(_f("Redis exposed to internet", FindingCategory.PORT))
        self.assertGreaterEqual(reachability.exposure_index(r), 20)

    def test_index_capped_at_100(self) -> None:
        findings = [
            _f("Redis exposed to internet", FindingCategory.PORT),
            _f("Elasticsearch exposed to internet", FindingCategory.PORT),
            _f("SMB exposed to internet", FindingCategory.PORT),
            _f("RDP exposed to internet", FindingCategory.PORT),
            _f("VNC exposed to internet", FindingCategory.PORT),
            _f("MongoDB exposed to internet", FindingCategory.PORT),
            _f(".env file exposed", FindingCategory.TECH_STACK),
            _f(".git directory exposed", FindingCategory.TECH_STACK),
            _f("Admin panel accessible", FindingCategory.APPLICATION),
            _f("phpinfo exposed", FindingCategory.APPLICATION),
        ]
        self.assertEqual(reachability.exposure_index(self._report(*findings)), 100)


class ExposureIndexMemoTests(unittest.TestCase):
    def _report(self, *findings: Finding) -> ScanReport:
        r = ScanReport(target="example.com", started_at=datetime.now(timezone.utc))
        r.findings = list(findings)
        return r

    def test_repeat_calls_compute_once(self) -> None:
        from unittest import mock
        r = self._report(_f("Redis exposed to internet", FindingCategory.PORT))
        with mock.patch.object(
            reachability, "_compute_exposure_index",
            wraps=reachability._compute_exposure_index,
        ) as spy:
            first = reachability.exposure_index(r)
            second = reachability.exposure_index(r)
        self.assertEqual(first, second)
        self.assertEqual(spy.call_count, 1)  # cached on the report instance

    def test_cache_invalidates_on_findings_change(self) -> None:
        r = self._report(_f("Redis exposed to internet", FindingCategory.PORT))
        before = reachability.exposure_index(r)
        r.findings.append(_f(".env file exposed", FindingCategory.TECH_STACK))
        after = reachability.exposure_index(r)
        self.assertGreater(after, before)  # recomputed, not stale


if __name__ == "__main__":
    unittest.main()
