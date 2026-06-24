from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import vuln_correlation
from models import CVERecord, Severity, cve_priority


class VulenCorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        vuln_correlation._cve_cache.clear()
        vuln_correlation._kev_cache = None
        vuln_correlation._epss_cache.clear()
        vuln_correlation._nuclei_cve_cache = None

    def test_lookup_uses_virtual_match_string_for_partial_cpe(self) -> None:
        response = Mock()
        response.status_code = 200
        response.json.return_value = {"vulnerabilities": []}

        with (
            patch("vuln_correlation.time.sleep"),
            patch("vuln_correlation.requests.get", return_value=response) as get,
        ):
            records = vuln_correlation.lookup_cves_for_cpe(
                "cpe:2.3:a:wordpress:wordpress",
                timeout=1.0,
            )

        self.assertEqual(records, [])
        # First call is the NVD API; second (if any) is CISA KEV — check the NVD call.
        nvd_call = get.call_args_list[0]
        params = nvd_call.kwargs["params"]
        self.assertNotIn("cpeName", params)
        self.assertEqual(
            params["virtualMatchString"],
            "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
        )


class ExploitabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        vuln_correlation._epss_cache.clear()
        vuln_correlation._nuclei_cve_cache = None

    def test_load_epss_parses_and_caches(self) -> None:
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.97400", "percentile": "0.99990"},
            ]
        }
        with patch("vuln_correlation.requests.get", return_value=response) as get:
            out = vuln_correlation._load_epss(["CVE-2021-44228"], timeout=1.0)
        self.assertAlmostEqual(out["CVE-2021-44228"][0], 0.974)
        self.assertAlmostEqual(out["CVE-2021-44228"][1], 0.9999)
        # Second call is served from cache — no further HTTP.
        with patch("vuln_correlation.requests.get") as get2:
            again = vuln_correlation._load_epss(["CVE-2021-44228"])
        get2.assert_not_called()
        self.assertEqual(again, out)
        self.assertEqual(get.call_count, 1)

    def test_enrich_marks_kev_and_nuclei_as_public_exploit(self) -> None:
        rec = CVERecord(
            cve_id="CVE-2017-0144",
            description="EternalBlue",
            severity=Severity.CRITICAL,
            cvss_score=9.3,
            in_cisa_kev=True,
        )
        with (
            patch("vuln_correlation._load_epss", return_value={"CVE-2017-0144": (0.5, 0.9)}),
            patch("vuln_correlation._load_nuclei_cve_ids", return_value={"CVE-2017-0144"}),
        ):
            vuln_correlation.enrich_exploitability([rec])
        self.assertTrue(rec.exploit_public)
        self.assertIn("Nuclei template", rec.exploit_sources)
        self.assertIn("CISA KEV (in-the-wild)", rec.exploit_sources)
        self.assertEqual(rec.epss_score, 0.5)

    def test_cve_priority_orders_by_real_world_risk(self) -> None:
        kev = CVERecord("CVE-A", "", Severity.LOW, cvss_score=4.0, in_cisa_kev=True)
        exploit = CVERecord("CVE-B", "", Severity.MEDIUM, cvss_score=5.0, exploit_public=True)
        high_epss = CVERecord("CVE-C", "", Severity.HIGH, cvss_score=7.0, epss_score=0.8)
        high_cvss = CVERecord("CVE-D", "", Severity.CRITICAL, cvss_score=9.8)
        ordered = sorted([high_cvss, high_epss, exploit, kev], key=cve_priority, reverse=True)
        self.assertEqual([c.cve_id for c in ordered], ["CVE-A", "CVE-B", "CVE-C", "CVE-D"])


if __name__ == "__main__":
    unittest.main()
