from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
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


class IntelProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        vuln_correlation._kev_cache = None
        vuln_correlation._intel_provenance.clear()

    def test_kev_load_records_catalog_provenance(self) -> None:
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "catalogVersion": "2026.06.20",
            "dateReleased": "2026-06-20T12:00:00.000Z",
            "vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2020-0001"}],
        }
        with patch("vuln_correlation.requests.get", return_value=response):
            vuln_correlation._load_cisa_kev(timeout=1.0)
        prov = {s.name: s for s in vuln_correlation.intel_provenance()}
        self.assertIn("CISA KEV", prov)
        self.assertEqual(prov["CISA KEV"].item_count, 2)
        self.assertIn("2026.06.20", prov["CISA KEV"].detail)
        self.assertEqual(prov["CISA KEV"].as_of, "2026-06-20T12:00:00.000Z")

    def test_kev_failure_marks_unavailable_stale(self) -> None:
        with patch("vuln_correlation.requests.get", side_effect=Exception("boom")):
            vuln_correlation._load_cisa_kev(timeout=1.0)
        prov = {s.name: s for s in vuln_correlation.intel_provenance()}
        self.assertTrue(prov["CISA KEV"].stale)


class ExploitabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        vuln_correlation._epss_cache.clear()
        vuln_correlation._nuclei_cve_cache = None
        vuln_correlation._msf_cve_cache = None

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
            patch("vuln_correlation._load_msf_cve_index", return_value={}),
        ):
            vuln_correlation.enrich_exploitability([rec])
        self.assertTrue(rec.exploit_public)
        self.assertIn("Nuclei template", rec.exploit_sources)
        self.assertIn("CISA KEV (in-the-wild)", rec.exploit_sources)
        self.assertEqual(rec.epss_score, 0.5)
        # Exploit-archive search links are attached regardless of exploit_public.
        labels = [label for label, _ in rec.exploit_links]
        self.assertIn("Exploit-DB", labels)
        self.assertIn("GitHub PoC search", labels)

    def test_load_msf_cve_index_scans_local_module_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exploits_dir = Path(tmp) / "exploits" / "multi" / "http"
            exploits_dir.mkdir(parents=True)
            module = exploits_dir / "log4shell_header_injection.rb"
            module.write_text(
                "'References' => [\n  ['CVE', '2021-44228'],\n  ['URL', 'https://example.com'],\n],\n"
            )
            with patch.dict(os.environ, {"METASPLOIT_MODULES": tmp}):
                index = vuln_correlation._load_msf_cve_index()
        self.assertEqual(index.get("CVE-2021-44228"), "multi/http/log4shell_header_injection")
        # Cached on second call — no re-scan needed (asserted implicitly by cache reuse).
        self.assertIs(vuln_correlation._load_msf_cve_index(), index)

    def test_exploit_links_includes_metasploit_and_nvd_refs_when_available(self) -> None:
        rec = CVERecord(
            cve_id="CVE-2021-44228",
            description="Log4Shell",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        )
        links = vuln_correlation.exploit_links(
            rec, msf_index={"CVE-2021-44228": "multi/http/log4shell_header_injection"}
        )
        by_label = dict(links)
        self.assertIn("Exploit-DB", by_label)
        self.assertIn("CVE-2021-44228", by_label["Exploit-DB"])
        self.assertIn("GitHub PoC search", by_label)
        self.assertIn("Metasploit module (log4shell_header_injection)", by_label)
        self.assertEqual(
            by_label["Metasploit module (log4shell_header_injection)"],
            "https://www.rapid7.com/db/modules/exploit/multi/http/log4shell_header_injection/",
        )
        # References are labeled by host, not assumed to be NVD.
        self.assertIn("Reference: nvd.nist.gov", by_label)
        self.assertEqual(
            by_label["Reference: nvd.nist.gov"],
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        )

    def test_cve_priority_orders_by_real_world_risk(self) -> None:
        kev = CVERecord("CVE-A", "", Severity.LOW, cvss_score=4.0, in_cisa_kev=True)
        exploit = CVERecord("CVE-B", "", Severity.MEDIUM, cvss_score=5.0, exploit_public=True)
        high_epss = CVERecord("CVE-C", "", Severity.HIGH, cvss_score=7.0, epss_score=0.8)
        high_cvss = CVERecord("CVE-D", "", Severity.CRITICAL, cvss_score=9.8)
        ordered = sorted([high_cvss, high_epss, exploit, kev], key=cve_priority, reverse=True)
        self.assertEqual([c.cve_id for c in ordered], ["CVE-A", "CVE-B", "CVE-C", "CVE-D"])


if __name__ == "__main__":
    unittest.main()
