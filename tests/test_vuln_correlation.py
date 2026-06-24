from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import vuln_correlation


class VulenCorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        vuln_correlation._cve_cache.clear()
        vuln_correlation._kev_cache = None

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


if __name__ == "__main__":
    unittest.main()
