from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import vuln_correlation


class VulenCorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        vuln_correlation._cve_cache.clear()

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
        params = get.call_args.kwargs["params"]
        self.assertNotIn("cpeName", params)
        self.assertEqual(
            params["virtualMatchString"],
            "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
        )


if __name__ == "__main__":
    unittest.main()
