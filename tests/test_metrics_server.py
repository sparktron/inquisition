"""Tests for the /metrics scrape server."""

from __future__ import annotations

import unittest
import urllib.error
import urllib.request

from metrics_server import MetricsHolder, start_metrics_server


class HolderTests(unittest.TestCase):
    def test_get_set_roundtrip(self) -> None:
        h = MetricsHolder("initial")
        self.assertEqual(h.get(), "initial")
        h.set("updated")
        self.assertEqual(h.get(), "updated")


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.holder = MetricsHolder()
        self.server = start_metrics_server(0, self.holder, host="127.0.0.1")
        self.port = self.server.server_address[1]
        self.addCleanup(self.server.shutdown)

    def _get(self, path: str) -> tuple[int, str]:
        try:
            resp = urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5)
            return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_metrics_path_serves_held_text(self) -> None:
        self.holder.set('inquisition_findings_total{target="x"} 3\n')
        status, body = self._get("/metrics")
        self.assertEqual(status, 200)
        self.assertIn('inquisition_findings_total{target="x"} 3', body)

    def test_root_also_serves_metrics(self) -> None:
        self.holder.set("data\n")
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("data", body)

    def test_other_path_is_404(self) -> None:
        status, _ = self._get("/nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
