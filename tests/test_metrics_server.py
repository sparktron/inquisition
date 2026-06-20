"""Tests for the /metrics scrape server."""

from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request

from metrics_server import HealthState, MetricsHolder, start_metrics_server


class HolderTests(unittest.TestCase):
    def test_get_set_roundtrip(self) -> None:
        h = MetricsHolder("initial")
        self.assertEqual(h.get(), "initial")
        h.set("updated")
        self.assertEqual(h.get(), "updated")


class HealthStateTests(unittest.TestCase):
    def test_not_ready_until_a_cycle_recorded(self) -> None:
        h = HealthState()
        self.assertFalse(h.is_ready())
        self.assertEqual(h.snapshot()["cycles"], 0)
        h.record_cycle(3)
        self.assertTrue(h.is_ready())
        snap = h.snapshot()
        self.assertEqual(snap["cycles"], 1)
        self.assertEqual(snap["targets"], 3)
        self.assertTrue(snap["last_cycle_at"])


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.holder = MetricsHolder()
        self.health = HealthState()
        self.server = start_metrics_server(0, self.holder, health=self.health, host="127.0.0.1")
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

    def test_healthz_always_200(self) -> None:
        status, body = self._get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_readyz_503_until_ready_then_200(self) -> None:
        status, _ = self._get("/readyz")
        self.assertEqual(status, 503)  # no cycle yet
        self.health.record_cycle(2)
        status, body = self._get("/readyz")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ready"])


if __name__ == "__main__":
    unittest.main()
