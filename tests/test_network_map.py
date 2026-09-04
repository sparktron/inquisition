"""Tests for the interactive network-topology map renderer."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from models import Finding, FindingCategory, ScanReport, Severity
from report import render_network_map
from report.network_map import _layout


def _report(target: str, findings: list[Finding]) -> ScanReport:
    return ScanReport(target=target, started_at=datetime.now(timezone.utc), findings=findings)


def _port(n: int, svc: str = "svc") -> Finding:
    return Finding(title=f"Open port: {n}/{svc}", category=FindingCategory.PORT,
                   severity=Severity.INFO, evidence="open")


def _no_ports() -> Finding:
    return Finding(title="No open ports detected", category=FindingCategory.PORT,
                   severity=Severity.INFO, evidence="none")


def _revdns(ip: str, name: str) -> Finding:
    return Finding(title="Reverse DNS", category=FindingCategory.DNS,
                   severity=Severity.INFO, evidence=f"{ip} -> {name}")


def _fleet() -> list[ScanReport]:
    return [
        _report("192.168.1.1", [_port(80), _revdns("192.168.1.1", "gw.lan")]),   # gateway
        _report("192.168.1.10", [_port(22), _port(5432)]),                        # server
        _report("192.168.1.42", [_port(445), _port(3389)]),                       # endpoint
        _report("192.168.1.99", [_no_ports()]),                                   # dead
    ]


class LayoutTests(unittest.TestCase):
    def test_zero_spokes(self) -> None:
        points, size, cx, cy = _layout(0)
        self.assertEqual(points, [])
        self.assertGreater(size, 0)
        self.assertAlmostEqual(cx, size / 2)

    def test_point_count_matches(self) -> None:
        points, _s, _cx, _cy = _layout(20)
        self.assertEqual(len(points), 20)


class RenderNetworkMapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = render_network_map(self._fleet_reports())

    @staticmethod
    def _fleet_reports() -> list[ScanReport]:
        return _fleet()

    def test_is_self_contained_html(self) -> None:
        self.assertTrue(self.html.startswith("<!DOCTYPE html>"))
        self.assertIn("<svg", self.html)
        self.assertNotIn("http://cdn", self.html)  # dependency-free
        self.assertNotIn("<script src", self.html)  # no external scripts

    def test_live_hosts_present_dead_summarized(self) -> None:
        self.assertIn("192.168.1.1", self.html)   # gateway
        self.assertIn("192.168.1.10", self.html)  # server
        self.assertIn("192.168.1.42", self.html)  # endpoint
        self.assertIn("3 live", self.html)
        self.assertIn("1 not responding", self.html)

    def test_dead_host_not_drawn_as_node(self) -> None:
        # The dead host is counted but not rendered as an interactive node.
        self.assertNotIn('data-ip="192.168.1.99"', self.html)

    def test_gateway_is_the_hub(self) -> None:
        self.assertIn("gateway 192.168.1.1", self.html)

    def test_role_labels_and_legend(self) -> None:
        self.assertIn("Gateway / router", self.html)
        self.assertIn("Server", self.html)
        self.assertIn("Endpoint / user device", self.html)

    def test_role_tables_show_ports(self) -> None:
        self.assertIn("5432", self.html)  # server's DB port listed
        self.assertIn("3389", self.html)  # endpoint's RDP port listed

    def test_no_gateway_falls_back_to_subnet_hub(self) -> None:
        reports = [_report("10.0.0.5", [_port(22)]), _report("10.0.0.6", [_port(80)])]
        html = render_network_map(reports)
        self.assertIn("no gateway identified", html)
        self.assertIn(">subnet<", html)

    def test_subnet_label_passthrough(self) -> None:
        html = render_network_map(self._fleet_reports(), subnet_label="192.168.1.0/24")
        self.assertIn("192.168.1.0/24", html)

    def test_empty_reports_render(self) -> None:
        html = render_network_map([])
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("0 live", html)


class FleetDashboardTopologyTests(unittest.TestCase):
    def test_dashboard_includes_topology_section(self) -> None:
        from report import render_fleet_dashboard
        html = render_fleet_dashboard(_fleet())
        self.assertIn("Network topology", html)
        self.assertIn("Gateway / router", html)
        self.assertIn("192.168.1.1", html)
        self.assertIn("id=\"nm-detail\"", html)  # interactive detail panel embedded

    def test_single_report_dashboard_still_renders(self) -> None:
        from report import render_fleet_dashboard
        html = render_fleet_dashboard([_report("192.168.1.10", [_port(22)])])
        self.assertIn("Network topology", html)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))


if __name__ == "__main__":
    unittest.main()
