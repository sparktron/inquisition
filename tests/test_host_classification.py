"""Tests for host liveness + role classification."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from host_classification import (
    HostRole,
    classify,
    classify_reports,
    detect_default_gateway,
    is_live,
    open_ports,
    parse_default_gateway,
    resolved_ips,
    reverse_dns_name,
)
from models import Finding, FindingCategory, ScanReport, Severity


def _report(target: str, findings: list[Finding]) -> ScanReport:
    return ScanReport(target=target, started_at=datetime.now(timezone.utc), findings=findings)


def _port(n: int, svc: str = "svc") -> Finding:
    return Finding(
        title=f"Open port: {n}/{svc}", category=FindingCategory.PORT,
        severity=Severity.INFO, evidence="open",
    )


def _no_ports() -> Finding:
    return Finding(
        title="No open ports detected", category=FindingCategory.PORT,
        severity=Severity.INFO, evidence="none responded",
    )


def _revdns(ip: str, name: str) -> Finding:
    return Finding(
        title="Reverse DNS", category=FindingCategory.DNS,
        severity=Severity.INFO, evidence=f"{ip} -> {name}",
    )


def _aaaa(ips: list[str]) -> Finding:
    return Finding(
        title="DNS A/AAAA records", category=FindingCategory.DNS, severity=Severity.INFO,
        evidence="resolves", metadata={"resolved_ips": ips},
    )


def _tls() -> Finding:
    return Finding(
        title="TLS 1.2 negotiated", category=FindingCategory.TLS,
        severity=Severity.INFO, evidence="handshake ok",
    )


def _waf(product: str = "Cloudflare") -> Finding:
    return Finding(
        title=f"WAF detected: {product}", category=FindingCategory.APPLICATION,
        severity=Severity.INFO, evidence="signature",
    )


class SignalExtractionTests(unittest.TestCase):
    def test_open_ports_parsed_sorted_unique(self) -> None:
        r = _report("h", [_port(443), _port(22), _port(443), _no_ports()])
        self.assertEqual(open_ports(r), [22, 443])

    def test_open_ports_ignores_no_ports_marker(self) -> None:
        self.assertEqual(open_ports(_report("h", [_no_ports()])), [])

    def test_reverse_dns_name(self) -> None:
        r = _report("h", [_revdns("192.168.1.1", "gw.lan")])
        self.assertEqual(reverse_dns_name(r), "gw.lan")

    def test_reverse_dns_absent(self) -> None:
        self.assertIsNone(reverse_dns_name(_report("h", [_port(80)])))

    def test_resolved_ips(self) -> None:
        r = _report("host.example", [_aaaa(["10.0.0.5", "10.0.0.6"])])
        self.assertEqual(resolved_ips(r), ["10.0.0.5", "10.0.0.6"])


class LivenessTests(unittest.TestCase):
    def test_open_port_means_live(self) -> None:
        self.assertTrue(is_live(_report("h", [_port(22)])))

    def test_tls_finding_means_live(self) -> None:
        self.assertTrue(is_live(_report("h", [_tls()])))

    def test_no_open_ports_means_not_live(self) -> None:
        self.assertFalse(is_live(_report("h", [_no_ports()])))

    def test_empty_report_not_live(self) -> None:
        self.assertFalse(is_live(_report("h", [])))


class RoleClassificationTests(unittest.TestCase):
    def test_gateway_by_default_gateway_match(self) -> None:
        p = classify(_report("192.168.1.1", [_port(80)]), default_gateway="192.168.1.1")
        self.assertEqual(p.role, HostRole.GATEWAY)
        self.assertEqual(p.confidence, "high")

    def test_gateway_match_via_resolved_ip_for_hostname_target(self) -> None:
        r = _report("router.lan", [_port(443), _aaaa(["192.168.0.1"])])
        p = classify(r, default_gateway="192.168.0.1")
        self.assertEqual(p.role, HostRole.GATEWAY)

    def test_gateway_by_reverse_dns_name(self) -> None:
        p = classify(_report("192.168.5.9", [_port(443), _revdns("192.168.5.9", "fw01.corp")]))
        self.assertEqual(p.role, HostRole.GATEWAY)
        self.assertEqual(p.confidence, "high")

    def test_gateway_by_convention_plus_web_admin(self) -> None:
        p = classify(_report("192.168.1.254", [_port(80)]))
        self.assertEqual(p.role, HostRole.GATEWAY)
        self.assertEqual(p.confidence, "medium")

    def test_dot_one_without_web_admin_is_not_gateway(self) -> None:
        # .1 but only SSH -> classified by service, not the address convention.
        p = classify(_report("192.168.1.1", [_port(22)]))
        self.assertEqual(p.role, HostRole.SERVER)

    def test_endpoint_by_workstation_ports(self) -> None:
        p = classify(_report("192.168.1.42", [_port(445, "SMB"), _port(3389, "RDP")]))
        self.assertEqual(p.role, HostRole.ENDPOINT)

    def test_server_by_server_ports(self) -> None:
        p = classify(_report("192.168.1.10", [_port(22, "SSH"), _port(5432, "PostgreSQL")]))
        self.assertEqual(p.role, HostRole.SERVER)

    def test_workstation_plus_server_port_leans_server(self) -> None:
        # 445 (workstation) + 22 (server) -> server wins.
        p = classify(_report("192.168.1.11", [_port(445), _port(22)]))
        self.assertEqual(p.role, HostRole.SERVER)

    def test_web_only_leans_server_low_confidence(self) -> None:
        p = classify(_report("192.168.1.50", [_port(80), _port(443)]))
        self.assertEqual(p.role, HostRole.SERVER)
        self.assertEqual(p.confidence, "low")

    def test_live_but_unknown(self) -> None:
        p = classify(_report("192.168.1.60", [_port(9999, "?")]))
        self.assertEqual(p.role, HostRole.UNKNOWN)
        self.assertTrue(p.live)

    def test_dead_host_is_unknown_and_not_live(self) -> None:
        p = classify(_report("192.168.1.70", [_no_ports()]))
        self.assertFalse(p.live)
        self.assertEqual(p.role, HostRole.UNKNOWN)

    def test_reverse_proxy_noted_as_signal(self) -> None:
        p = classify(_report("192.168.1.80", [_port(443), _waf()]))
        self.assertTrue(any("reverse-proxy" in s or "CDN" in s for s in p.signals))

    def test_profile_as_dict_roundtrips_fields(self) -> None:
        p = classify(_report("192.168.1.10", [_port(22)]))
        d = p.as_dict()
        self.assertEqual(d["target"], "192.168.1.10")
        self.assertEqual(d["role"], "server")
        ports = d["open_ports"]
        assert isinstance(ports, list)
        self.assertIn(22, ports)

    def test_classify_reports_preserves_order(self) -> None:
        reports = [_report("a", [_port(22)]), _report("b", [_no_ports()])]
        profiles = classify_reports(reports)
        self.assertEqual([p.target for p in profiles], ["a", "b"])
        self.assertTrue(profiles[0].live)
        self.assertFalse(profiles[1].live)


class DefaultGatewayParsingTests(unittest.TestCase):
    def test_parse_linux_ip_route(self) -> None:
        out = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
        self.assertEqual(parse_default_gateway(out), "192.168.1.1")

    def test_parse_picks_valid_ip_only(self) -> None:
        self.assertIsNone(parse_default_gateway("default via not-an-ip dev eth0"))

    def test_parse_empty(self) -> None:
        self.assertIsNone(parse_default_gateway(""))

    def test_detect_returns_str_or_none(self) -> None:
        # Environment-dependent; just assert the contract holds and it never raises.
        gw = detect_default_gateway()
        self.assertTrue(gw is None or isinstance(gw, str))


if __name__ == "__main__":
    unittest.main()
