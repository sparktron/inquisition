from __future__ import annotations

import socket
import unittest
from dataclasses import dataclass, field
from typing import Any, Callable, cast
from unittest.mock import patch

from models import ScanConfig, ScanDepth, Severity
from modules.app_checks import AppChecksModule
from modules.dns_recon import DnsReconModule
from modules.http_headers import HttpHeaderModule
from modules.http_client import HttpRequestException
from modules.port_scan import PortScanModule
from modules.waf_detection import WafDetectionModule


@dataclass
class RecordedResponse:
    status_code: int = 200
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""
    content: bytes = b""
    cookies: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.content:
            self.content = self.text.encode()

    def json(self) -> dict[str, Any]:
        return {}


class RecordedTextRecord:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


class RecordedHttpClient:
    def __init__(
        self,
        *,
        get: Callable[..., RecordedResponse] | None = None,
        options: Callable[..., RecordedResponse] | None = None,
        post: Callable[..., RecordedResponse] | None = None,
    ) -> None:
        self._get = get
        self._options = options
        self._post = post

    def get(self, url: str, **kwargs: object) -> RecordedResponse:
        if self._get is None:
            raise HttpRequestException(f"unexpected GET {url}")
        return self._get(url, **kwargs)

    def options(self, url: str, **kwargs: object) -> RecordedResponse:
        if self._options is None:
            raise HttpRequestException(f"unexpected OPTIONS {url}")
        return self._options(url, **kwargs)

    def post(self, url: str, **kwargs: object) -> RecordedResponse:
        if self._post is None:
            raise HttpRequestException(f"unexpected POST {url}")
        return self._post(url, **kwargs)


class RecordedSocket:
    connected_ports: list[int] = []

    def __init__(self, *_: object, **__: object) -> None:
        self.port = 0
        self.timeout = 0.0

    def __enter__(self) -> RecordedSocket:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def connect_ex(self, address: tuple[str, int]) -> int:
        _, port = address
        self.port = port
        self.connected_ports.append(port)
        return 0 if port == 22 else 111

    def recv(self, _: int) -> bytes:
        if self.port == 22:
            return b"SSH-2.0-OpenSSH_9.6\r\n"
        raise socket.timeout()


class RecordedNetworkFixtureTests(unittest.TestCase):
    def test_http_header_fixture_reports_missing_headers_and_https_redirect(self) -> None:
        responses = {
            "https://example.test/": RecordedResponse(
                status_code=200,
                headers={"Server": "nginx/1.25", "X-Content-Type-Options": "nosniff"},
                url="https://example.test/",
            ),
            "http://example.test/": RecordedResponse(
                status_code=301,
                headers={"Location": "https://example.test/"},
                url="https://example.test/",
            ),
        }

        def fake_get(url: str, **_: object) -> RecordedResponse:
            return responses[url]

        config = ScanConfig(target="example.test", rate_limit=0)
        findings = HttpHeaderModule(
            config,
            http_client=cast(Any, RecordedHttpClient(get=fake_get)),
        ).run()

        titles = {finding.title for finding in findings}
        self.assertIn("Missing header: Content-Security-Policy", titles)
        self.assertIn("Information disclosure: Server", titles)
        self.assertIn("HTTP redirects to HTTPS", titles)

    def test_waf_fixture_detects_cloudflare_header(self) -> None:
        response = RecordedResponse(
            status_code=200,
            headers={"cf-ray": "abc123-SJC", "server": "cloudflare"},
            text="<html></html>",
            url="https://example.test/",
        )

        findings = WafDetectionModule(
            ScanConfig(target="example.test", rate_limit=0),
            http_client=cast(Any, RecordedHttpClient(get=lambda *_args, **_kwargs: response)),
        ).run()

        self.assertTrue(any("Cloudflare" in finding.title for finding in findings))
        self.assertTrue(all(finding.severity == Severity.INFO for finding in findings))

    def test_app_checks_fixture_reports_cors_and_advertised_methods(self) -> None:
        def fake_get(url: str, **_: object) -> RecordedResponse:
            if url.endswith("/graphql"):
                return RecordedResponse(status_code=404, url=url)
            return RecordedResponse(
                status_code=200,
                headers={"Access-Control-Allow-Origin": "*"},
                url=url,
            )

        def fake_options(url: str, **_: object) -> RecordedResponse:
            return RecordedResponse(
                status_code=204,
                headers={
                    "Access-Control-Allow-Origin": "https://evil.example.com",
                    "Allow": "GET, HEAD, OPTIONS, TRACE, DELETE",
                },
                url=url,
            )

        config = ScanConfig(target="example.test", depth=ScanDepth.STANDARD, rate_limit=0)
        findings = AppChecksModule(
            config,
            http_client=cast(
                Any,
                RecordedHttpClient(get=fake_get, options=fake_options),
            ),
        ).run()

        titles = {finding.title for finding in findings}
        self.assertIn("CORS wildcard", titles)
        self.assertIn("CORS allows arbitrary origins", titles)
        self.assertIn("HTTP TRACE method enabled", titles)
        self.assertTrue(any("DELETE" in title for title in titles))

    def test_dns_fixture_reports_records_without_global_socket_timeout(self) -> None:
        def fake_resolve(name: str, qtype: str, **_: object) -> list[RecordedTextRecord]:
            if name == "example.test" and qtype == "MX":
                return [RecordedTextRecord("10 mail.example.test.")]
            if name == "example.test" and qtype == "NS":
                return []
            if name == "example.test" and qtype == "TXT":
                return [RecordedTextRecord('"v=spf1 -all"')]
            if name == "_dmarc.example.test" and qtype == "TXT":
                return [RecordedTextRecord('"v=DMARC1; p=reject"')]
            return []

        config = ScanConfig(target="example.test", depth=ScanDepth.QUICK, rate_limit=0)
        with (
            patch("modules.dns_recon._safe_dns_resolve", return_value=["203.0.113.10"]),
            patch("modules.dns_recon.socket.gethostbyaddr", return_value=("web.example.test", [], [])),
            patch("dns.resolver.resolve", side_effect=fake_resolve),
            patch("socket.setdefaulttimeout") as setdefaulttimeout,
        ):
            findings = DnsReconModule(config).run()

        titles = {finding.title for finding in findings}
        self.assertIn("DNS A/AAAA records", titles)
        self.assertIn("Reverse DNS", titles)
        self.assertIn("DNS TXT records", titles)
        self.assertIn("DMARC record found", titles)
        setdefaulttimeout.assert_not_called()

    def test_port_scan_fixture_reports_open_ssh_with_passive_banner(self) -> None:
        RecordedSocket.connected_ports = []
        config = ScanConfig(
            target="example.test",
            max_threads=1,
            rate_limit=0,
            connect_timeout=0.5,
            ports=(22, 80),
        )

        with patch("modules.port_scan.socket.socket", side_effect=RecordedSocket):
            findings = PortScanModule(config).run()

        self.assertEqual(RecordedSocket.connected_ports, [22, 80])
        self.assertTrue(any(finding.title == "Open port: 22/SSH" for finding in findings))
        self.assertTrue(any("OpenSSH" in finding.evidence for finding in findings))


if __name__ == "__main__":
    unittest.main()
