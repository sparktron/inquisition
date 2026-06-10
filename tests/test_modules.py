from __future__ import annotations

import unittest
from dataclasses import dataclass
from unittest.mock import patch

import requests  # type: ignore[import-untyped]

from models import Finding, ScanConfig, ScanDepth, Severity
from modules.content_discovery import ContentDiscoveryModule
from modules.tech_stack import TechStackModule


@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = ""
    content: bytes = b""
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if not self.content:
            self.content = self.text.encode()
        if self.headers is None:
            self.headers = {}


class ModuleBehaviorTests(unittest.TestCase):
    def test_security_txt_with_expired_expires_is_low_severity(self) -> None:
        module = ContentDiscoveryModule(ScanConfig(target="example.com"))
        findings: list[Finding] = []

        with patch.object(
            module,
            "_get",
            return_value=FakeResponse(
                text=(
                    "Contact: mailto:security@example.com\n"
                    "Expires: Wed, 01 Jan 2020 00:00:00 GMT\n"
                )
            ),
        ):
            module._check_security_txt("https://example.com", "example.com", findings)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "security.txt needs attention")
        self.assertEqual(findings[0].severity, Severity.LOW)
        self.assertIn("Expires is in the past", findings[0].evidence)

    def test_tech_stack_path_probe_uses_http_when_https_homepage_fails(self) -> None:
        calls: list[str] = []

        def fake_get(url: str, **_: object) -> FakeResponse:
            calls.append(url)
            if url == "https://example.com/":
                raise requests.RequestException("tls failed")
            if url == "http://example.com/":
                return FakeResponse(status_code=200, text="<html></html>")
            if url == "http://example.com/.env":
                return FakeResponse(status_code=200, text="SECRET=value")
            return FakeResponse(status_code=404, text="not found")

        config = ScanConfig(
            target="example.com",
            depth=ScanDepth.STANDARD,
            rate_limit=0,
        )
        with patch("modules.tech_stack.requests.get", side_effect=fake_get):
            findings = TechStackModule(config).run()

        self.assertIn("http://example.com/.env", calls)
        self.assertTrue(
            any(f.title == "Detected: Environment file exposure (/.env)" for f in findings)
        )


if __name__ == "__main__":
    unittest.main()
