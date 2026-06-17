"""Tests for graded-confidence signature detection."""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any, cast

from models import Confidence, ScanConfig, ScanDepth, combine_confidence
from modules.content_discovery import ContentDiscoveryModule
from modules.http_client import HttpRequestException
from modules.tech_stack import TechStackModule
from modules.waf_detection import WafDetectionModule


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


class CombineConfidenceTests(unittest.TestCase):
    def test_empty_is_low(self) -> None:
        self.assertEqual(combine_confidence([]), Confidence.LOW)

    def test_single_signal_is_unchanged(self) -> None:
        self.assertEqual(combine_confidence([Confidence.LOW]), Confidence.LOW)
        self.assertEqual(combine_confidence([Confidence.MEDIUM]), Confidence.MEDIUM)

    def test_two_signals_promote_one_tier(self) -> None:
        self.assertEqual(combine_confidence([Confidence.LOW, Confidence.LOW]), Confidence.MEDIUM)
        self.assertEqual(combine_confidence([Confidence.MEDIUM, Confidence.MEDIUM]), Confidence.HIGH)

    def test_promotion_uses_strongest_signal_first(self) -> None:
        # strongest is MEDIUM, two signals -> promoted to HIGH
        self.assertEqual(combine_confidence([Confidence.LOW, Confidence.MEDIUM]), Confidence.HIGH)

    def test_confirmed_is_the_ceiling(self) -> None:
        self.assertEqual(
            combine_confidence([Confidence.HIGH, Confidence.HIGH]), Confidence.CONFIRMED
        )


def _module(body: str = "", headers: dict[str, str] | None = None) -> TechStackModule:
    class FakeHttpClient:
        def get(self, url: str, **_: object) -> FakeResponse:
            if url.rstrip("/") == "https://example.com":
                return FakeResponse(status_code=200, text=body, headers=headers or {})
            raise HttpRequestException("404")

    config = ScanConfig(target="example.com", depth=ScanDepth.QUICK, rate_limit=0)
    return TechStackModule(config, http_client=cast(Any, FakeHttpClient()))


class TechStackConfidenceTests(unittest.TestCase):
    def _detect(self, tech: str, **kwargs: Any) -> Any:
        findings = _module(**kwargs).run()
        return next(f for f in findings if f.title == f"Detected: {tech}")

    def test_weak_single_signal_is_low(self) -> None:
        finding = self._detect("React", body="<div>built with react</div>")
        self.assertEqual(finding.confidence, Confidence.LOW)

    def test_medium_single_signal(self) -> None:
        finding = self._detect("Drupal", body="<meta name='generator' content='Drupal'>")
        self.assertEqual(finding.confidence, Confidence.MEDIUM)

    def test_corroborating_signals_raise_confidence(self) -> None:
        # Two strong WordPress path markers -> promoted, then capped at HIGH.
        finding = self._detect(
            "WordPress",
            body='<link href="/wp-content/x.css"><script src="/wp-includes/y.js">',
        )
        self.assertEqual(finding.confidence, Confidence.HIGH)
        # Both patterns are recorded as evidence.
        self.assertIn("/wp-content/", finding.evidence)
        self.assertIn("/wp-includes/", finding.evidence)

    def test_header_signal_is_high_and_carries_version(self) -> None:
        finding = self._detect("nginx 1.25.3", headers={"Server": "nginx/1.25.3"})
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertIn("1.25.3", finding.cpe)

    def test_body_and_header_corroborate_same_tech(self) -> None:
        # Body 'express' (LOW) + header X-Powered-By Express (MEDIUM) -> HIGH.
        finding = self._detect(
            "Express.js",
            body="<!-- express -->",
            headers={"X-Powered-By": "Express"},
        )
        self.assertEqual(finding.confidence, Confidence.HIGH)


@dataclass
class _WafResp:
    headers: dict[str, str]
    text: str = "<html></html>"
    status_code: int = 200
    cookies: tuple[Any, ...] = ()


class WafConfidenceTests(unittest.TestCase):
    def _run(self, headers: dict[str, str]) -> Any:
        resp = _WafResp(headers=headers)

        class FakeHttpClient:
            def get(self, url: str, **_: object) -> _WafResp:
                return resp

        config = ScanConfig(target="example.com", rate_limit=0)
        return WafDetectionModule(config, http_client=cast(Any, FakeHttpClient())).run()

    def test_corroborating_cloudflare_headers_combine_to_high(self) -> None:
        findings = self._run({"cf-ray": "abc-SJC", "server": "cloudflare"})
        cf = [f for f in findings if "Cloudflare" in f.title]
        self.assertEqual(len(cf), 1)  # one aggregated finding, not two
        self.assertEqual(cf[0].confidence, Confidence.HIGH)

    def test_generic_cache_header_is_low(self) -> None:
        findings = self._run({"x-cache": "HIT"})
        cache = next(f for f in findings if "cache layer" in f.title)
        self.assertEqual(cache.confidence, Confidence.LOW)


class ContentDiscoveryConfidenceTests(unittest.TestCase):
    def test_status_confidence_mapping(self) -> None:
        sc = ContentDiscoveryModule._status_confidence
        self.assertEqual(sc(200), Confidence.CONFIRMED)
        self.assertEqual(sc(403), Confidence.HIGH)
        self.assertEqual(sc(401), Confidence.HIGH)
        self.assertEqual(sc(301), Confidence.MEDIUM)
        self.assertEqual(sc(302), Confidence.MEDIUM)


if __name__ == "__main__":
    unittest.main()
