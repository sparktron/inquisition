from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import Any, cast

from models import ScanConfig
from modules.http_client import HttpClient


@dataclass
class FakeSession:
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)

    def request(self, method: str, url: str, **kwargs: Any) -> object:
        self.calls.append((method, url, kwargs))
        return object()


class HttpClientTests(unittest.TestCase):
    def test_cached_get_reuses_session_response(self) -> None:
        client = HttpClient(ScanConfig(target="example.test", timeout=7))
        session = FakeSession()
        client.session = cast(Any, session)

        first = client.get("https://example.test/", use_cache=True)
        second = client.get("https://example.test/", use_cache=True)
        third = client.get("https://example.test/", use_cache=False)

        self.assertIs(first, second)
        self.assertIsNot(second, third)
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(session.calls[0][0], "GET")
        self.assertEqual(session.calls[0][2]["timeout"], 7)
        self.assertEqual(
            session.calls[0][2]["headers"]["User-Agent"],
            "Inquisition/0.1 SecurityScanner",
        )

    def test_cache_key_respects_redirect_behavior(self) -> None:
        client = HttpClient(ScanConfig(target="example.test"))
        session = FakeSession()
        client.session = cast(Any, session)

        redirected = client.get("https://example.test/", allow_redirects=True, use_cache=True)
        not_redirected = client.get("https://example.test/", allow_redirects=False, use_cache=True)

        self.assertIsNot(redirected, not_redirected)
        self.assertEqual(len(session.calls), 2)


if __name__ == "__main__":
    unittest.main()
