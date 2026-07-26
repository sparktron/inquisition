from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any, cast

from models import ScanConfig
from modules.http_client import HttpClient


@dataclass
class FakeSession:
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        return FakeResponse(url=url)


@dataclass
class FakeResponse:
    url: str
    status_code: int = 200
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    cookies: tuple[()] = ()

    def json(self) -> object:
        return {}


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

    def test_auth_credentials_are_injected_into_requests(self) -> None:
        config = ScanConfig(
            target="example.test",
            auth_header="Authorization: Bearer abc123",
            auth_cookie="session=xyz",
        )
        client = HttpClient(config)
        session = FakeSession()
        client.session = cast(Any, session)

        client.get("https://example.test/")
        headers = session.calls[0][2]["headers"]
        self.assertEqual(headers["Authorization"], "Bearer abc123")
        self.assertEqual(headers["Cookie"], "session=xyz")

    def test_no_auth_headers_when_unconfigured(self) -> None:
        client = HttpClient(ScanConfig(target="example.test"))
        session = FakeSession()
        client.session = cast(Any, session)

        client.get("https://example.test/")
        headers = session.calls[0][2]["headers"]
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Cookie", headers)

    def test_redirects_retain_secrets_same_origin_and_strip_them_cross_origin(self) -> None:
        received: dict[str, dict[str, str]] = {}

        class DestinationHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                received[self.path] = {key: value for key, value in self.headers.items()}
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                pass

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)
        destination_thread = Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()
        destination_url = f"http://127.0.0.1:{destination.server_port}/cross-origin"

        class OriginHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", "/same-origin")
                else:
                    received[self.path] = {key: value for key, value in self.headers.items()}
                    self.send_response(302)
                    self.send_header("Location", destination_url)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                pass

        origin = ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
        origin_thread = Thread(target=origin.serve_forever, daemon=True)
        origin_thread.start()
        try:
            config = ScanConfig(
                target="127.0.0.1",
                auth_header="X-API-Key: top-secret",
                auth_cookie="session=also-secret",
            )
            client = HttpClient(config)
            client.get(f"http://127.0.0.1:{origin.server_port}/start")
        finally:
            origin.shutdown()
            origin.server_close()
            destination.shutdown()
            destination.server_close()
            origin_thread.join()
            destination_thread.join()

        same_origin_headers = received["/same-origin"]
        self.assertEqual(same_origin_headers.get("X-API-Key"), "top-secret")
        self.assertEqual(same_origin_headers.get("Cookie"), "session=also-secret")
        cross_origin_headers = received["/cross-origin"]
        self.assertNotIn("X-API-Key", cross_origin_headers)
        self.assertNotIn("Cookie", cross_origin_headers)

    def test_cross_origin_redirect_strips_per_request_standard_secrets(self) -> None:
        received: dict[str, str] = {}

        class DestinationHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                received.update({key: value for key, value in self.headers.items()})
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                pass

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)
        destination_thread = Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()
        destination_url = f"http://127.0.0.1:{destination.server_port}/destination"

        class OriginHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", destination_url)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                pass

        origin = ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
        origin_thread = Thread(target=origin.serve_forever, daemon=True)
        origin_thread.start()
        try:
            client = HttpClient(ScanConfig(target="127.0.0.1"))
            client.get(
                f"http://127.0.0.1:{origin.server_port}/start",
                headers={
                    "Authorization": "Bearer request-secret",
                    "Proxy-Authorization": "Basic proxy-secret",
                    "Cookie": "request-cookie=secret",
                },
            )
        finally:
            origin.shutdown()
            origin.server_close()
            destination.shutdown()
            destination.server_close()
            origin_thread.join()
            destination_thread.join()

        self.assertNotIn("Authorization", received)
        self.assertNotIn("Proxy-Authorization", received)
        self.assertNotIn("Cookie", received)


if __name__ == "__main__":
    unittest.main()
