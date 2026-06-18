"""A tiny HTTP server exposing the latest scan metrics for Prometheus to scrape.

Used in watch mode: the loop refreshes the held exposition text after each scan
cycle, and Prometheus pulls it from ``/metrics`` — the scrape-based alternative
to ``--metrics-push``. The held text is swapped under a lock so a scrape always
sees a complete document.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Type


class MetricsHolder:
    """Thread-safe holder for the current metrics exposition text."""

    def __init__(self, text: str = "") -> None:
        self._text = text
        self._lock = threading.Lock()

    def set(self, text: str) -> None:
        with self._lock:
            self._text = text

    def get(self) -> str:
        with self._lock:
            return self._text


def _make_handler(holder: MetricsHolder) -> Type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            if self.path.rstrip("/") in ("", "/metrics"):
                body = holder.get().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404, "only /metrics is served")

        def log_message(self, *_args: object) -> None:
            # Stay quiet; scrape traffic would otherwise spam stderr every interval.
            return

    return _Handler


def start_metrics_server(
    port: int, holder: MetricsHolder, *, host: str = "0.0.0.0"
) -> ThreadingHTTPServer:
    """Start a background HTTP server serving ``holder`` text at /metrics."""
    server = ThreadingHTTPServer((host, port), _make_handler(holder))
    thread = threading.Thread(target=server.serve_forever, name="metrics-http", daemon=True)
    thread.start()
    return server
