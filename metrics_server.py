"""A tiny HTTP server exposing the latest scan metrics for Prometheus to scrape.

Used in watch mode: the loop refreshes the held exposition text after each scan
cycle, and Prometheus pulls it from ``/metrics`` — the scrape-based alternative
to ``--metrics-push``. The held text is swapped under a lock so a scrape always
sees a complete document.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Type


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


class HealthState:
    """Thread-safe liveness/readiness state for the /healthz and /readyz endpoints.

    The process is *ready* once at least one scan cycle has completed; before that
    /readyz returns 503 so an orchestrator does not route to a not-yet-scanned
    instance. /healthz always returns 200 while the server can respond (liveness).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cycles = 0
        self._last_cycle_at = ""
        self._targets = 0
        self._ready = False

    def record_cycle(self, targets: int, when: str | None = None) -> None:
        with self._lock:
            self._cycles += 1
            self._targets = targets
            self._last_cycle_at = when or datetime.now(timezone.utc).isoformat()
            self._ready = True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "status": "ok",
                "ready": self._ready,
                "cycles": self._cycles,
                "targets": self._targets,
                "last_cycle_at": self._last_cycle_at,
            }

    def is_ready(self) -> bool:
        with self._lock:
            return self._ready


def _make_handler(
    holder: MetricsHolder | None, health: HealthState | None
) -> Type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.rstrip("/") or "/"
            if holder is not None and path in ("/", "/metrics"):
                self._send(200, holder.get().encode("utf-8"),
                           "text/plain; version=0.0.4; charset=utf-8")
            elif health is not None and path == "/healthz":
                self._send(200, json.dumps(health.snapshot()).encode("utf-8"), "application/json")
            elif health is not None and path == "/readyz":
                snap = health.snapshot()
                self._send(200 if health.is_ready() else 503,
                           json.dumps(snap).encode("utf-8"), "application/json")
            else:
                self.send_error(404, "not found")

        def log_message(self, *_args: object) -> None:
            # Stay quiet; scrape/health traffic would otherwise spam stderr.
            return

    return _Handler


def start_metrics_server(
    port: int,
    holder: MetricsHolder | None = None,
    *,
    health: HealthState | None = None,
    host: str = "0.0.0.0",
) -> ThreadingHTTPServer:
    """Start a background HTTP server serving /metrics, /healthz, and /readyz."""
    server = ThreadingHTTPServer((host, port), _make_handler(holder, health))
    thread = threading.Thread(target=server.serve_forever, name="metrics-http", daemon=True)
    thread.start()
    return server
