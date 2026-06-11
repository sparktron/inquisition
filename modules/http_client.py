"""Shared HTTP client for scanner modules."""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from typing import Any, Protocol, cast

import requests  # type: ignore[import-untyped]

from models import ScanConfig


HttpRequestException = requests.RequestException


class HttpResponse(Protocol):
    status_code: int
    text: str
    headers: Mapping[str, str]
    url: str
    content: bytes
    cookies: Iterable[Any]

    def json(self) -> Any:
        ...

_USER_AGENT = "Inquisition/0.1 SecurityScanner"


def _build_auth_headers(config: ScanConfig) -> dict[str, str]:
    """Build authentication headers (for authenticated scanning) from config."""
    headers: dict[str, str] = {}
    if config.auth_header and ":" in config.auth_header:
        name, _, value = config.auth_header.partition(":")
        headers[name.strip()] = value.strip()
    if config.auth_cookie:
        headers["Cookie"] = config.auth_cookie.strip()
    return headers


class HttpClient:
    """Small wrapper around one requests.Session plus explicit GET caching."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self._cache: dict[tuple[str, str, bool, bool, tuple[tuple[str, str], ...]], HttpResponse] = {}
        self._lock = threading.Lock()
        self._auth_headers = _build_auth_headers(config)

    def get(
        self,
        url: str,
        *,
        timeout: float | None = None,
        allow_redirects: bool = True,
        verify: bool = False,
        headers: dict[str, str] | None = None,
        use_cache: bool = False,
    ) -> HttpResponse:
        return self.request(
            "GET",
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            headers=headers,
            use_cache=use_cache,
        )

    def options(
        self,
        url: str,
        *,
        timeout: float | None = None,
        verify: bool = False,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        return self.request("OPTIONS", url, timeout=timeout, verify=verify, headers=headers)

    def post(
        self,
        url: str,
        *,
        json: dict[str, Any] | None = None,
        timeout: float | None = None,
        verify: bool = False,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        return self.request("POST", url, json=json, timeout=timeout, verify=verify, headers=headers)

    def request(
        self,
        method: str,
        url: str,
        *,
        json: dict[str, Any] | None = None,
        timeout: float | None = None,
        allow_redirects: bool = True,
        verify: bool = False,
        headers: dict[str, str] | None = None,
        use_cache: bool = False,
    ) -> HttpResponse:
        merged_headers = {"User-Agent": _USER_AGENT}
        merged_headers.update(self._auth_headers)
        if headers:
            merged_headers.update(headers)

        normalized_method = method.upper()
        cache_key = (
            normalized_method,
            url,
            allow_redirects,
            verify,
            tuple(sorted(merged_headers.items())),
        )
        if use_cache and normalized_method == "GET":
            with self._lock:
                cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        response = cast(
            HttpResponse,
            self.session.request(
                normalized_method,
                url,
                json=json,
                timeout=self.config.timeout if timeout is None else timeout,
                allow_redirects=allow_redirects,
                verify=verify,
                headers=merged_headers,
            ),
        )

        if use_cache and normalized_method == "GET":
            with self._lock:
                self._cache[cache_key] = response
        return response
