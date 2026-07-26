"""Shared HTTP client for scanner modules."""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from typing import Any, Protocol, cast
from urllib.parse import urljoin, urlparse

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
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 10
_STANDARD_SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie"}


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
        self._session_lock = threading.Lock()
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
        # Start with the configured credentials, then let a module add or
        # replace request-specific headers for this one call.
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
                # Modules often inspect the same homepage independently.  A
                # shared cached GET reduces duplicate traffic to the target.
                return cached

        response = self._request_with_redirects(
            normalized_method,
            url,
            json=json,
            timeout=self.config.timeout if timeout is None else timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            headers=merged_headers,
        )

        if use_cache and normalized_method == "GET":
            with self._lock:
                self._cache[cache_key] = response
        return response

    def _request_with_redirects(
        self,
        method: str,
        url: str,
        *,
        json: dict[str, Any] | None,
        timeout: float,
        allow_redirects: bool,
        verify: bool,
        headers: dict[str, str],
    ) -> HttpResponse:
        """Follow bounded redirects without forwarding configured secrets cross-origin."""
        current_method = method
        current_url = url
        current_json = json
        current_headers = dict(headers)
        secret_names = _STANDARD_SECRET_HEADERS | {
            name.lower() for name in self._auth_headers
        }

        for redirect_count in range(_MAX_REDIRECTS + 1):
            with self._session_lock:
                response = cast(
                    HttpResponse,
                    self.session.request(
                        current_method,
                        current_url,
                        json=current_json,
                        timeout=timeout,
                        allow_redirects=False,
                        verify=verify,
                        headers=current_headers,
                    ),
                )

            location = response.headers.get("Location") or response.headers.get("location")
            if (
                not allow_redirects
                or response.status_code not in _REDIRECT_STATUSES
                or not location
            ):
                return response
            if redirect_count == _MAX_REDIRECTS:
                raise requests.TooManyRedirects(f"Exceeded {_MAX_REDIRECTS} redirects")

            next_url = urljoin(current_url, location)
            if _normalized_origin(next_url) is None:
                # Do not follow a malformed or non-HTTP(S) Location header.
                return response
            if _normalized_origin(current_url) != _normalized_origin(next_url):
                # A redirect to another scheme, host, or port is a boundary:
                # never leak configured secrets to the new origin.
                current_headers = {
                    name: value
                    for name, value in current_headers.items()
                    if name.lower() not in secret_names
                }

            if response.status_code == 303 or (
                response.status_code in {301, 302} and current_method == "POST"
            ):
                # Match normal browser semantics: redirected form submissions
                # continue as a GET and must not resend their JSON body.
                current_method = "GET"
                current_json = None
            current_url = next_url

        raise AssertionError("redirect loop terminated unexpectedly")


def _normalized_origin(url: str) -> tuple[str, str, int] | None:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"} or not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    # Include the effective default port so https://site and
    # https://site:443 compare as the same origin.
    return scheme, host, port if port is not None else (443 if scheme == "https" else 80)
