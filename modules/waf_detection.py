"""Module 7 — WAF / CDN / reverse-proxy fingerprinting.

Identifies edge infrastructure in front of the target.  Knowing whether a WAF
or CDN is present helps defenders verify that protective layers are active, and
helps pentesters understand what bypass techniques may be needed during an
authorised engagement.
"""

from __future__ import annotations

import re

from models import Confidence, Finding, FindingCategory, Severity, combine_confidence
from modules.base import BaseModule
from modules.http_client import HttpRequestException

_H = Confidence.HIGH
_M = Confidence.MEDIUM
_L = Confidence.LOW

# ---------------------------------------------------------------------------
# Signature tables
# ---------------------------------------------------------------------------

# (header_name, value_pattern, product_name, category, base confidence).
# Vendor-specific headers are HIGH; generic cache/score/proxy markers are weaker
# because unrelated infrastructure emits them too.
_HEADER_SIGS: list[tuple[str, str, str, str, Confidence]] = [
    ("server",                 r"cloudflare",              "Cloudflare CDN/WAF",        "CDN/WAF",     _H),
    ("cf-ray",                 r".",                        "Cloudflare CDN/WAF",        "CDN/WAF",     _H),
    ("x-amz-cf-id",            r".",                        "AWS CloudFront CDN",         "CDN",        _H),
    ("x-amz-request-id",       r".",                        "AWS S3 / CloudFront",        "CDN",        _M),
    ("x-cache",                r"cloudfront",              "AWS CloudFront CDN",         "CDN",        _H),
    ("x-served-by",            r"cache-",                  "Fastly CDN",                 "CDN",        _M),
    ("fastly-restarts",        r".",                        "Fastly CDN",                 "CDN",        _H),
    ("x-akamai-transformed",   r".",                        "Akamai CDN/WAF",             "CDN/WAF",    _H),
    ("x-check-cacheable",      r".",                        "Akamai CDN",                 "CDN",        _M),
    ("x-sucuri-id",            r".",                        "Sucuri WAF/CDN",             "CDN/WAF",    _H),
    ("x-fw-hash",              r".",                        "Sucuri Firewall",            "WAF",        _M),
    ("x-cdn",                  r"incapsula",               "Imperva Incapsula WAF",      "WAF",        _H),
    ("x-iinfo",                r".",                        "Imperva Incapsula WAF",      "WAF",        _H),
    ("x-protected-by",         r".",                        "Generic WAF protection",     "WAF",        _M),
    ("x-waf-score",            r".",                        "Generic WAF (score header)", "WAF",        _M),
    ("x-datadome",             r".",                        "DataDome Bot Protection",    "WAF",        _H),
    ("server",                 r"AkamaiGHost",             "Akamai CDN/WAF",             "CDN/WAF",    _H),
    ("via",                    r"varnish",                 "Varnish Cache",              "Cache",      _H),
    ("x-varnish",              r".",                        "Varnish Cache",              "Cache",      _H),
    ("x-cache",                r"HIT|MISS",                "Varnish/CDN cache layer",    "Cache",      _L),
    ("server",                 r"nginx/.*cloudflare",      "Cloudflare CDN/WAF",         "CDN/WAF",    _H),
    ("x-powered-by",           r"cloudflare",              "Cloudflare Workers",         "CDN",        _H),
    ("x-github-request-id",    r".",                        "GitHub Pages / CDN",         "CDN",        _H),
    ("x-vercel-id",            r".",                        "Vercel Edge Network",        "CDN",        _H),
    ("server",                 r"Netlify",                 "Netlify CDN",                "CDN",        _H),
    ("x-nf-request-id",        r".",                        "Netlify CDN",                "CDN",        _H),
    ("server",                 r"envoy",                   "Envoy Proxy",                "Proxy",      _H),
    ("server",                 r"traefik",                 "Traefik Reverse Proxy",      "Proxy",      _H),
    ("x-kong-upstream-latency",r".",                        "Kong API Gateway",           "API Gateway",_H),
    ("x-kong-proxy-latency",   r".",                        "Kong API Gateway",           "API Gateway",_H),
    ("apigw-requestid",        r".",                        "AWS API Gateway",            "API Gateway",_M),
]

# Cookie name patterns that indicate WAF presence (specific names -> HIGH).
_COOKIE_SIGS: list[tuple[str, str, Confidence]] = [
    (r"^__cfduid$|^cf_clearance$|^__cf_bm$", "Cloudflare CDN/WAF",        _H),
    (r"^visid_incap_|^incap_ses_",            "Imperva Incapsula WAF",     _H),
    (r"^sucuri_cloudproxy_uuid_",             "Sucuri WAF",                _H),
    (r"^_ddg\d+$",                            "DataDome Bot Protection",   _H),
    (r"^_abck$",                              "Akamai Bot Manager",        _H),
    (r"^ak_bmsc$",                            "Akamai Bot Manager",        _H),
]

# Response body markers (block pages are highly specific -> HIGH).
_BODY_SIGS: list[tuple[str, str, Confidence]] = [
    (r"cloudflare ray id",             "Cloudflare CDN/WAF",                _H),
    (r"attention required.*cloudflare","Cloudflare WAF Block Page",         _H),
    (r"sucuri website firewall",       "Sucuri WAF Block Page",             _H),
    (r"incapsula incident id",         "Imperva Incapsula WAF Block Page",  _H),
    (r"powered by akamai",             "Akamai CDN/WAF",                    _M),
    (r"<title>.*403.*forbidden.*akamai","Akamai WAF Block Page",            _H),
]


class _WafAccumulator:
    """Collects WAF/CDN signals per product so corroborating hits combine."""

    def __init__(self) -> None:
        self._signals: dict[str, list[tuple[Confidence, str]]] = {}
        self._category: dict[str, str] = {}

    def add(self, product: str, category: str, confidence: Confidence, evidence: str) -> None:
        self._signals.setdefault(product, []).append((confidence, evidence))
        self._category.setdefault(product, category)

    def __bool__(self) -> bool:
        return bool(self._signals)

    def emit(self) -> list[Finding]:
        findings: list[Finding] = []
        for product, signals in self._signals.items():
            confidence = combine_confidence([c for c, _ in signals])
            if confidence == Confidence.CONFIRMED:  # signatures stay heuristic
                confidence = Confidence.HIGH
            evidences: list[str] = []
            for _, evidence in signals:
                if evidence not in evidences:
                    evidences.append(evidence)
            findings.append(_make_finding(product, self._category[product], "; ".join(evidences), confidence))
        return findings


def _make_finding(product: str, category: str, evidence: str, confidence: Confidence) -> Finding:
    return Finding(
        title=f"{category} detected: {product}",
        category=FindingCategory.APPLICATION,
        severity=Severity.INFO,
        evidence=evidence,
        confidence=confidence,
        impact=(
            f"Confirms {product} is present. "
            "Verify WAF rules are actively enforced and not in monitor-only mode."
        ),
        remediation=(
            "Ensure WAF/CDN rules are up to date and set to block (not log-only). "
            "Review rate-limiting thresholds and geo-blocking policies."
        ),
    )


class WafDetectionModule(BaseModule):
    name = "waf_detection"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target

        if self.config.dry_run:
            findings.append(Finding(
                title="WAF/CDN detection (dry-run)",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=f"Would probe {target} for WAF/CDN/proxy signatures",
            ))
            return findings

        self._rate_limit()
        try:
            resp = self.http.get(
                f"https://{target}/",
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=True,
                use_cache=True,
            )
        except HttpRequestException:
            # Fall back to HTTP
            self._rate_limit()
            try:
                resp = self.http.get(
                    f"http://{target}/",
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=True,
                    use_cache=True,
                )
            except HttpRequestException:
                return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body_lower = resp.text[:20_000].lower()
        acc = _WafAccumulator()

        # --- Header-based detection ---
        for header, pattern, product, category, confidence in _HEADER_SIGS:
            value = headers_lower.get(header, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                acc.add(product, category, confidence, f"{header}: {value}")

        # --- Cookie-based detection ---
        for cookie in resp.cookies:
            for pattern, product, confidence in _COOKIE_SIGS:
                if re.search(pattern, cookie.name, re.IGNORECASE):
                    acc.add(product, "WAF", confidence, f"Cookie name: {cookie.name}")

        # --- Body-based detection ---
        for pattern, product, confidence in _BODY_SIGS:
            if re.search(pattern, body_lower):
                acc.add(product, "WAF block page", confidence, f"Body contains pattern: {pattern}")

        findings.extend(acc.emit())

        if not acc:
            findings.append(Finding(
                title="No WAF/CDN layer detected",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence="No known WAF/CDN response headers, cookies, or body signatures found",
                impact="Target may be directly exposed without an edge protection layer",
                remediation=(
                    "Consider placing the service behind a WAF or CDN (Cloudflare, AWS WAF, "
                    "Imperva) to add DDoS mitigation, bot filtering, and rate limiting"
                ),
            ))

        return findings
