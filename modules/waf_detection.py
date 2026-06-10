"""Module 7 — WAF / CDN / reverse-proxy fingerprinting.

Identifies edge infrastructure in front of the target.  Knowing whether a WAF
or CDN is present helps defenders verify that protective layers are active, and
helps pentesters understand what bypass techniques may be needed during an
authorised engagement.
"""

from __future__ import annotations

import re

import requests  # type: ignore[import-untyped]

from models import Finding, FindingCategory, Severity
from modules.base import BaseModule


# ---------------------------------------------------------------------------
# Signature tables
# ---------------------------------------------------------------------------

# (header_name, value_pattern, product_name, category, remediation_hint)
_HEADER_SIGS: list[tuple[str, str, str, str]] = [
    ("server",                 r"cloudflare",              "Cloudflare CDN/WAF",        "CDN/WAF"),
    ("cf-ray",                 r".",                        "Cloudflare CDN/WAF",        "CDN/WAF"),
    ("x-amz-cf-id",            r".",                        "AWS CloudFront CDN",         "CDN"),
    ("x-amz-request-id",       r".",                        "AWS S3 / CloudFront",        "CDN"),
    ("x-cache",                r"cloudfront",              "AWS CloudFront CDN",         "CDN"),
    ("x-served-by",            r"cache-",                  "Fastly CDN",                 "CDN"),
    ("fastly-restarts",        r".",                        "Fastly CDN",                 "CDN"),
    ("x-akamai-transformed",   r".",                        "Akamai CDN/WAF",             "CDN/WAF"),
    ("x-check-cacheable",      r".",                        "Akamai CDN",                 "CDN"),
    ("x-sucuri-id",            r".",                        "Sucuri WAF/CDN",             "CDN/WAF"),
    ("x-fw-hash",              r".",                        "Sucuri Firewall",            "WAF"),
    ("x-cdn",                  r"incapsula",               "Imperva Incapsula WAF",      "WAF"),
    ("x-iinfo",                r".",                        "Imperva Incapsula WAF",      "WAF"),
    ("x-protected-by",         r".",                        "Generic WAF protection",     "WAF"),
    ("x-waf-score",            r".",                        "Generic WAF (score header)", "WAF"),
    ("x-datadome",             r".",                        "DataDome Bot Protection",    "WAF"),
    ("server",                 r"AkamaiGHost",             "Akamai CDN/WAF",             "CDN/WAF"),
    ("via",                    r"varnish",                 "Varnish Cache",              "Cache"),
    ("x-varnish",              r".",                        "Varnish Cache",              "Cache"),
    ("x-cache",                r"HIT|MISS",                "Varnish/CDN cache layer",    "Cache"),
    ("server",                 r"nginx/.*cloudflare",      "Cloudflare CDN/WAF",         "CDN/WAF"),
    ("x-powered-by",           r"cloudflare",              "Cloudflare Workers",         "CDN"),
    ("x-github-request-id",    r".",                        "GitHub Pages / CDN",         "CDN"),
    ("x-vercel-id",            r".",                        "Vercel Edge Network",        "CDN"),
    ("server",                 r"Netlify",                 "Netlify CDN",                "CDN"),
    ("x-nf-request-id",        r".",                        "Netlify CDN",                "CDN"),
    ("server",                 r"envoy",                   "Envoy Proxy",                "Proxy"),
    ("server",                 r"traefik",                 "Traefik Reverse Proxy",      "Proxy"),
    ("x-kong-upstream-latency",r".",                        "Kong API Gateway",           "API Gateway"),
    ("x-kong-proxy-latency",   r".",                        "Kong API Gateway",           "API Gateway"),
    ("apigw-requestid",        r".",                        "AWS API Gateway",            "API Gateway"),
]

# Cookie name patterns that indicate WAF presence
_COOKIE_SIGS: list[tuple[str, str]] = [
    (r"^__cfduid$|^cf_clearance$|^__cf_bm$", "Cloudflare CDN/WAF"),
    (r"^visid_incap_|^incap_ses_",            "Imperva Incapsula WAF"),
    (r"^sucuri_cloudproxy_uuid_",             "Sucuri WAF"),
    (r"^_ddg\d+$",                            "DataDome Bot Protection"),
    (r"^_abck$",                              "Akamai Bot Manager"),
    (r"^ak_bmsc$",                            "Akamai Bot Manager"),
]

# Response body markers (after stripping)
_BODY_SIGS: list[tuple[str, str]] = [
    (r"cloudflare ray id",             "Cloudflare CDN/WAF"),
    (r"attention required.*cloudflare","Cloudflare WAF Block Page"),
    (r"sucuri website firewall",       "Sucuri WAF Block Page"),
    (r"incapsula incident id",         "Imperva Incapsula WAF Block Page"),
    (r"powered by akamai",             "Akamai CDN/WAF"),
    (r"<title>.*403.*forbidden.*akamai","Akamai WAF Block Page"),
]


class WafDetectionModule(BaseModule):
    name = "waf_detection"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target
        detected: set[str] = set()

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
            resp = requests.get(
                f"https://{target}/",
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
            )
        except requests.RequestException:
            # Fall back to HTTP
            self._rate_limit()
            try:
                resp = requests.get(
                    f"http://{target}/",
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
                )
            except requests.RequestException:
                return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body_lower = resp.text[:20_000].lower()

        # --- Header-based detection ---
        for header, pattern, product, category in _HEADER_SIGS:
            value = headers_lower.get(header, "")
            if value and re.search(pattern, value, re.IGNORECASE) and product not in detected:
                detected.add(product)
                findings.append(self._make_finding(product, category, f"{header}: {value}"))

        # --- Cookie-based detection ---
        for cookie in resp.cookies:
            for pattern, product in _COOKIE_SIGS:
                if re.search(pattern, cookie.name, re.IGNORECASE) and product not in detected:
                    detected.add(product)
                    findings.append(self._make_finding(product, "WAF", f"Cookie name: {cookie.name}"))

        # --- Body-based detection ---
        for pattern, product in _BODY_SIGS:
            if re.search(pattern, body_lower) and product not in detected:
                detected.add(product)
                findings.append(self._make_finding(product, "WAF block page", f"Body contains pattern: {pattern}"))

        if not detected:
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

    @staticmethod
    def _make_finding(product: str, category: str, evidence: str) -> Finding:
        return Finding(
            title=f"{category} detected: {product}",
            category=FindingCategory.APPLICATION,
            severity=Severity.INFO,
            evidence=evidence,
            impact=(
                f"Confirms {product} is present. "
                "Verify WAF rules are actively enforced and not in monitor-only mode."
            ),
            remediation=(
                "Ensure WAF/CDN rules are up to date and set to block (not log-only). "
                "Review rate-limiting thresholds and geo-blocking policies."
            ),
        )
