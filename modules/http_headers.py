"""Module 4 — HTTP header security audit."""

from __future__ import annotations

from typing import Any

import requests  # type: ignore[import-untyped]

from models import Finding, FindingCategory, Severity
from modules.base import BaseModule

# Headers that should be present for good security posture
_SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "impact": "Without HSTS, users can be downgraded from HTTPS to HTTP",
        "remediation": "Add Strict-Transport-Security header with max-age >= 31536000",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "impact": "Without CSP, XSS attacks are harder to mitigate",
        "remediation": "Implement a Content-Security-Policy header",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "impact": "Browsers may MIME-sniff responses, enabling attacks",
        "remediation": "Add X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": Severity.LOW,
        "impact": "Page may be embedded in iframes — clickjacking risk",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "impact": "Sensitive URLs may leak via Referer header",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "impact": "Browser features (camera, mic, geolocation) not restricted",
        "remediation": "Add a Permissions-Policy header",
    },
}

# Headers that reveal too much information
_LEAKY_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


class HttpHeaderModule(BaseModule):
    name = "http_headers"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target

        if self.config.dry_run:
            findings.append(Finding(
                title="HTTP header audit (dry-run)",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.INFO,
                evidence=f"Would fetch headers from https://{target}/ and http://{target}/",
            ))
            return findings

        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/"
            self._rate_limit()
            try:
                resp = requests.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=True,
                    verify=False,  # we inspect regardless of cert validity
                    headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
                )
            except requests.RequestException as exc:
                findings.append(Finding(
                    title=f"HTTP request failed ({scheme})",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.INFO,
                    evidence=f"{url}: {exc}",
                ))
                continue

            headers = resp.headers
            findings.append(Finding(
                title=f"HTTP {resp.status_code} from {url}",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.INFO,
                evidence=f"Status {resp.status_code}, {len(headers)} headers returned",
            ))

            # Check for missing security headers
            for header_name, meta in _SECURITY_HEADERS.items():
                if header_name.lower() not in {k.lower() for k in headers}:
                    findings.append(Finding(
                        title=f"Missing header: {header_name}",
                        category=FindingCategory.HTTP_HEADER,
                        severity=meta["severity"],
                        evidence=f"{url} does not return {header_name}",
                        impact=meta["impact"],
                        remediation=meta["remediation"],
                    ))

            # Check for leaky headers
            for header_name in _LEAKY_HEADERS:
                value = headers.get(header_name)
                if value:
                    findings.append(Finding(
                        title=f"Information disclosure: {header_name}",
                        category=FindingCategory.HTTP_HEADER,
                        severity=Severity.LOW,
                        evidence=f"{header_name}: {value}",
                        impact="Server technology/version disclosed — aids targeted attacks",
                        remediation=f"Remove or genericize the {header_name} header",
                    ))

            # Cookie security
            for cookie in resp.cookies:
                issues: list[str] = []
                if not cookie.secure:
                    issues.append("missing Secure flag")

                # HttpOnly detection: requests stores the flag in _rest dict (case-insensitive key)
                httponly_present = any(
                    k.lower() == "httponly"
                    for k in (cookie._rest or {})
                )
                if not httponly_present:
                    issues.append("missing HttpOnly flag")

                # SameSite detection
                samesite_val = next(
                    (v for k, v in (cookie._rest or {}).items() if k.lower() == "samesite"),
                    None,
                )
                if samesite_val is None:
                    issues.append("missing SameSite attribute")
                elif samesite_val.lower() == "none" and not cookie.secure:
                    issues.append("SameSite=None without Secure flag (rejected by modern browsers)")
                elif samesite_val.lower() not in ("strict", "lax", "none"):
                    issues.append(f"invalid SameSite value: {samesite_val!r}")

                if issues:
                    findings.append(Finding(
                        title=f"Insecure cookie: {cookie.name}",
                        category=FindingCategory.HTTP_HEADER,
                        severity=Severity.MEDIUM,
                        evidence=f"Cookie '{cookie.name}' — {', '.join(issues)}",
                        impact=(
                            "Cookie may be intercepted over HTTP (no Secure), "
                            "accessed by scripts (no HttpOnly), or sent in CSRF requests (no SameSite)"
                        ),
                        remediation=(
                            "Set Secure, HttpOnly, and SameSite=Strict (or Lax) on all cookies. "
                            "Example: Set-Cookie: session=…; Secure; HttpOnly; SameSite=Strict"
                        ),
                    ))

            # Only check HTTPS once for headers; HTTP mainly for redirect check
            if scheme == "http":
                if resp.url.startswith("https://"):
                    findings.append(Finding(
                        title="HTTP redirects to HTTPS",
                        category=FindingCategory.HTTP_HEADER,
                        severity=Severity.INFO,
                        evidence=f"http://{target}/ redirected to {resp.url}",
                    ))
                else:
                    findings.append(Finding(
                        title="No HTTP-to-HTTPS redirect",
                        category=FindingCategory.HTTP_HEADER,
                        severity=Severity.MEDIUM,
                        evidence=f"http://{target}/ did not redirect to HTTPS",
                        impact="Users may access the site over unencrypted HTTP",
                        remediation="Configure a 301 redirect from HTTP to HTTPS",
                    ))

        return findings
