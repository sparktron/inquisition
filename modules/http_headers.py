"""Module 4 — HTTP header security audit."""

from __future__ import annotations

from urllib.parse import quote
from typing import Any

from models import Finding, FindingCategory, Severity
from modules.base import BaseModule
from modules.http_client import HttpRequestException

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

_MIN_HSTS_MAX_AGE = 31_536_000
_HSTS_PRELOAD_STATUS_URL = "https://hstspreload.org/api/v2/status?domain={domain}"
_SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
_SENSITIVE_PERMISSIONS = ("camera", "microphone", "geolocation", "payment", "usb")


def _header_value(headers: Any, name: str) -> str:
    """Return a header value using case-insensitive lookup."""
    value = headers.get(name)
    if value is not None:
        return str(value)
    name_lower = name.lower()
    for key, candidate in headers.items():
        if str(key).lower() == name_lower:
            return str(candidate)
    return ""


def _parse_directives(value: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, _, directive_value = part.partition("=")
        else:
            name, _, directive_value = part.partition(" ")
        directives[name.lower()] = directive_value.strip()
    return directives


def _parse_hsts_max_age(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return -1


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
                resp = self.http.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=True,
                    verify=False,  # we inspect regardless of cert validity
                    use_cache=True,
                )
            except HttpRequestException as exc:
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
            header_names = {k.lower() for k in headers}
            for header_name, meta in _SECURITY_HEADERS.items():
                if header_name.lower() not in header_names:
                    findings.append(Finding(
                        title=f"Missing header: {header_name}",
                        category=FindingCategory.HTTP_HEADER,
                        severity=meta["severity"],
                        evidence=f"{url} does not return {header_name}",
                        impact=meta["impact"],
                        remediation=meta["remediation"],
                    ))
                else:
                    self._check_header_quality(url, header_name, _header_value(headers, header_name), findings)

            if scheme == "https":
                hsts_value = _header_value(headers, "Strict-Transport-Security")
                if hsts_value:
                    self._check_hsts_preload_status(target, hsts_value, findings)

            # Check for leaky headers
            for header_name in _LEAKY_HEADERS:
                value = _header_value(headers, header_name)
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

                cookie_name_lower = cookie.name.lower()
                if cookie_name_lower.startswith("__secure-") and not cookie.secure:
                    issues.append("__Secure- prefix requires Secure flag")
                if cookie_name_lower.startswith("__host-"):
                    if not cookie.secure:
                        issues.append("__Host- prefix requires Secure flag")
                    if cookie.domain:
                        issues.append("__Host- prefix forbids Domain attribute")
                    if cookie.path != "/":
                        issues.append("__Host- prefix requires Path=/")

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

    def _check_header_quality(
        self,
        url: str,
        header_name: str,
        value: str,
        findings: list[Finding],
    ) -> None:
        if header_name == "Strict-Transport-Security":
            self._check_hsts_quality(url, value, findings)
        elif header_name == "Content-Security-Policy":
            self._check_csp_quality(url, value, findings)
        elif header_name == "X-Content-Type-Options":
            if value.strip().lower() != "nosniff":
                findings.append(Finding(
                    title="Weak header value: X-Content-Type-Options",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.LOW,
                    evidence=f"{url} returns X-Content-Type-Options: {value}",
                    impact="Browsers may still MIME-sniff responses if the header is not set to nosniff",
                    remediation="Set X-Content-Type-Options: nosniff",
                ))
        elif header_name == "X-Frame-Options":
            if value.strip().lower() not in ("deny", "sameorigin"):
                findings.append(Finding(
                    title="Weak header value: X-Frame-Options",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.LOW,
                    evidence=f"{url} returns X-Frame-Options: {value}",
                    impact="Unexpected frame policy values may not protect against clickjacking",
                    remediation="Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors",
                ))
        elif header_name == "Referrer-Policy":
            policy = value.strip().lower()
            if policy not in _SAFE_REFERRER_POLICIES:
                findings.append(Finding(
                    title="Weak header value: Referrer-Policy",
                    category=FindingCategory.HTTP_HEADER,
                    severity=Severity.LOW,
                    evidence=f"{url} returns Referrer-Policy: {value}",
                    impact="Sensitive URL paths or query strings may leak to third-party origins",
                    remediation="Use strict-origin-when-cross-origin, strict-origin, same-origin, or no-referrer",
                ))
        elif header_name == "Permissions-Policy":
            self._check_permissions_policy_quality(url, value, findings)

    def _check_hsts_quality(self, url: str, value: str, findings: list[Finding]) -> None:
        directives = _parse_directives(value)
        max_age_raw = directives.get("max-age", "")
        try:
            max_age = int(max_age_raw)
        except ValueError:
            findings.append(Finding(
                title="Weak HSTS policy: invalid max-age",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence=f"{url} returns Strict-Transport-Security: {value}",
                impact="Browsers may ignore malformed HSTS policies, leaving users vulnerable to SSL stripping",
                remediation="Set Strict-Transport-Security: max-age=31536000; includeSubDomains",
            ))
            return

        if max_age < _MIN_HSTS_MAX_AGE:
            findings.append(Finding(
                title="Weak HSTS policy: max-age too short",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence=f"{url} returns max-age={max_age}; expected at least {_MIN_HSTS_MAX_AGE}",
                impact="Short HSTS durations reduce protection against downgrade and SSL-stripping attacks",
                remediation="Set HSTS max-age to at least 31536000 seconds after confirming HTTPS works everywhere",
            ))
        if "includesubdomains" not in directives:
            findings.append(Finding(
                title="Weak HSTS policy: includeSubDomains missing",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.LOW,
                evidence=f"{url} returns Strict-Transport-Security: {value}",
                impact="Subdomains may remain vulnerable to HTTPS downgrade attacks",
                remediation="Add includeSubDomains once every subdomain supports HTTPS",
            ))
        if max_age >= _MIN_HSTS_MAX_AGE and "includesubdomains" in directives and "preload" not in directives:
            findings.append(Finding(
                title="HSTS preload directive missing",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.LOW,
                evidence=f"{url} returns Strict-Transport-Security: {value}",
                impact="First-time visitors remain exposed to HTTPS downgrade attacks until their browser sees HSTS",
                remediation="After validating HTTPS on all subdomains, add the preload directive and submit to hstspreload.org",
            ))

    def _check_hsts_preload_status(self, target: str, hsts_value: str, findings: list[Finding]) -> None:
        status_url = _HSTS_PRELOAD_STATUS_URL.format(domain=quote(target, safe=""))
        try:
            response = self.http.get(
                status_url,
                timeout=self.config.timeout,
                allow_redirects=True,
                verify=True,
            )
            payload = response.json()
        except (HttpRequestException, ValueError) as exc:
            findings.append(Finding(
                title="HSTS preload status check failed",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.INFO,
                evidence=f"{status_url}: {exc}",
            ))
            return

        if not isinstance(payload, dict):
            findings.append(Finding(
                title="HSTS preload status check failed",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.INFO,
                evidence=f"{status_url}: unexpected response payload",
            ))
            return

        status = str(payload.get("status", "unknown")).lower()
        if status == "preloaded":
            preloaded_domain = str(payload.get("preloadedDomain") or target)
            findings.append(Finding(
                title="HSTS preload active",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.INFO,
                evidence=f"{target} is preloaded via {preloaded_domain}",
            ))
            return
        if status == "pending":
            findings.append(Finding(
                title="HSTS preload pending",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.INFO,
                evidence=f"{target} is pending inclusion in the HSTS preload list",
            ))
            return

        directives = _parse_directives(hsts_value)
        preload_ready = (
            _parse_hsts_max_age(directives.get("max-age", "")) >= _MIN_HSTS_MAX_AGE
            and "includesubdomains" in directives
            and "preload" in directives
        )
        if preload_ready:
            findings.append(Finding(
                title="HSTS preload not active",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.LOW,
                evidence=f"{target} has a preload-ready HSTS header but preload status is {status}",
                impact="First-time visitors may still make an initial insecure HTTP request before HSTS is learned",
                remediation="Submit the domain at https://hstspreload.org/ and monitor until status is preloaded",
            ))


    def _check_csp_quality(self, url: str, value: str, findings: list[Finding]) -> None:
        directives = _parse_directives(value)
        script_src = directives.get("script-src", directives.get("default-src", ""))
        default_src = directives.get("default-src", "")

        if not default_src:
            findings.append(Finding(
                title="Weak CSP: default-src missing",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.LOW,
                evidence=f"{url} returns Content-Security-Policy: {value}",
                impact="Resources without explicit directives may fall back to overly broad browser defaults",
                remediation="Add a restrictive default-src directive, such as default-src 'self'",
            ))
        if "'unsafe-inline'" in script_src or "'unsafe-eval'" in script_src:
            findings.append(Finding(
                title="Weak CSP: unsafe script execution allowed",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence=f"{url} allows unsafe script sources: {script_src}",
                impact="CSP may not meaningfully mitigate XSS when unsafe-inline or unsafe-eval is allowed",
                remediation="Replace unsafe inline scripts with nonces or hashes and remove unsafe-eval",
            ))
        if "*" in script_src.split() or "*" in default_src.split():
            findings.append(Finding(
                title="Weak CSP: wildcard source allowed",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence=f"{url} returns Content-Security-Policy: {value}",
                impact="Wildcard sources allow arbitrary origins to provide scripts or other resources",
                remediation="Replace wildcard sources with explicit trusted origins",
            ))
        if "object-src" not in directives:
            findings.append(Finding(
                title="Weak CSP: object-src missing",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.LOW,
                evidence=f"{url} returns Content-Security-Policy: {value}",
                impact="Legacy plugin content may not be explicitly blocked",
                remediation="Add object-src 'none' to the Content-Security-Policy",
            ))
        if "frame-ancestors" not in directives:
            findings.append(Finding(
                title="Weak CSP: frame-ancestors missing",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.LOW,
                evidence=f"{url} returns Content-Security-Policy: {value}",
                impact="Clickjacking protection is not expressed in CSP",
                remediation="Add frame-ancestors 'none' or frame-ancestors 'self'",
            ))

    def _check_permissions_policy_quality(self, url: str, value: str, findings: list[Finding]) -> None:
        policy = value.lower().replace(" ", "")
        missing = [feature for feature in _SENSITIVE_PERMISSIONS if f"{feature}=" not in policy]
        permissive = [
            feature for feature in _SENSITIVE_PERMISSIONS
            if f"{feature}=*" in policy or f"{feature}=self" in policy or f"{feature}=(self)" in policy
        ]
        if missing:
            findings.append(Finding(
                title="Weak Permissions-Policy: sensitive features not restricted",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.LOW,
                evidence=f"{url} does not explicitly restrict: {', '.join(missing)}",
                impact="Browser features may be available to pages or embedded content unless restricted elsewhere",
                remediation="Explicitly disable unused sensitive features, e.g. camera=(), microphone=(), geolocation=()",
            ))
        if permissive:
            findings.append(Finding(
                title="Weak Permissions-Policy: sensitive features allowed",
                category=FindingCategory.HTTP_HEADER,
                severity=Severity.MEDIUM,
                evidence=f"{url} allows sensitive features: {', '.join(permissive)}",
                impact="Compromised scripts or embedded content may request access to sensitive browser capabilities",
                remediation="Disable unused sensitive features with empty allowlists, e.g. camera=(), microphone=()",
            ))
