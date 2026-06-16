"""Module 6 — Application-level checks (safe, detection-only)."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import json
from urllib.parse import urljoin, urlparse

from models import Finding, FindingCategory, ScanDepth, Severity
from modules.base import BaseModule
from modules.http_client import HttpRequestException

# GraphQL introspection query (read-only, no mutations)
_GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { name kind description }
  }
}
""".strip()

# Dangerous methods that are reported when advertised by the OPTIONS Allow header.
_DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "TRACE"}

# Common application-level checks (all read-only, no payloads)
_CHECKS: list[dict[str, str]] = [
    {
        "name": "CORS wildcard",
        "description": "Check if Access-Control-Allow-Origin is set to *",
        "header": "Access-Control-Allow-Origin",
        "bad_value": "*",
        "impact": "Any website can make cross-origin requests, potentially leaking data",
        "remediation": "Restrict CORS to specific trusted origins",
    },
    {
        "name": "X-XSS-Protection disabled",
        "description": "Check if X-XSS-Protection is explicitly set to 0",
        "header": "X-XSS-Protection",
        "bad_value": "0",
        "impact": "Browser XSS filter explicitly disabled",
        "remediation": "Remove X-XSS-Protection header (modern CSP is preferred) or set to '1; mode=block'",
    },
]

# Error / info paths that may reveal application details
_INFO_PATHS: list[tuple[str, str, list[str]]] = [
    ("/favicon.ico", "Favicon present", []),
    ("/sitemap.xml", "Sitemap exposed", []),
    ("/crossdomain.xml", "Flash cross-domain policy", ["allow-access-from"]),
    ("/clientaccesspolicy.xml", "Silverlight cross-domain policy", ["allow-from"]),
    ("/elmah.axd", "ELMAH error log exposed", ["error"]),
    ("/trace.axd", "ASP.NET trace exposed", ["trace"]),
    ("/phpinfo.php", "PHP info page exposed", ["phpinfo"]),
    ("/info.php", "PHP info page exposed", ["phpinfo"]),
    ("/debug", "Debug endpoint exposed", ["debug", "error", "traceback"]),
    ("/api", "API root accessible", []),
    ("/api/v1", "API v1 root accessible", []),
    ("/graphql", "GraphQL endpoint", ["query"]),
    ("/swagger", "Swagger UI exposed", ["swagger"]),
    ("/api-docs", "API documentation exposed", ["swagger", "openapi"]),
]

_MAX_DISCOVERED_ASSET_PAGES = 25


@dataclass(frozen=True)
class _AssetReference:
    tag: str
    attr: str
    url: str
    integrity: str
    crossorigin: str
    rel: str


class _AssetParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.assets: list[_AssetReference] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        for attr in ("src", "href", "action", "poster"):
            value = attr_map.get(attr)
            if value:
                self.assets.append(self._asset(tag, attr, value, attr_map))
        srcset = attr_map.get("srcset")
        if srcset:
            for value in _parse_srcset_urls(srcset):
                self.assets.append(self._asset(tag, "srcset", value, attr_map))

    def _asset(self, tag: str, attr: str, url: str, attr_map: dict[str, str]) -> _AssetReference:
        return _AssetReference(
            tag=tag.lower(),
            attr=attr,
            url=urljoin(self.base_url, url.strip()),
            integrity=attr_map.get("integrity", ""),
            crossorigin=attr_map.get("crossorigin", ""),
            rel=attr_map.get("rel", ""),
        )


def _parse_srcset_urls(value: str) -> list[str]:
    urls: list[str] = []
    for candidate in value.split(","):
        parts = candidate.strip().split()
        if parts:
            urls.append(parts[0])
    return urls


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return (parsed.scheme.lower(), parsed.hostname or "", parsed.port)


class AppChecksModule(BaseModule):
    name = "app_checks"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target

        if self.config.dry_run:
            findings.append(Finding(
                title="Application checks (dry-run)",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=f"Would run {len(_CHECKS) + len(_INFO_PATHS)} app-level checks on {target}",
            ))
            return findings

        base_url = f"https://{target}"

        # --- Fetch main page for header-based checks ---
        self._rate_limit()
        try:
            main_resp = self.http.get(
                f"{base_url}/",
                timeout=self.config.timeout,
                allow_redirects=True,
                verify=False,
                use_cache=True,
            )
        except HttpRequestException:
            # Fallback to HTTP
            base_url = f"http://{target}"
            self._rate_limit()
            try:
                main_resp = self.http.get(
                    f"{base_url}/",
                    timeout=self.config.timeout,
                    allow_redirects=True,
                    verify=False,
                    use_cache=True,
                )
            except HttpRequestException as exc:
                findings.append(Finding(
                    title="Could not reach target",
                    category=FindingCategory.APPLICATION,
                    severity=Severity.INFO,
                    evidence=str(exc),
                ))
                return findings

        # --- Header-based checks ---
        for check in _CHECKS:
            value = main_resp.headers.get(check["header"], "")
            if value.strip() == check["bad_value"]:
                findings.append(Finding(
                    title=check["name"],
                    category=FindingCategory.APPLICATION,
                    severity=Severity.MEDIUM,
                    evidence=f"{check['header']}: {value}",
                    impact=check["impact"],
                    remediation=check["remediation"],
                ))

        self._check_page_assets(base_url, main_resp.text, findings, is_homepage=True)
        self._check_discovered_page_assets(base_url, findings)

        # --- CORS preflight check ---
        self._rate_limit()
        try:
            cors_resp = self.http.options(
                f"{base_url}/",
                timeout=self.config.timeout,
                headers={
                    "Origin": "https://evil.example.com",
                    "Access-Control-Request-Method": "GET",
                },
                verify=False,
            )
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*" or acao == "https://evil.example.com":
                findings.append(Finding(
                    title="CORS allows arbitrary origins",
                    category=FindingCategory.APPLICATION,
                    severity=Severity.MEDIUM,
                    evidence=f"Access-Control-Allow-Origin: {acao} for Origin: https://evil.example.com",
                    impact="Cross-origin data theft possible",
                    remediation="Validate the Origin header against an allowlist",
                ))
        except HttpRequestException:
            pass

        # --- Path-based info checks ---
        if self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            for path, title, keywords in _INFO_PATHS:
                url = f"{base_url}{path}"
                self._rate_limit()
                try:
                    resp = self.http.get(
                        url,
                        timeout=self.config.timeout,
                        allow_redirects=False,
                        verify=False,
                    )
                except HttpRequestException:
                    continue

                if resp.status_code != 200:
                    continue

                body_lower = resp.text[:50_000].lower()

                # If keywords specified, require at least one match
                if keywords and not any(kw in body_lower for kw in keywords):
                    continue

                severity = Severity.INFO
                impact = ""
                remediation = ""

                if path in ("/phpinfo.php", "/info.php"):
                    severity = Severity.HIGH
                    impact = "Full PHP configuration exposed — aids targeted attacks"
                    remediation = "Remove phpinfo files from production"
                elif path in ("/elmah.axd", "/trace.axd"):
                    severity = Severity.HIGH
                    impact = "Application error details / stack traces exposed"
                    remediation = "Disable or restrict access to debug endpoints"
                elif path == "/debug":
                    severity = Severity.HIGH
                    impact = "Debug information may leak internal state"
                    remediation = "Disable debug mode in production"
                elif "swagger" in path or "api-docs" in path:
                    severity = Severity.LOW
                    impact = "API structure exposed — aids reconnaissance"
                    remediation = "Restrict Swagger/API docs to authenticated users"
                elif path == "/graphql":
                    severity = Severity.LOW
                    impact = "GraphQL endpoint may allow introspection"
                    remediation = "Disable GraphQL introspection in production"

                # Extra: run GraphQL introspection if the endpoint responds
                if path == "/graphql" and severity != Severity.INFO:
                    self._graphql_introspection(base_url, findings)

                findings.append(Finding(
                    title=title,
                    category=FindingCategory.APPLICATION,
                    severity=severity,
                    evidence=f"HTTP 200 at {url} ({len(resp.text)} bytes)",
                    impact=impact,
                    remediation=remediation,
                ))

        # --- HTTP method enumeration ---
        if self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            self._enumerate_http_methods(base_url, findings)

        return findings

    # -----------------------------------------------------------------------

    def _check_discovered_page_assets(self, base_url: str, findings: list[Finding]) -> None:
        checked = 0
        home_url = f"{base_url}/"
        for url in self.config.discovered_urls:
            if checked >= _MAX_DISCOVERED_ASSET_PAGES:
                break
            if url.rstrip("/") == home_url.rstrip("/"):
                continue
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                continue
            self._rate_limit()
            try:
                resp = self.http.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=True,
                    verify=False,
                    use_cache=True,
                )
            except HttpRequestException:
                continue
            if resp.status_code != 200:
                continue
            content_type = resp.headers.get("Content-Type", "")
            if content_type and "html" not in content_type.lower():
                continue
            checked += 1
            self._check_page_assets(url, resp.text, findings, is_homepage=False)

    def _check_page_assets(
        self,
        page_url: str,
        html: str,
        findings: list[Finding],
        *,
        is_homepage: bool,
    ) -> None:
        if not page_url.startswith("https://") or not html:
            return

        parser = _AssetParser(page_url)
        parser.feed(html[:500_000])
        mixed_content = [
            asset.url for asset in parser.assets
            if urlparse(asset.url).scheme.lower() == "http"
        ]
        if mixed_content:
            examples = ", ".join(mixed_content[:5])
            title = "Mixed content references found"
            if not is_homepage:
                title = f"Mixed content references found: {urlparse(page_url).path or '/'}"
            findings.append(Finding(
                title=title,
                category=FindingCategory.APPLICATION,
                severity=Severity.MEDIUM,
                evidence=f"{page_url} references insecure assets: {examples}",
                impact="Browsers may block active mixed content or load passive content over an interceptable channel",
                remediation="Load all page assets over HTTPS and replace hard-coded http:// URLs.",
                metadata={"url": page_url},
            ))

        page_origin = _origin(page_url)
        third_party_without_sri = [
            asset.url for asset in parser.assets
            if self._requires_sri(asset) and _origin(asset.url) != page_origin and not asset.integrity
        ]
        if third_party_without_sri:
            examples = ", ".join(third_party_without_sri[:5])
            title = "Subresource Integrity missing on third-party assets"
            if not is_homepage:
                title = f"Subresource Integrity missing on third-party assets: {urlparse(page_url).path or '/'}"
            findings.append(Finding(
                title=title,
                category=FindingCategory.APPLICATION,
                severity=Severity.LOW,
                evidence=f"{page_url} loads third-party script/stylesheet without integrity: {examples}",
                impact="If a third-party CDN or dependency is compromised, modified code may execute in users' browsers",
                remediation="Add integrity hashes and crossorigin attributes to third-party script and stylesheet tags.",
                metadata={"url": page_url},
            ))

    @staticmethod
    def _requires_sri(asset: _AssetReference) -> bool:
        parsed = urlparse(asset.url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        if asset.tag == "script" and asset.attr == "src":
            return True
        return asset.tag == "link" and asset.attr == "href" and "stylesheet" in asset.rel.lower().split()

    def _graphql_introspection(self, base_url: str, findings: list[Finding]) -> None:
        """Send a GraphQL introspection query to enumerate the schema."""
        self._rate_limit()
        try:
            resp = self.http.post(
                f"{base_url}/graphql",
                json={"query": _GRAPHQL_INTROSPECTION_QUERY},
                timeout=self.config.timeout,
                verify=False,
                headers={
                    "Content-Type": "application/json",
                },
            )
        except HttpRequestException:
            return

        if resp.status_code != 200:
            return

        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            return

        schema = data.get("data", {}).get("__schema")
        if not schema:
            # Introspection was blocked or returned no schema
            findings.append(Finding(
                title="GraphQL introspection disabled",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=f"POST /graphql returned HTTP 200 but introspection query returned no schema",
                impact="GraphQL schema enumeration is blocked — good security posture",
                remediation="",
            ))
            return

        type_names = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]
        mutation_type = schema.get("mutationType")
        findings.append(Finding(
            title="GraphQL introspection enabled",
            category=FindingCategory.APPLICATION,
            severity=Severity.MEDIUM,
            evidence=(
                f"Schema exposed: {len(type_names)} type(s): {', '.join(type_names[:15])}"
                + (" …" if len(type_names) > 15 else "")
                + (f". Mutations available: yes ({mutation_type['name']})" if mutation_type else ". No mutations.")
            ),
            impact=(
                "Full API schema exposed — attackers can enumerate all queries, mutations, "
                "types, and fields without authentication, accelerating API abuse"
            ),
            remediation=(
                "Disable introspection in production. "
                "In Apollo Server: introspection: false in server config. "
                "In Graphene: GRAPHENE = {'ATOMIC_MUTATIONS': True} and restrict introspection. "
                "Consider field-level authorization and depth/complexity limiting."
            ),
        ))

    def _enumerate_http_methods(self, base_url: str, findings: list[Finding]) -> None:
        """Probe which HTTP methods the server accepts on the root path."""
        # First try OPTIONS to get Allow header
        self._rate_limit()
        allowed_from_options: list[str] = []
        try:
            opt_resp = self.http.options(
                f"{base_url}/",
                timeout=self.config.timeout,
                verify=False,
            )
            allow_header = opt_resp.headers.get("Allow", "")
            if allow_header:
                allowed_from_options = [m.strip().upper() for m in allow_header.split(",")]
        except HttpRequestException:
            pass

        # Flag dangerous methods
        dangerous_allowed = _DANGEROUS_METHODS & set(allowed_from_options)

        if "TRACE" in allowed_from_options:
            findings.append(Finding(
                title="HTTP TRACE method enabled",
                category=FindingCategory.APPLICATION,
                severity=Severity.MEDIUM,
                evidence=f"OPTIONS /  →  Allow: {', '.join(allowed_from_options)}",
                impact=(
                    "HTTP TRACE allows Cross-Site Tracing (XST) attacks — "
                    "JavaScript can use TRACE to read HttpOnly cookies via reflected headers"
                ),
                remediation=(
                    "Disable TRACE in web server config. "
                    "Apache: TraceEnable Off. Nginx: rewrite, location, or limit_except. "
                    "IIS: Remove TRACE from allowed verbs."
                ),
            ))

        if dangerous_allowed - {"TRACE"}:
            findings.append(Finding(
                title=f"Potentially dangerous HTTP methods enabled: {', '.join(sorted(dangerous_allowed - {'TRACE'}))}",
                category=FindingCategory.APPLICATION,
                severity=Severity.LOW,
                evidence=f"OPTIONS /  →  Allow: {', '.join(allowed_from_options)}",
                impact=(
                    "PUT/DELETE/PATCH on root may allow unauthorized resource manipulation "
                    "if access controls are not enforced at the application layer"
                ),
                remediation=(
                    "Restrict HTTP methods at the web-server level to only those required. "
                    "Apache: <LimitExcept GET POST HEAD> Deny from all </LimitExcept>. "
                    "Nginx: limit_except GET POST { deny all; }."
                ),
            ))

        if allowed_from_options:
            findings.append(Finding(
                title="HTTP methods reported via OPTIONS",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=(
                    f"Allowed methods: {', '.join(allowed_from_options)}. "
                    "This is based on the Allow header; methods not advertised by the server may still exist."
                ),
            ))
