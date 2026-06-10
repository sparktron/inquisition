"""Module 9 — site crawler / URL-surface discovery.

The other modules probe a fixed list of well-known paths. Real coverage needs
to learn the site's actual URL surface, so this module discovers internal URLs
from three sources — homepage links, ``robots.txt``, and ``sitemap.xml`` — and
(at deep scan depth) follows a bounded number of internal pages one level
further. It reports the discovered surface and flags discovered paths that look
sensitive (admin panels, upload endpoints, debug routes, etc.).

It is deliberately bounded (capped URL count, capped pages fetched) and
same-origin only: it never follows links off the target host.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from models import Finding, FindingCategory, ScanDepth, Severity
from modules.base import BaseModule
from modules.http_client import HttpRequestException, HttpResponse

# Upper bounds keep a crawl polite and finite even on large sites.
_MAX_URLS = 250
_MAX_DEEP_PAGES = 15

# Attributes that carry URLs we care about for surface discovery.
_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#\s]+)["']""", re.IGNORECASE)
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

# Path fragments that suggest a sensitive or high-value endpoint worth review.
_SENSITIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("admin", "administrative interface"),
    ("login", "authentication endpoint"),
    ("signin", "authentication endpoint"),
    ("dashboard", "management dashboard"),
    ("upload", "file upload endpoint"),
    ("backup", "backup artifact"),
    ("config", "configuration resource"),
    ("debug", "debug endpoint"),
    ("internal", "internal-only resource"),
    ("staging", "non-production environment"),
    ("test", "test resource"),
    ("api", "API surface"),
    ("graphql", "GraphQL endpoint"),
    ("phpmyadmin", "database admin interface"),
    (".git", "exposed VCS metadata"),
    (".env", "environment/secret file"),
)


class CrawlerModule(BaseModule):
    name = "crawler"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target

        if self.config.dry_run:
            findings.append(Finding(
                title="Site crawl (dry-run)",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=(
                    f"Would discover URLs for {target} from homepage links, "
                    "robots.txt, and sitemap.xml"
                ),
            ))
            return findings

        base_url = self._resolve_base_url(target)
        if base_url is None:
            findings.append(Finding(
                title="Crawler could not reach target",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=f"Neither https://{target}/ nor http://{target}/ responded",
            ))
            return findings

        discovered: dict[str, str] = {}  # url -> source

        # --- Homepage links (all depths) ---
        home = self._fetch(base_url)
        if home is not None:
            for url in self._extract_links(base_url, home.text):
                discovered.setdefault(url, "homepage")

        # --- robots.txt + sitemap.xml (standard and deep) ---
        if self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            sitemap_urls = self._collect_from_robots(base_url, discovered)
            self._collect_from_sitemaps(base_url, sitemap_urls, discovered)

        # --- Bounded deep crawl one level further ---
        if self.config.depth == ScanDepth.DEEP:
            self._expand_deep(target, discovered)

        internal = {
            url: src for url, src in discovered.items()
            if self._same_origin(url, target)
        }

        if not internal:
            findings.append(Finding(
                title="No additional URLs discovered",
                category=FindingCategory.APPLICATION,
                severity=Severity.INFO,
                evidence=f"Crawl of {base_url} surfaced no internal links",
            ))
            return findings

        sample = sorted(internal)[:15]
        findings.append(Finding(
            title="Site URL surface discovered",
            category=FindingCategory.APPLICATION,
            severity=Severity.INFO,
            evidence=(
                f"Discovered {len(internal)} internal URL(s). "
                f"Sample: {', '.join(sample)}"
                + (" …" if len(internal) > len(sample) else "")
            ),
        ))

        # --- Flag sensitive-looking discovered paths ---
        for url in sorted(internal):
            label = self._sensitive_label(url)
            if label is None:
                continue
            descriptor, source = label, internal[url]
            findings.append(Finding(
                title=f"Sensitive path discovered: {urlparse(url).path or '/'}",
                category=FindingCategory.APPLICATION,
                severity=Severity.LOW,
                evidence=f"{url} ({descriptor}) — discovered via {source}",
                impact=(
                    "Discovered endpoints widen the attack surface; sensitive routes "
                    "should not be reachable or indexable if they are not meant to be public"
                ),
                remediation=(
                    "Confirm the endpoint is intended to be public; otherwise require "
                    "authentication, restrict by network, and remove it from sitemap/robots"
                ),
            ))

        return findings

    # -----------------------------------------------------------------------
    # Fetching
    # -----------------------------------------------------------------------

    def _resolve_base_url(self, target: str) -> str | None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/"
            if self._fetch(url) is not None:
                return url
        return None

    def _fetch(self, url: str) -> HttpResponse | None:
        self._rate_limit()
        try:
            return self.http.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=True,
                verify=False,
                use_cache=True,
            )
        except HttpRequestException:
            return None

    # -----------------------------------------------------------------------
    # Parsing
    # -----------------------------------------------------------------------

    def _extract_links(self, base_url: str, html: str) -> set[str]:
        urls: set[str] = set()
        for match in _LINK_RE.findall(html):
            if match.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            absolute = urljoin(base_url, match)
            if absolute.startswith(("http://", "https://")):
                urls.add(absolute.split("#")[0])
            if len(urls) >= _MAX_URLS:
                break
        return urls

    def _collect_from_robots(self, base_url: str, discovered: dict[str, str]) -> list[str]:
        """Parse robots.txt for Disallow/Allow paths and Sitemap URLs."""
        sitemap_urls: list[str] = []
        resp = self._fetch(urljoin(base_url, "/robots.txt"))
        if resp is None or resp.status_code != 200:
            return sitemap_urls
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if not value:
                continue
            if key in ("disallow", "allow"):
                if len(discovered) < _MAX_URLS:
                    discovered.setdefault(urljoin(base_url, value), "robots.txt")
            elif key == "sitemap":
                sitemap_urls.append(value)
        return sitemap_urls

    def _collect_from_sitemaps(
        self, base_url: str, extra_sitemaps: list[str], discovered: dict[str, str]
    ) -> None:
        """Parse sitemap.xml (and sitemap indexes) for <loc> URLs."""
        queue = [urljoin(base_url, "/sitemap.xml"), *extra_sitemaps]
        seen_sitemaps: set[str] = set()
        while queue and len(discovered) < _MAX_URLS:
            sitemap_url = queue.pop(0)
            if sitemap_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sitemap_url)

            resp = self._fetch(sitemap_url)
            if resp is None or resp.status_code != 200:
                continue
            text = resp.text
            is_index = "<sitemapindex" in text.lower()
            for loc in _LOC_RE.findall(text):
                loc = loc.strip()
                if is_index:
                    if loc not in seen_sitemaps:
                        queue.append(loc)
                elif len(discovered) < _MAX_URLS:
                    discovered.setdefault(loc, "sitemap.xml")

    def _expand_deep(self, target: str, discovered: dict[str, str]) -> None:
        """Fetch a bounded number of internal HTML pages to find deeper links."""
        seeds = [
            url for url in list(discovered)
            if self._same_origin(url, target)
        ][:_MAX_DEEP_PAGES]
        for url in seeds:
            if len(discovered) >= _MAX_URLS:
                break
            resp = self._fetch(url)
            if resp is None or resp.status_code != 200:
                continue
            content_type = resp.headers.get("Content-Type", "")
            if content_type and "html" not in content_type.lower():
                continue
            for found in self._extract_links(url, resp.text):
                discovered.setdefault(found, "deep-crawl")

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _same_origin(self, url: str, target: str) -> bool:
        host = urlparse(url).hostname or ""
        host = host.lower()
        target = target.lower()
        return host in (target, f"www.{target}") or f"www.{host}" == target

    def _sensitive_label(self, url: str) -> str | None:
        path = urlparse(url).path.lower()
        for fragment, descriptor in _SENSITIVE_PATTERNS:
            if fragment in path:
                return descriptor
        return None
