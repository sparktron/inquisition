from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import Any, cast

from models import ScanConfig, ScanDepth
from modules.crawler import CrawlerModule
from modules.http_client import HttpRequestException


@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, pages: dict[str, FakeResponse]) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def get(self, url: str, **_: object) -> FakeResponse:
        self.requested.append(url)
        return self.pages.get(url, FakeResponse(status_code=404, text="not found"))


def _module(pages: dict[str, FakeResponse], depth: ScanDepth = ScanDepth.STANDARD) -> CrawlerModule:
    config = ScanConfig(target="example.com", depth=depth, rate_limit=0)
    return CrawlerModule(config, http_client=cast(Any, FakeHttpClient(pages)))


class CrawlerTests(unittest.TestCase):
    def test_dry_run_returns_single_info(self) -> None:
        config = ScanConfig(target="example.com", dry_run=True, rate_limit=0)
        findings = CrawlerModule(config, http_client=cast(Any, FakeHttpClient({}))).run()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Site crawl (dry-run)")

    def test_discovers_links_robots_and_sitemap(self) -> None:
        pages = {
            "https://example.com/": FakeResponse(text=(
                '<a href="/about">About</a>'
                '<a href="/admin/login">Admin</a>'
                '<a href="https://external.test/evil">External</a>'
            )),
            "https://example.com/robots.txt": FakeResponse(text=(
                "User-agent: *\n"
                "Disallow: /secret-backup\n"
                "Sitemap: https://example.com/sitemap.xml\n"
            )),
            "https://example.com/sitemap.xml": FakeResponse(text=(
                "<urlset><url><loc>https://example.com/dashboard</loc></url></urlset>"
            )),
        }
        findings = _module(pages).run()
        titles = [f.title for f in findings]
        evidence_blob = " ".join(f.evidence for f in findings)

        self.assertIn("Site URL surface discovered", titles)
        summary = next(f for f in findings if f.title == "Site URL surface discovered")
        self.assertIn("https://example.com/about", summary.metadata["discovered_urls"])
        # External host is excluded from the internal surface.
        self.assertNotIn("external.test", evidence_blob)
        # Sensitive paths from each source are flagged.
        sensitive = {f.evidence for f in findings if f.title.startswith("Sensitive path discovered")}
        self.assertTrue(any("/admin/login" in e and "homepage" in e for e in sensitive))
        self.assertTrue(any("/secret-backup" in e and "robots.txt" in e for e in sensitive))
        self.assertTrue(any("/dashboard" in e and "sitemap.xml" in e for e in sensitive))

    def test_sitemap_index_is_followed(self) -> None:
        pages = {
            "https://example.com/": FakeResponse(text="<html></html>"),
            "https://example.com/sitemap.xml": FakeResponse(text=(
                "<sitemapindex><sitemap><loc>https://example.com/sm1.xml</loc></sitemap></sitemapindex>"
            )),
            "https://example.com/sm1.xml": FakeResponse(text=(
                "<urlset><url><loc>https://example.com/admin</loc></url></urlset>"
            )),
        }
        findings = _module(pages).run()
        sensitive = [f for f in findings if f.title.startswith("Sensitive path discovered")]
        self.assertTrue(any("/admin" in f.evidence for f in sensitive))

    def test_external_sitemaps_are_never_requested(self) -> None:
        pages = {
            "https://example.com/": FakeResponse(text="<html></html>"),
            "https://example.com/robots.txt": FakeResponse(text=(
                "Sitemap: https://external.test/from-robots.xml\n"
            )),
            "https://example.com/sitemap.xml": FakeResponse(text=(
                "<sitemapindex>"
                "<sitemap><loc>https://external.test/nested.xml</loc></sitemap>"
                "<sitemap><loc>https://example.com/internal.xml</loc></sitemap>"
                "</sitemapindex>"
            )),
            "https://example.com/internal.xml": FakeResponse(text=(
                "<urlset><url><loc>https://example.com/admin</loc></url></urlset>"
            )),
        }
        client = FakeHttpClient(pages)
        config = ScanConfig(target="example.com", rate_limit=0)

        findings = CrawlerModule(config, http_client=cast(Any, client)).run()

        self.assertFalse(any("external.test" in url for url in client.requested))
        self.assertTrue(any("/admin" in finding.evidence for finding in findings))

    def test_sitemap_origin_includes_scheme_and_effective_port(self) -> None:
        pages = {
            "https://example.com/": FakeResponse(text="<html></html>"),
            "https://example.com/robots.txt": FakeResponse(text=(
                "Sitemap: http://example.com/insecure.xml\n"
                "Sitemap: https://example.com:444/other-port.xml\n"
            )),
            "https://example.com/sitemap.xml": FakeResponse(text="<urlset></urlset>"),
        }
        client = FakeHttpClient(pages)
        config = ScanConfig(target="example.com", rate_limit=0)

        CrawlerModule(config, http_client=cast(Any, client)).run()

        self.assertNotIn("http://example.com/insecure.xml", client.requested)
        self.assertNotIn("https://example.com:444/other-port.xml", client.requested)

    def test_no_internal_links_reports_empty_surface(self) -> None:
        pages = {
            "https://example.com/": FakeResponse(text='<a href="https://external.test/x">x</a>'),
        }
        findings = _module(pages).run()
        self.assertIn("No additional URLs discovered", [f.title for f in findings])

    def test_unreachable_target_is_reported(self) -> None:
        class RaisingHttpClient:
            def get(self, url: str, **_: object) -> FakeResponse:
                raise HttpRequestException("connection refused")

        config = ScanConfig(target="example.com", rate_limit=0)
        findings = CrawlerModule(config, http_client=cast(Any, RaisingHttpClient())).run()
        self.assertIn("Crawler could not reach target", [f.title for f in findings])


if __name__ == "__main__":
    unittest.main()
