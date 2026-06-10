"""Fingerprinting modules."""

from __future__ import annotations

from modules.dns_recon import DnsReconModule
from modules.port_scan import PortScanModule
from modules.tls_analysis import TlsAnalysisModule
from modules.http_headers import HttpHeaderModule
from modules.tech_stack import TechStackModule
from modules.app_checks import AppChecksModule
from modules.waf_detection import WafDetectionModule
from modules.content_discovery import ContentDiscoveryModule
from modules.crawler import CrawlerModule

ALL_MODULES: list[type] = [
    DnsReconModule,
    PortScanModule,
    TlsAnalysisModule,
    HttpHeaderModule,
    TechStackModule,
    AppChecksModule,
    WafDetectionModule,
    ContentDiscoveryModule,
    CrawlerModule,
]

__all__ = [
    "DnsReconModule",
    "PortScanModule",
    "TlsAnalysisModule",
    "HttpHeaderModule",
    "TechStackModule",
    "AppChecksModule",
    "WafDetectionModule",
    "ContentDiscoveryModule",
    "CrawlerModule",
    "ALL_MODULES",
]
