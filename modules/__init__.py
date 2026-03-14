"""Fingerprinting modules."""

from __future__ import annotations

from modules.dns_recon import DnsReconModule
from modules.port_scan import PortScanModule
from modules.tls_analysis import TlsAnalysisModule
from modules.http_headers import HttpHeaderModule
from modules.tech_stack import TechStackModule
from modules.app_checks import AppChecksModule

ALL_MODULES: list[type] = [
    DnsReconModule,
    PortScanModule,
    TlsAnalysisModule,
    HttpHeaderModule,
    TechStackModule,
    AppChecksModule,
]

__all__ = [
    "DnsReconModule",
    "PortScanModule",
    "TlsAnalysisModule",
    "HttpHeaderModule",
    "TechStackModule",
    "AppChecksModule",
    "ALL_MODULES",
]
