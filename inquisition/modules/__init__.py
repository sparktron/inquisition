"""Fingerprinting modules."""

from __future__ import annotations

from inquisition.modules.dns_recon import DnsReconModule
from inquisition.modules.port_scan import PortScanModule
from inquisition.modules.tls_analysis import TlsAnalysisModule
from inquisition.modules.http_headers import HttpHeaderModule
from inquisition.modules.tech_stack import TechStackModule
from inquisition.modules.app_checks import AppChecksModule

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
