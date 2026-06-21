"""Module 5 — Technology stack detection (CMS / framework / library probing)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from models import (
    Confidence,
    Finding,
    FindingCategory,
    ScanDepth,
    Severity,
    combine_confidence,
)
from modules.base import BaseModule
from modules.http_client import HttpRequestException

_H = Confidence.HIGH
_M = Confidence.MEDIUM
_L = Confidence.LOW

# Signatures: (pattern_in_body, tech_name, optional CPE, base confidence).
# Confidence reflects how specific the marker is: a unique path like
# ``/wp-content/`` is strong evidence; a bare word like ``react`` is weak. When
# several signals agree on the same tech, confidence is promoted (see
# ``models.combine_confidence``).
_BODY_SIGNATURES: list[tuple[str, str, str, Confidence]] = [
    (r"/wp-content/", "WordPress", "cpe:2.3:a:wordpress:wordpress", _H),
    (r"/wp-includes/", "WordPress", "cpe:2.3:a:wordpress:wordpress", _H),
    (r"Joomla!", "Joomla", "cpe:2.3:a:joomla:joomla", _H),
    (r"/media/jui/", "Joomla", "cpe:2.3:a:joomla:joomla", _H),
    (r"/sites/default/files/", "Drupal", "cpe:2.3:a:drupal:drupal", _H),
    (r"Drupal", "Drupal", "cpe:2.3:a:drupal:drupal", _M),
    (r"cdn\.shopify\.com", "Shopify", "", _H),
    (r"shopify\.com", "Shopify", "", _M),
    (r"/_next/", "Next.js", "", _H),
    (r"__next", "Next.js", "", _M),
    (r"__nuxt", "Nuxt.js", "", _H),
    (r"react", "React", "", _L),
    (r"vue\.js|vuejs|v-bind|v-on", "Vue.js", "", _M),
    (r"angular|ng-version", "Angular", "", _M),
    (r"laravel", "Laravel", "cpe:2.3:a:laravel:laravel", _M),
    (r"django", "Django", "cpe:2.3:a:djangoproject:django", _M),
    (r"rails|ruby on rails", "Ruby on Rails", "", _M),
    (r"express", "Express.js", "", _L),
    (r"phpmyadmin", "phpMyAdmin", "cpe:2.3:a:phpmyadmin:phpmyadmin", _M),
]

# (header_name, pattern, tech_name, CPE, base confidence). Server-emitted
# headers are authoritative, so most are HIGH.
_HEADER_SIGNATURES: list[tuple[str, str, str, str, Confidence]] = [
    ("X-Powered-By", r"PHP/([\d.]+)", "PHP", "cpe:2.3:a:php:php", _H),
    ("X-Powered-By", r"ASP\.NET", "ASP.NET", "cpe:2.3:a:microsoft:asp.net", _H),
    ("X-Powered-By", r"Express", "Express.js", "", _M),
    ("Server", r"nginx/([\d.]+)", "nginx", "cpe:2.3:a:f5:nginx", _H),
    ("Server", r"Apache/([\d.]+)", "Apache HTTP Server", "cpe:2.3:a:apache:http_server", _H),
    ("Server", r"Microsoft-IIS/([\d.]+)", "Microsoft IIS", "cpe:2.3:a:microsoft:iis", _H),
    ("Server", r"LiteSpeed", "LiteSpeed", "", _H),
    ("Server", r"cloudflare", "Cloudflare", "", _H),
    ("X-Drupal-Cache", r".", "Drupal", "cpe:2.3:a:drupal:drupal", _H),
    ("X-Generator", r"Drupal", "Drupal", "cpe:2.3:a:drupal:drupal", _H),
    ("X-Generator", r"WordPress", "WordPress", "cpe:2.3:a:wordpress:wordpress", _H),
]

# Well-known paths to probe for CMS / framework detection
_PROBE_PATHS: list[tuple[str, str, str]] = [
    ("/robots.txt", "", ""),
    ("/wp-login.php", "WordPress", "cpe:2.3:a:wordpress:wordpress"),
    ("/wp-json/", "WordPress REST API", "cpe:2.3:a:wordpress:wordpress"),
    ("/administrator/", "Joomla Admin", "cpe:2.3:a:joomla:joomla"),
    ("/user/login", "Drupal", "cpe:2.3:a:drupal:drupal"),
    ("/phpmyadmin/", "phpMyAdmin", "cpe:2.3:a:phpmyadmin:phpmyadmin"),
    ("/.env", "Environment file exposure", ""),
    ("/.git/HEAD", "Git repository exposure", ""),
    ("/server-status", "Apache mod_status", ""),
    ("/server-info", "Apache mod_info", ""),
]

_MAX_DISCOVERED_TECH_URLS = 30


@dataclass
class _Signal:
    confidence: Confidence
    evidence: str


class _TechAccumulator:
    """Collects signature signals per technology so corroborating hits combine.

    Multiple weak signals that agree on the same tech raise overall confidence;
    a lone weak hint stays weak. One ``Detected: <tech>`` finding is emitted per
    technology rather than one per matched pattern.
    """

    def __init__(self) -> None:
        self._signals: dict[str, list[_Signal]] = {}
        self._cpe: dict[str, str] = {}
        self._version: dict[str, str] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def add(
        self,
        tech: str,
        confidence: Confidence,
        evidence: str,
        *,
        cpe: str = "",
        version: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._signals.setdefault(tech, []).append(_Signal(confidence, evidence))
        if cpe and tech not in self._cpe:
            self._cpe[tech] = cpe
        if version and tech not in self._version:
            self._version[tech] = version
        if metadata and tech not in self._metadata:
            self._metadata[tech] = metadata

    def __contains__(self, tech: str) -> bool:
        return tech in self._signals

    def emit(self) -> list[Finding]:
        findings: list[Finding] = []
        for tech, signals in self._signals.items():
            confidence = combine_confidence([s.confidence for s in signals])
            # Signatures are heuristics; reserve CONFIRMED for deterministic facts.
            if confidence == Confidence.CONFIRMED:
                confidence = Confidence.HIGH
            version = self._version.get(tech, "")
            cpe = self._cpe.get(tech, "")
            if cpe and version:
                cpe = f"{cpe}:{version.replace(':', '_')}:*:*:*:*:*:*:*"
            evidences: list[str] = []
            for sig in signals:
                if sig.evidence not in evidences:
                    evidences.append(sig.evidence)
            findings.append(Finding(
                title=f"Detected: {tech}" + (f" {version}" if version else ""),
                category=FindingCategory.TECH_STACK,
                severity=Severity.INFO,
                evidence="; ".join(evidences),
                confidence=confidence,
                cpe=cpe,
                metadata=self._metadata.get(tech, {}),
            ))
        return findings


class TechStackModule(BaseModule):
    name = "tech_stack"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target
        acc = _TechAccumulator()
        detected: set[str] = set()  # techs/paths already reported (path-probe dedup)

        if self.config.dry_run:
            findings.append(Finding(
                title="Technology stack detection (dry-run)",
                category=FindingCategory.TECH_STACK,
                severity=Severity.INFO,
                evidence=f"Would probe {target} for CMS/framework/library signatures",
            ))
            return findings

        # --- Fetch main page ---
        body = ""
        headers: dict[str, str] = {}
        base_url = ""
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/"
            self._rate_limit()
            try:
                resp = self.http.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=True,
                    verify=False,
                    use_cache=True,
                )
                body = resp.text[:100_000]  # cap body size
                headers = dict(resp.headers)
                base_url = f"{scheme}://{target}"
                break
            except HttpRequestException:
                continue

        # --- Signature matching (body + headers) ---
        self._scan_body(body, "page body", acc, detected)
        self._scan_headers(headers, "", acc, detected)

        # --- Path probing (standard/deep) ---
        if base_url and self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            self._probe_paths(base_url, findings, detected)
            self._check_discovered_urls(acc, detected, findings)

        # --- Emit one finding per corroborated technology ---
        findings.extend(acc.emit())

        if not findings:
            findings.append(Finding(
                title="No technology stack signatures detected",
                category=FindingCategory.TECH_STACK,
                severity=Severity.INFO,
                evidence="No matching patterns found in body, headers, or probed paths",
            ))

        return findings

    # -----------------------------------------------------------------------

    def _scan_body(
        self,
        body: str,
        source: str,
        acc: _TechAccumulator,
        detected: set[str],
        *,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not body:
            return
        for pattern, tech, cpe, confidence in _BODY_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE):
                acc.add(
                    tech,
                    confidence,
                    f"Pattern '{pattern}' matched in {source}",
                    cpe=cpe,
                    metadata=metadata,
                )
                detected.add(tech)

    def _scan_headers(
        self,
        headers: dict[str, str],
        source_suffix: str,
        acc: _TechAccumulator,
        detected: set[str],
        *,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        for header_name, pattern, tech, cpe, confidence in _HEADER_SIGNATURES:
            value = headers.get(header_name, "")
            match = re.search(pattern, value, re.IGNORECASE)
            if not match:
                continue
            version_str = match.group(1) if match.lastindex else ""
            evidence = f"{header_name}: {value}" + (f" on {source_suffix}" if source_suffix else "")
            acc.add(
                tech,
                confidence,
                evidence,
                cpe=cpe,
                version=version_str,
                metadata=metadata,
            )
            detected.add(tech)

    def _probe_paths(self, base_url: str, findings: list[Finding], detected: set[str]) -> None:
        for path, tech, cpe in _PROBE_PATHS:
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

            sev, impact, remediation = self._path_risk(path)
            label = tech if tech else path
            if label in detected:
                continue
            detected.add(label)
            findings.append(Finding(
                title=f"Accessible path: {path}" if not tech else f"Detected: {tech} ({path})",
                category=FindingCategory.TECH_STACK,
                severity=sev,
                evidence=f"HTTP 200 at {url}",
                impact=impact,
                remediation=remediation,
                cpe=cpe,
                metadata={"scheme": base_url.split(":", 1)[0], "url": url},
            ))

    @staticmethod
    def _path_risk(path: str) -> tuple[Severity, str, str]:
        if path == "/.env":
            return (
                Severity.CRITICAL,
                "Environment file may contain credentials and secrets",
                "Block public access to .env files via web server config",
            )
        if path == "/.git/HEAD":
            return (
                Severity.HIGH,
                "Source code repository exposed — may leak secrets",
                "Block public access to .git/ directory",
            )
        if path in ("/server-status", "/server-info"):
            return (
                Severity.MEDIUM,
                "Server internals exposed to the public",
                "Restrict access to server status endpoints",
            )
        if path == "/phpmyadmin/":
            return (
                Severity.HIGH,
                "Database administration interface exposed",
                "Restrict phpMyAdmin access to trusted IPs",
            )
        return Severity.INFO, "", ""

    def _check_discovered_urls(
        self, acc: _TechAccumulator, detected: set[str], findings: list[Finding]
    ) -> None:
        checked = 0
        for url in self.config.discovered_urls:
            if checked >= _MAX_DISCOVERED_TECH_URLS:
                break
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                continue
            self._rate_limit()
            try:
                resp = self.http.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=False,
                    verify=False,
                    use_cache=True,
                )
            except HttpRequestException:
                continue
            if resp.status_code != 200:
                continue
            checked += 1

            page_meta = {"scheme": parsed.scheme, "url": url}
            self._scan_body(resp.text[:100_000], f"discovered page {url}", acc, detected, metadata=page_meta)
            self._scan_headers(dict(resp.headers), f"discovered page {url}", acc, detected, metadata=page_meta)

            probe_match = self._probe_path_match(parsed.path)
            if probe_match is None:
                continue
            path, tech, cpe = probe_match
            label = tech if tech else path
            if label in detected:
                continue
            detected.add(label)
            # Use the same risk table as the root probe so a discovered sensitive
            # path (e.g. /.env) is reported at its true severity, not flat INFO.
            sev, impact, remediation = self._path_risk(path)
            findings.append(Finding(
                title=f"Accessible discovered path: {parsed.path}" if not tech else f"Detected: {tech} ({parsed.path})",
                category=FindingCategory.TECH_STACK,
                severity=sev,
                evidence=f"HTTP 200 at discovered URL {url}",
                impact=impact,
                remediation=remediation,
                cpe=cpe,
                metadata=page_meta,
            ))

    @staticmethod
    def _probe_path_match(path: str) -> tuple[str, str, str] | None:
        normalized = path.rstrip("/") or "/"
        for probe_path, tech, cpe in _PROBE_PATHS:
            probe_normalized = probe_path.rstrip("/") or "/"
            if normalized == probe_normalized:
                return probe_path, tech, cpe
        return None
