"""Module 5 — Technology stack detection (CMS / framework / library probing)."""

from __future__ import annotations

import re

import requests

from models import Finding, FindingCategory, ScanDepth, Severity
from modules.base import BaseModule

# Signatures: (pattern_in_body_or_header, tech_name, optional CPE)
_BODY_SIGNATURES: list[tuple[str, str, str]] = [
    (r"/wp-content/", "WordPress", "cpe:2.3:a:wordpress:wordpress"),
    (r"/wp-includes/", "WordPress", "cpe:2.3:a:wordpress:wordpress"),
    (r"Joomla!", "Joomla", "cpe:2.3:a:joomla:joomla"),
    (r"/media/jui/", "Joomla", "cpe:2.3:a:joomla:joomla"),
    (r"Drupal", "Drupal", "cpe:2.3:a:drupal:drupal"),
    (r"/sites/default/files/", "Drupal", "cpe:2.3:a:drupal:drupal"),
    (r"shopify\.com", "Shopify", ""),
    (r"cdn\.shopify\.com", "Shopify", ""),
    (r"__next", "Next.js", ""),
    (r"/_next/", "Next.js", ""),
    (r"__nuxt", "Nuxt.js", ""),
    (r"react", "React (likely)", ""),
    (r"vue\.js|vuejs|v-bind|v-on", "Vue.js", ""),
    (r"angular|ng-version", "Angular", ""),
    (r"laravel", "Laravel", "cpe:2.3:a:laravel:laravel"),
    (r"django", "Django", "cpe:2.3:a:djangoproject:django"),
    (r"rails|ruby on rails", "Ruby on Rails", ""),
    (r"express", "Express.js (possible)", ""),
    (r"phpmyadmin", "phpMyAdmin", "cpe:2.3:a:phpmyadmin:phpmyadmin"),
]

_HEADER_SIGNATURES: list[tuple[str, str, str, str]] = [
    # (header_name, pattern, tech_name, CPE)
    ("X-Powered-By", r"PHP/([\d.]+)", "PHP", "cpe:2.3:a:php:php"),
    ("X-Powered-By", r"ASP\.NET", "ASP.NET", "cpe:2.3:a:microsoft:asp.net"),
    ("X-Powered-By", r"Express", "Express.js", ""),
    ("Server", r"nginx/([\d.]+)", "nginx", "cpe:2.3:a:f5:nginx"),
    ("Server", r"Apache/([\d.]+)", "Apache HTTP Server", "cpe:2.3:a:apache:http_server"),
    ("Server", r"Microsoft-IIS/([\d.]+)", "Microsoft IIS", "cpe:2.3:a:microsoft:iis"),
    ("Server", r"LiteSpeed", "LiteSpeed", ""),
    ("Server", r"cloudflare", "Cloudflare", ""),
    ("X-Drupal-Cache", r".", "Drupal", "cpe:2.3:a:drupal:drupal"),
    ("X-Generator", r"Drupal", "Drupal", "cpe:2.3:a:drupal:drupal"),
    ("X-Generator", r"WordPress", "WordPress", "cpe:2.3:a:wordpress:wordpress"),
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


class TechStackModule(BaseModule):
    name = "tech_stack"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target
        detected: set[str] = set()

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
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/"
            self._rate_limit()
            try:
                resp = requests.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
                )
                body = resp.text[:100_000]  # cap body size
                headers = dict(resp.headers)
                break
            except requests.RequestException:
                continue

        # --- Body-based signatures ---
        for pattern, tech, cpe in _BODY_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE) and tech not in detected:
                detected.add(tech)
                findings.append(Finding(
                    title=f"Detected: {tech}",
                    category=FindingCategory.TECH_STACK,
                    severity=Severity.INFO,
                    evidence=f"Pattern '{pattern}' matched in page body",
                    cpe=cpe,
                ))

        # --- Header-based signatures ---
        for header_name, pattern, tech, cpe in _HEADER_SIGNATURES:
            value = headers.get(header_name, "")
            match = re.search(pattern, value, re.IGNORECASE)
            if match and tech not in detected:
                detected.add(tech)
                version_str = match.group(1) if match.lastindex else ""
                evidence = f"{header_name}: {value}"
                findings.append(Finding(
                    title=f"Detected: {tech}" + (f" {version_str}" if version_str else ""),
                    category=FindingCategory.TECH_STACK,
                    severity=Severity.INFO,
                    evidence=evidence,
                    cpe=f"{cpe}:{version_str.replace(':', '_')}:*:*:*:*:*:*:*" if cpe and version_str else cpe,
                ))

        # --- Path probing (standard/deep) ---
        if self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            for path, tech, cpe in _PROBE_PATHS:
                url = f"https://{target}{path}"
                self._rate_limit()
                try:
                    resp = requests.get(
                        url,
                        timeout=self.config.timeout,
                        allow_redirects=False,
                        verify=False,
                        headers={"User-Agent": "Inquisition/0.1 SecurityScanner"},
                    )
                except requests.RequestException:
                    continue

                if resp.status_code == 200:
                    sev = Severity.INFO
                    impact = ""
                    remediation = ""

                    if path == "/.env":
                        sev = Severity.CRITICAL
                        impact = "Environment file may contain credentials and secrets"
                        remediation = "Block public access to .env files via web server config"
                    elif path == "/.git/HEAD":
                        sev = Severity.HIGH
                        impact = "Source code repository exposed — may leak secrets"
                        remediation = "Block public access to .git/ directory"
                    elif path in ("/server-status", "/server-info"):
                        sev = Severity.MEDIUM
                        impact = "Server internals exposed to the public"
                        remediation = "Restrict access to server status endpoints"
                    elif path == "/phpmyadmin/":
                        sev = Severity.HIGH
                        impact = "Database administration interface exposed"
                        remediation = "Restrict phpMyAdmin access to trusted IPs"

                    label = tech if tech else path
                    if label not in detected:
                        detected.add(label)
                        findings.append(Finding(
                            title=f"Accessible path: {path}" if not tech else f"Detected: {tech} ({path})",
                            category=FindingCategory.TECH_STACK,
                            severity=sev,
                            evidence=f"HTTP 200 at {url}",
                            impact=impact,
                            remediation=remediation,
                            cpe=cpe,
                        ))

        if not findings:
            findings.append(Finding(
                title="No technology stack signatures detected",
                category=FindingCategory.TECH_STACK,
                severity=Severity.INFO,
                evidence="No matching patterns found in body, headers, or probed paths",
            ))

        return findings
