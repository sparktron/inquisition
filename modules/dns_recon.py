"""Module 1 — DNS reconnaissance."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import dns.exception  # type: ignore[import-untyped]
import dns.query  # type: ignore[import-untyped]
import dns.resolver  # type: ignore[import-untyped]
import dns.reversename  # type: ignore[import-untyped]
import dns.zone  # type: ignore[import-untyped]

from models import Finding, FindingCategory, Severity
from modules.base import BaseModule
from modules.security_grading import Issue, grade_dmarc, grade_spf

# Common subdomains to probe in deeper scans
_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "blog", "dev", "staging", "api", "admin", "vpn", "cdn", "app",
    "test", "old", "beta", "secure", "portal", "dashboard", "m",
    "shop", "store", "support", "help", "status", "monitoring",
]

# Common DKIM selectors used by major mail providers. DKIM selectors are
# arbitrary per-domain, so this list only enables a best-effort positive probe.
_COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2",
    "k1", "k2", "mail", "dkim", "mandrill", "mailjet", "smtp", "zoho",
]

# Third-party services that indicate potential subdomain takeover if CNAME points there
# Maps CNAME suffix -> (service_name, how_to_verify)
_TAKEOVER_CANDIDATES: dict[str, tuple[str, str]] = {
    "github.io":               ("GitHub Pages", "If 404 with GitHub branding, page is unclaimed"),
    "herokuapp.com":           ("Heroku",        "If 'No such app' error, the app is unclaimed"),
    "s3.amazonaws.com":        ("AWS S3",        "If NoSuchBucket or 403, bucket may be claimable"),
    "s3-website":              ("AWS S3 Website","If 'NoSuchBucket', bucket is unclaimed"),
    "cloudfront.net":          ("AWS CloudFront","Distribution may be orphaned"),
    "azurewebsites.net":       ("Azure App Service","If 404 from Azure, the app is unclaimed"),
    "azurefd.net":             ("Azure Front Door","Distribution may be orphaned"),
    "trafficmanager.net":      ("Azure Traffic Manager","Endpoint may be deleteable and claimable"),
    "wordpress.com":           ("WordPress.com","Blog may be unclaimed"),
    "ghost.io":                ("Ghost",         "If 'Domain not found', site is unclaimed"),
    "netlify.app":             ("Netlify",       "If 404 with Netlify branding, site is unclaimed"),
    "vercel.app":              ("Vercel",        "If 404 with Vercel branding, deployment is unclaimed"),
    "readthedocs.io":          ("ReadTheDocs",   "If 404 from RTD, project is unclaimed"),
    "surge.sh":                ("Surge.sh",      "If 404 from Surge, deployment is unclaimed"),
    "fastly.net":              ("Fastly",        "If 'Fastly error', service is unclaimed"),
    "myshopify.com":           ("Shopify",       "If 'Sorry, this shop is currently unavailable', shop is deleted"),
    "zendesk.com":             ("Zendesk",       "If Zendesk 404, subdomain is unclaimed"),
    "helpjuice.com":           ("HelpJuice",     "Knowledge base may be unclaimed"),
    "helpscoutdocs.com":       ("HelpScout Docs","Docs site may be unclaimed"),
    "bitbucket.io":            ("Bitbucket Pages","Page may be unclaimed"),
    "desk.com":                ("Desk.com",      "Support portal may be unclaimed"),
    "cargocollective.com":     ("Cargo Collective","Portfolio may be unclaimed"),
    "tumblr.com":              ("Tumblr",        "Blog may be unclaimed"),
}


@dataclass(frozen=True)
class _DnsResolution:
    addresses: tuple[str, ...]
    transient_errors: tuple[str, ...] = ()


def _resolve_dns(hostname: str, timeout: float) -> _DnsResolution:
    """Resolve bounded A/AAAA queries and retain transient-failure context."""
    try:
        return _DnsResolution((str(ipaddress.ip_address(hostname)),))
    except ValueError:
        pass

    addresses: set[str] = set()
    transient_errors: set[str] = set()
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(hostname, record_type, lifetime=timeout)
            addresses.update(str(answer).strip() for answer in answers)
        except dns.resolver.NXDOMAIN:
            break
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException) as exc:
            transient_errors.add(type(exc).__name__)
    return _DnsResolution(
        addresses=tuple(sorted(addresses)),
        transient_errors=tuple(sorted(transient_errors)) if not addresses else (),
    )


def _safe_dns_resolve(hostname: str, timeout: float) -> list[str]:
    """Resolve bounded A/AAAA queries without leaving background worker threads."""
    return list(_resolve_dns(hostname, timeout).addresses)


class DnsReconModule(BaseModule):
    name = "dns_recon"

    def run(self) -> list[Finding]:
        from models import ScanDepth

        findings: list[Finding] = []
        target = self.config.target

        if self.config.dry_run:
            findings.append(Finding(
                title="DNS resolution (dry-run)",
                category=FindingCategory.DNS,
                severity=Severity.INFO,
                evidence=f"Would resolve {target} and check common subdomains",
            ))
            return findings

        # --- A / AAAA resolution ---
        self._rate_limit()
        resolution = _resolve_dns(target, self.config.timeout)
        ips = list(resolution.addresses)
        if ips:
            findings.append(Finding(
                title="DNS A/AAAA records",
                category=FindingCategory.DNS,
                severity=Severity.INFO,
                evidence=f"{target} resolves to: {', '.join(sorted(ips))}",
                # Structured copy so consumers (e.g. fleet_correlation) read a
                # stable field instead of regex-parsing the evidence prose.
                metadata={"resolved_ips": sorted(ips)},
            ))
        elif resolution.transient_errors:
            findings.append(Finding(
                title="DNS resolution inconclusive",
                category=FindingCategory.DNS,
                severity=Severity.INFO,
                evidence=(
                    f"Could not determine A/AAAA records for {target}: "
                    f"{', '.join(resolution.transient_errors)}"
                ),
                impact="No invalid-hostname assertion was made because the DNS lookup failed",
                remediation="Retry after confirming the configured DNS resolver is reachable.",
            ))
            return findings
        else:
            findings.append(Finding(
                title="DNS resolution failed",
                category=FindingCategory.DNS,
                severity=Severity.MEDIUM,
                evidence=f"Could not resolve {target}",
                impact="Target may be unreachable or hostname is invalid",
            ))
            return findings

        # --- Reverse DNS ---
        for ip in ips:
            self._rate_limit()
            try:
                reverse_name = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(reverse_name, "PTR", lifetime=self.config.timeout)
                hostname_rev = str(next(iter(answers))).rstrip(".")
                findings.append(Finding(
                    title="Reverse DNS",
                    category=FindingCategory.DNS,
                    severity=Severity.INFO,
                    evidence=f"{ip} -> {hostname_rev}",
                ))
            except (ValueError, StopIteration, dns.exception.DNSException):
                pass

        # --- Subdomain enumeration (standard + deep) ---
        if self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            for sub in _COMMON_SUBDOMAINS:
                fqdn = f"{sub}.{target}"
                self._rate_limit()
                sub_ips = _safe_dns_resolve(fqdn, self.config.timeout)
                if sub_ips:
                    findings.append(Finding(
                        title=f"Subdomain found: {fqdn}",
                        category=FindingCategory.DNS,
                        severity=Severity.INFO,
                        evidence=f"{fqdn} -> {', '.join(sorted(sub_ips))}",
                    ))

        # --- MX / NS via dnspython (optional) ---
        try:
            for qtype in ("MX", "NS", "TXT"):
                self._rate_limit()
                try:
                    answers = dns.resolver.resolve(target, qtype, lifetime=self.config.timeout)
                    records = [str(r) for r in answers]
                    findings.append(Finding(
                        title=f"DNS {qtype} records",
                        category=FindingCategory.DNS,
                        severity=Severity.INFO,
                        evidence=f"{qtype}: {', '.join(records)}",
                    ))
                    # Check for SPF in TXT — flag if missing, grade strength if present.
                    if qtype == "TXT":
                        spf_record = next(
                            (
                                r.replace('"', "").strip()
                                for r in records
                                if "v=spf1" in r.lower()
                            ),
                            None,
                        )
                        if spf_record is None:
                            findings.append(Finding(
                                title="Missing SPF record",
                                category=FindingCategory.MISCONFIGURATION,
                                severity=Severity.MEDIUM,
                                evidence=f"No SPF TXT record found for {target}",
                                impact="Email spoofing may be possible",
                                remediation="Add an SPF TXT record to the domain",
                            ))
                        else:
                            self._append_email_auth_findings(
                                "SPF",
                                target,
                                spf_record,
                                grade_spf(spf_record),
                                findings,
                            )
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass

            # DMARC applies to email domains, not literal IP scan targets.
            try:
                ipaddress.ip_address(target)
                is_literal_ip = True
            except ValueError:
                is_literal_ip = False
            if not is_literal_ip:
                # DMARC check — flag if missing, grade policy strength if present.
                self._rate_limit()
                try:
                    dmarc = dns.resolver.resolve(f"_dmarc.{target}", "TXT", lifetime=self.config.timeout)
                    dmarc_records = [str(r).replace('"', "").strip() for r in dmarc]
                    dmarc_record = next(
                        (r for r in dmarc_records if "v=dmarc1" in r.lower()),
                        dmarc_records[0] if dmarc_records else "",
                    )
                    findings.append(Finding(
                        title="DMARC record found",
                        category=FindingCategory.DNS,
                        severity=Severity.INFO,
                        evidence=f"DMARC: {', '.join(dmarc_records)}",
                    ))
                    self._append_email_auth_findings(
                        "DMARC", target, dmarc_record, grade_dmarc(dmarc_record), findings,
                    )
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    findings.append(Finding(
                        title="Missing DMARC record",
                        category=FindingCategory.MISCONFIGURATION,
                        severity=Severity.MEDIUM,
                        evidence=f"No DMARC record at _dmarc.{target}",
                        impact="Email spoofing / phishing risk",
                        remediation="Add a DMARC TXT record at _dmarc.<domain>",
                    ))
                except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                    findings.append(Finding(
                        title="DMARC lookup inconclusive",
                        category=FindingCategory.DNS,
                        severity=Severity.INFO,
                        evidence=(
                            f"Could not determine DMARC status for _dmarc.{target}: "
                            f"{type(exc).__name__}"
                        ),
                        impact="No missing-DMARC assertion was made because the DNS lookup failed",
                        remediation="Retry after confirming the configured DNS resolver is reachable.",
                    ))
                except dns.exception.DNSException as exc:
                    findings.append(Finding(
                        title="DMARC lookup inconclusive",
                        category=FindingCategory.DNS,
                        severity=Severity.INFO,
                        evidence=(
                            f"Could not determine DMARC status for _dmarc.{target}: "
                            f"{type(exc).__name__}"
                        ),
                        impact="No missing-DMARC assertion was made because the DNS lookup failed",
                        remediation="Retry after confirming the configured DNS resolver is reachable.",
                    ))

            # --- DKIM probe (common selectors) ---
            # DKIM selectors are arbitrary, so absence via common selectors is
            # not conclusive — only report when a record is actually found.
            found_selectors: list[str] = []
            for selector in _COMMON_DKIM_SELECTORS:
                self._rate_limit()
                try:
                    dkim = dns.resolver.resolve(
                        f"{selector}._domainkey.{target}", "TXT", lifetime=self.config.timeout
                    )
                    if any("v=dkim1" in str(r).lower() or "p=" in str(r).lower() for r in dkim):
                        found_selectors.append(selector)
                except Exception:
                    pass
            if found_selectors:
                findings.append(Finding(
                    title="DKIM record found",
                    category=FindingCategory.DNS,
                    severity=Severity.INFO,
                    evidence=f"DKIM selector(s) present for {target}: {', '.join(found_selectors)}",
                ))

            # --- DNS zone transfer (AXFR) attempt ---
            # Attempt against each authoritative NS.  A successful transfer
            # reveals the entire zone — all hostnames and IPs.
            try:
                ns_answers = dns.resolver.resolve(target, "NS", lifetime=self.config.timeout)
                ns_names = [str(r).rstrip(".") for r in ns_answers]
            except Exception:
                ns_names = []

            for ns in ns_names:
                self._rate_limit()
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=self.config.timeout))
                    record_names = [str(n) for n in zone.nodes.keys()]
                    findings.append(Finding(
                        title="DNS zone transfer succeeded (AXFR)",
                        category=FindingCategory.DNS,
                        severity=Severity.CRITICAL,
                        evidence=(
                            f"NS {ns} allowed AXFR for {target}. "
                            f"{len(record_names)} zone record(s) retrieved: "
                            f"{', '.join(record_names[:20])}"
                            + (" …" if len(record_names) > 20 else "")
                        ),
                        impact=(
                            "Full zone contents exposed — attacker can enumerate every hostname, "
                            "IP, mail server, and internal subdomain without further probing"
                        ),
                        remediation=(
                            "Restrict AXFR to authorised secondary NS IPs only. "
                            "On BIND: allow-transfer { <secondary-ip>; }; "
                            "On Route53/Cloud DNS: zone transfers are disabled by default."
                        ),
                    ))
                except Exception:
                    pass  # AXFR refused or failed — expected on hardened servers

            # --- Subdomain takeover detection ---
            # Check all discovered subdomains for dangling CNAME records pointing
            # to third-party services where the resource has been deleted.
            if self.config.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
                subdomain_findings = [
                    f for f in findings
                    if f.title.startswith("Subdomain found:")
                ]
                for sf in subdomain_findings:
                    fqdn = sf.title.replace("Subdomain found: ", "").strip()
                    self._rate_limit()
                    try:
                        cname_ans = dns.resolver.resolve(fqdn, "CNAME", lifetime=self.config.timeout)
                        for rdata in cname_ans:
                            cname_target = str(rdata.target).rstrip(".").lower()
                            for suffix, (service, how_to_verify) in _TAKEOVER_CANDIDATES.items():
                                if cname_target.endswith(suffix):
                                    findings.append(Finding(
                                        title=f"Potential subdomain takeover: {fqdn}",
                                        category=FindingCategory.DNS,
                                        severity=Severity.HIGH,
                                        evidence=(
                                            f"{fqdn} CNAME → {cname_target} ({service}). "
                                            f"Verification: {how_to_verify}"
                                        ),
                                        impact=(
                                            f"An attacker may be able to register the {service} "
                                            f"resource at {cname_target} and serve malicious content "
                                            "under your domain, bypassing cookie/CORS restrictions"
                                        ),
                                        remediation=(
                                            f"Remove the CNAME record for {fqdn} if the {service} "
                                            "resource no longer exists, or re-create the resource "
                                            "to prevent an attacker from claiming it"
                                        ),
                                    ))
                    except Exception:
                        pass  # Not a CNAME or resolution failed

        except ImportError:
            pass  # dnspython not installed — skip advanced DNS

        return findings

    @staticmethod
    def _append_email_auth_findings(
        record_type: str,
        target: str,
        record: str,
        issues: list[Issue],
        findings: list[Finding],
    ) -> None:
        for issue in issues:
            findings.append(Finding(
                title=f"Weak {record_type} policy: {issue.summary}",
                category=FindingCategory.MISCONFIGURATION,
                severity=issue.severity,
                evidence=f"{record_type} record for {target}: {record}",
                impact=issue.impact,
                remediation=issue.remediation,
            ))
