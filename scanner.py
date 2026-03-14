"""Main scanner orchestrator — ties modules, correlation, and reporting together."""

from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from models import ReportFormat, ScanReport, Severity
from modules import ALL_MODULES
from modules.base import BaseModule
from report import render
from safety import abort, enforce_dry_run, prompt_authorization, validate_config
from vuln_correlation import derive_misconfigurations, lookup_cves_for_cpe

if TYPE_CHECKING:
    from models import Finding, ScanConfig

logger = logging.getLogger(__name__)


def _run_module(module: BaseModule) -> tuple[str, list[Finding], list[str]]:
    """Run a single module and return (module_name, findings, errors)."""
    errors: list[str] = []
    try:
        findings = module.run()
    except Exception as exc:
        logger.exception("Module %s failed", module.name)
        findings = []
        errors.append(f"Module {module.name}: {exc}")
    return module.name, findings, errors


def run_scan(config: ScanConfig, *, skip_auth: bool = False) -> None:
    """Execute a full scan with the given configuration."""

    # --- Validation ---
    warnings = validate_config(config)
    if warnings:
        for w in warnings:
            print(f"[!] {w}", file=sys.stderr)
        abort("Invalid configuration — cannot proceed.")

    # --- Authorization ---
    if not skip_auth:
        if not prompt_authorization(config):
            abort("Authorization denied — aborting scan.")

    # --- Dry-run banner ---
    if enforce_dry_run(config):
        print("\n[*] DRY-RUN mode — no network traffic will be generated.\n")

    # --- Initialize report ---
    report = ScanReport(
        target=config.target,
        started_at=datetime.now(timezone.utc),
        config=config,
    )

    # --- Run fingerprinting modules ---
    print(f"[*] Starting scan of {config.target} (depth={config.depth.value})\n")

    modules = [cls(config) for cls in ALL_MODULES]

    # Run modules concurrently (each module handles its own internal rate-limiting)
    with ThreadPoolExecutor(max_workers=min(config.max_threads, len(modules))) as pool:
        futures = {pool.submit(_run_module, m): m.name for m in modules}
        for future in as_completed(futures):
            mod_name, findings, errors = future.result()
            status = f"{len(findings)} finding(s)"
            if errors:
                status += f", {len(errors)} error(s)"
            print(f"  [+] {mod_name}: {status}")
            report.findings.extend(findings)
            report.errors.extend(errors)

    # --- Vulnerability correlation (CPE -> CVE) ---
    cpe_values = {f.cpe for f in report.findings if f.cpe}
    if cpe_values and not config.dry_run:
        print(f"\n[*] Correlating {len(cpe_values)} CPE(s) with NVD...")
        for cpe in cpe_values:
            try:
                cves = lookup_cves_for_cpe(cpe, timeout=config.timeout)
                report.cve_records.extend(cves)
                if cves:
                    print(f"  [+] {cpe}: {len(cves)} CVE(s)")
            except Exception as exc:
                report.errors.append(f"CVE lookup for {cpe}: {exc}")

    # --- Misconfiguration checks ---
    report.misconfigurations = derive_misconfigurations(report.findings)
    if report.misconfigurations:
        print(f"\n[*] {len(report.misconfigurations)} misconfiguration(s) detected")

    # --- Finalize ---
    report.finished_at = datetime.now(timezone.utc)

    # --- Render report ---
    output = render(report, config.report_format)
    print(f"\n{'=' * 72}")
    print(output)

    # Summary line
    counts = report.summary_counts()
    crit_high = counts.get("critical", 0) + counts.get("high", 0)
    print(f"\n[*] Scan complete. {sum(counts.values())} findings, "
          f"{crit_high} critical/high, "
          f"{len(report.cve_records)} CVEs correlated.")
