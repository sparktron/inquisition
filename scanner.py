"""Main scanner orchestrator — ties modules, correlation, and reporting together."""

from __future__ import annotations

import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
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


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings that share the same title, category, and severity.

    When modules run concurrently against both HTTP and HTTPS, the same
    structural issue (e.g. 'Missing header: CSP') can surface twice.  Keep
    the first occurrence, which tends to carry the most evidence detail.
    """
    seen: set[tuple] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f.title.lower(), f.category, f.severity)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


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


def run_scan(
    config: ScanConfig,
    *,
    skip_auth: bool = False,
    brief: bool = False,
    output_path: str | None = None,
) -> None:
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
            status = f"{len(findings)} finding"
            if len(findings) != 1:
                status += "s"
            if errors:
                status += f" • {len(errors)} error"
                if len(errors) != 1:
                    status += "s"
            print(f"  [✓] {mod_name:<20} {status}")
            report.findings.extend(findings)
            report.errors.extend(errors)

    # --- Vulnerability correlation (CPE -> CVE) ---
    cpe_values = {f.cpe for f in report.findings if f.cpe}
    if cpe_values and not config.dry_run:
        print(f"\n[*] Correlating {len(cpe_values)} CPE value(s) with NVD...")
        for cpe in cpe_values:
            try:
                cves = lookup_cves_for_cpe(cpe, timeout=config.timeout)
                report.cve_records.extend(cves)
                if cves:
                    count = len(cves)
                    print(f"  [!] {cpe}: {count} CVE" + ("" if count == 1 else "s"))
            except Exception as exc:
                msg = f"CVE lookup for {cpe}: {exc}"
                report.errors.append(msg)
                print(f"  [✗] CVE lookup failed for {cpe}")

    # --- Deduplicate findings ---
    before = len(report.findings)
    report.findings = _deduplicate(report.findings)
    dupes = before - len(report.findings)
    if dupes:
        print(f"\n[*] Removed {dupes} duplicate finding(s)")

    # --- Misconfiguration checks ---
    report.misconfigurations = derive_misconfigurations(report.findings)
    if report.misconfigurations:
        print(f"\n[*] {len(report.misconfigurations)} misconfiguration(s) detected")

    # --- Finalize ---
    report.finished_at = datetime.now(timezone.utc)

    # --- Render report ---
    output = render(report, config.report_format, brief=brief)

    if not output_path:
        timestamp = report.started_at.strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^\w\-]", "_", config.target)
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        output_path = str(reports_dir / f"{timestamp}_{safe_target}.md")

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"\n[✓] Report saved to: {output_path}")
    except OSError as exc:
        err_msg = str(exc)
        if "Permission denied" in err_msg:
            hint = " — Check write permissions in the target directory"
        elif "No such file" in err_msg:
            hint = " — Parent directory does not exist, creating 'reports/' directory"
        else:
            hint = ""
        print(f"\n[✗] Could not write report to {output_path}{hint}", file=sys.stderr)
        print(f"\n{'=' * 72}")
        print(output)

    # Summary
    counts = report.summary_counts()
    crit_high = counts.get("critical", 0) + counts.get("high", 0)
    total = sum(counts.values())

    if crit_high > 0:
        severity_icon = "⚠"
        severity_msg = f"{crit_high} critical/high"
    else:
        severity_icon = "✓"
        severity_msg = "no critical/high"

    print(f"\n[{severity_icon}] Scan complete: {total} finding" + ("s" if total != 1 else ""),
          f"({severity_msg}, {len(report.cve_records)} CVE" + ("s" if len(report.cve_records) != 1 else "") + ")")
