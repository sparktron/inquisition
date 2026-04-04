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
from ui import (
    console,
    make_progress,
    print_cve_error,
    print_cve_match,
    print_cve_phase,
    print_error,
    print_header,
    print_info,
    print_module_result,
    print_summary,
    print_warning,
)
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
            print_warning(w)
        abort("Invalid configuration — cannot proceed.")

    # --- Authorization ---
    if not skip_auth:
        if not prompt_authorization(config):
            abort("Authorization denied — aborting scan.")

    # --- Header ---
    print_header(
        target=config.target,
        depth=config.depth.value,
        fmt=config.report_format.value,
        dry_run=config.dry_run,
    )

    # --- Initialize report ---
    report = ScanReport(
        target=config.target,
        started_at=datetime.now(timezone.utc),
        config=config,
    )

    # --- Run fingerprinting modules ---
    modules = [cls(config) for cls in ALL_MODULES]

    progress = make_progress()
    with progress:
        task = progress.add_task("scanning", total=len(modules))
        with ThreadPoolExecutor(max_workers=min(config.max_threads, len(modules))) as pool:
            futures = {pool.submit(_run_module, m): m.name for m in modules}
            for future in as_completed(futures):
                mod_name, findings, errors = future.result()
                print_module_result(mod_name, len(findings), len(errors))
                progress.advance(task)
                report.findings.extend(findings)
                report.errors.extend(errors)

    # --- Vulnerability correlation (CPE -> CVE) ---
    cpe_values = {f.cpe for f in report.findings if f.cpe}
    if cpe_values and not config.dry_run:
        print_cve_phase(len(cpe_values))
        for cpe in cpe_values:
            try:
                cves = lookup_cves_for_cpe(cpe, timeout=config.timeout)
                report.cve_records.extend(cves)
                if cves:
                    print_cve_match(cpe, len(cves))
            except Exception as exc:
                report.errors.append(f"CVE lookup for {cpe}: {exc}")
                print_cve_error(cpe)

    # --- Deduplicate findings ---
    before = len(report.findings)
    report.findings = _deduplicate(report.findings)
    dupes = before - len(report.findings)
    if dupes:
        print_info(f"removed {dupes} duplicate finding" + ("s" if dupes != 1 else ""))

    # --- Misconfiguration checks ---
    report.misconfigurations = derive_misconfigurations(report.findings)
    if report.misconfigurations:
        n = len(report.misconfigurations)
        print_info(f"{n} misconfiguration" + ("s" if n != 1 else "") + " detected")

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

    report_saved = False
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(output)
        report_saved = True
    except OSError as exc:
        err_msg = str(exc)
        if "Permission denied" in err_msg:
            hint = "check write permissions on the target directory"
        elif "No such file" in err_msg:
            hint = "parent directory does not exist"
        else:
            hint = err_msg
        print_error(f"could not write report to {output_path}", hint)
        console.print(output)

    # --- Summary ---
    counts = report.summary_counts()
    print_summary(
        target=config.target,
        total=sum(counts.values()),
        counts=counts,
        cve_count=len(report.cve_records),
        misconfig_count=len(report.misconfigurations),
        output_path=output_path if report_saved else "(not saved)",
    )
