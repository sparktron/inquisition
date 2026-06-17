"""Main scanner orchestrator — ties modules, correlation, and reporting together."""

from __future__ import annotations

import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from diffing import (
    DiffResult,
    default_state_dir,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
    snapshot_from_report,
)
from active_scan import run_active_scan
from models import ReportFormat, ScanReport, Severity
from notifications import NOTIFY_REGRESSION, notify
from modules import ALL_MODULES
from modules.base import BaseModule
from modules.crawler import CrawlerModule
from modules.http_client import HttpClient
from report import render
from safety import (
    abort,
    confirm_active_scan,
    enforce_dry_run,
    prompt_authorization,
    validate_config,
)
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
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[Finding] = []
    for f in findings:
        scheme = f.metadata.get("scheme", "")
        if not scheme:
            match = re.search(r"\bhttps?://", f.evidence)
            scheme = match.group(0).rstrip(":/") if match else ""
        key = (f.title.lower(), f.category.value, f.severity.value, scheme)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def _default_report_path(report: ScanReport, report_format: ReportFormat) -> Path:
    """Return the default report path for the selected output format."""
    extensions = {
        ReportFormat.TEXT: ".txt",
        ReportFormat.JSON: ".json",
        ReportFormat.HTML: ".html",
        ReportFormat.SARIF: ".sarif",
    }
    timestamp = report.started_at.strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^\w\-]", "_", report.target)
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    return reports_dir / f"{timestamp}_{safe_target}{extensions[report_format]}"


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


def _extract_discovered_urls(findings: list[Finding]) -> tuple[str, ...]:
    for finding in findings:
        raw_urls = finding.metadata.get("discovered_urls")
        if isinstance(raw_urls, list):
            urls = [url for url in raw_urls if isinstance(url, str)]
            return tuple(sorted(set(urls)))
    return ()


def _print_diff(diff: DiffResult) -> None:
    """Print a one-line-per-category delta vs the previous scan of this target."""
    if diff.is_baseline:
        print_info("baseline scan — no previous results to compare against")
        return
    if not diff.has_changes():
        print_info(f"no change since last scan ({diff.unchanged_count} finding(s) stable)")
        return
    parts: list[str] = []
    if diff.new:
        parts.append(f"{len(diff.new)} new")
    if diff.regressed:
        parts.append(f"{len(diff.regressed)} regressed")
    if diff.fixed:
        parts.append(f"{len(diff.fixed)} fixed")
    if diff.improved:
        parts.append(f"{len(diff.improved)} improved")
    print_info("vs previous scan: " + ", ".join(parts))
    for delta in diff.new:
        print_info(f"  + new [{delta.severity}] {delta.title}")
    for delta in diff.regressed:
        print_info(f"  ! regressed [{delta.previous_severity}→{delta.severity}] {delta.title}")
    for delta in diff.fixed:
        print_info(f"  - fixed [{delta.severity}] {delta.title}")


def run_scan(
    config: ScanConfig,
    *,
    skip_auth: bool = False,
    brief: bool = False,
    output_path: str | None = None,
    notify_url: str | None = None,
    notify_min_severity: Severity = Severity.HIGH,
    notify_on: str = NOTIFY_REGRESSION,
    write_report: bool = True,
) -> ScanReport:
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

    # --- Pre-discover URL surface, then feed it into path-aware modules ---
    http_client = HttpClient(config)
    crawler = CrawlerModule(config, http_client=http_client)
    mod_name, crawler_findings, crawler_errors = _run_module(crawler)
    print_module_result(mod_name, len(crawler_findings), len(crawler_errors))
    report.findings.extend(crawler_findings)
    report.errors.extend(crawler_errors)

    discovered_urls = _extract_discovered_urls(crawler_findings)
    if discovered_urls:
        print_info(f"feeding {len(discovered_urls)} discovered URL(s) into path-aware modules")
        config = replace(config, discovered_urls=discovered_urls)
        report.config = config

    # --- Run fingerprinting modules ---
    module_classes = [cls for cls in ALL_MODULES if cls is not CrawlerModule]
    modules = [cls(config, http_client=http_client) for cls in module_classes]

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

    # --- Active testing phase (opt-in, sends payloads) ---
    if config.active and not config.dry_run:
        if confirm_active_scan(config, assume_yes=skip_auth):
            print_info(f"running active scan ({config.active_engine}) — this sends payloads")
            active_findings, active_errors = run_active_scan(config)
            report.findings.extend(active_findings)
            report.errors.extend(active_errors)
            print_info(
                f"active scan complete: {len(active_findings)} finding(s)"
                + (f", {len(active_errors)} error(s)" if active_errors else "")
            )
        else:
            print_warning("active scan not authorized — skipping active phase")

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

    # --- Scan diffing vs the previous run for this target ---
    if not config.dry_run:
        state_dir = default_state_dir()
        previous = load_snapshot(config.target, state_dir)
        diff_result = diff_snapshots(previous, snapshot_from_report(report))
        _print_diff(diff_result)
        try:
            save_snapshot(report, state_dir)
        except OSError as exc:
            report.errors.append(f"Could not save scan snapshot: {exc}")

        # --- Scan notification ---
        if notify_url:
            try:
                if notify(
                    notify_url,
                    config.target,
                    diff_result,
                    notify_min_severity,
                    policy=notify_on,
                    report=report,
                ):
                    print_info(f"scan notification sent ({notify_on})")
            except Exception as exc:
                report.errors.append(f"Notification failed: {exc}")
                print_warning(f"scan notification failed: {exc}")

    # --- Render report ---
    report_saved = False
    summary_path = "(combined artifact)"
    if write_report:
        output = render(report, config.report_format, brief=brief)

        if not output_path:
            output_path = str(_default_report_path(report, config.report_format))

        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(output)
            report_saved = True
            report.report_path = output_path
            summary_path = output_path
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
            summary_path = "(not saved)"

    # --- Summary ---
    counts = report.summary_counts()
    print_summary(
        target=config.target,
        total=sum(counts.values()),
        counts=counts,
        cve_count=len(report.cve_records),
        misconfig_count=len(report.misconfigurations),
        output_path=summary_path,
    )

    return report
