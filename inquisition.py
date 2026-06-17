"""Command-line interface for Inquisition — website fingerprinting and security recon tool."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure local modules can be imported
sys.path.insert(0, str(Path(__file__).parent))

# Suppress urllib3 SSL warnings (read-only reconnaissance, unverified requests expected)
import urllib3  # type: ignore[import-untyped]
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from typing import Callable

from models import ReportFormat, ScanConfig, ScanDepth, ScanReport
from scanner import run_scan


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="inquisition",
        description="Inquisition — website fingerprinting & security reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  inquisition example.com\n"
            "  inquisition example.com --depth deep --format html --output report.html\n"
            "  inquisition example.com --depth quick --brief\n"
            "  inquisition 192.168.1.10 --ports 22 80 443 8080 --dry-run\n"
            "  inquisition a.com b.com c.com           # fleet scan (multiple targets)\n"
            "  inquisition --targets-file hosts.txt --format sarif --output reports/\n"
        ),
    )

    parser.add_argument(
        "target",
        nargs="*",
        help="One or more hostnames or IP addresses to scan (space-separated)",
    )

    parser.add_argument(
        "--targets-file",
        metavar="FILE",
        dest="targets_file",
        help=(
            "Read additional targets from FILE, one per line (blank lines and "
            "lines starting with # are ignored). Combined with any positional targets."
        ),
    )

    parser.add_argument(
        "--depth", "-d",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Scan depth: quick (5 ports), standard (20 ports + probing), deep (1-1024 ports + full probing). Default: standard",
    )

    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "html", "sarif"],
        default="text",
        dest="report_format",
        help="Report output format (sarif for CI / GitHub code scanning). Default: text",
    )

    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        dest="fail_on",
        help=(
            "Exit non-zero (code 1) if any finding is at or above this severity. "
            "For CI gating. Default: never fail on findings."
        ),
    )

    parser.add_argument(
        "--notify",
        metavar="URL",
        default=None,
        dest="notify_url",
        help=(
            "Webhook URL to POST a regression alert to when a new or worsened "
            "finding appears vs the previous scan. Slack incoming-webhook URLs "
            "(hooks.slack.com) get a formatted message; any other URL gets JSON."
        ),
    )

    parser.add_argument(
        "--notify-min-severity",
        choices=["critical", "high", "medium", "low"],
        default="high",
        dest="notify_min_severity",
        help="Only notify for new/regressed findings at or above this severity (default: high)",
    )

    parser.add_argument(
        "--notify-on",
        choices=["regression", "changes", "always"],
        default="regression",
        dest="notify_on",
        help=(
            "When to send a notification: 'regression' (new/worsened finding at or "
            "above --notify-min-severity; default), 'changes' (any new/fixed/"
            "regressed/improved finding), or 'always' (every scan, even a clean one "
            "— a scheduled heartbeat)."
        ),
    )

    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write report to FILE instead of stdout",
    )

    parser.add_argument(
        "--combined-output",
        metavar="FILE",
        dest="combined_output",
        help=(
            "Write a single combined artifact spanning all targets to FILE "
            "(instead of one report per target). JSON and SARIF are merged "
            "structurally (a fleet object / multi-run SARIF); text and HTML are "
            "concatenated. Ideal for uploading one SARIF file from a fleet CI run."
        ),
    )

    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=1,
        metavar="N",
        help=(
            "Scan up to N targets concurrently (default: 1 = sequential). With "
            "more than one target, N>1 suppresses each scan's live UI and prints "
            "a concise per-target line as it finishes, then the fleet table."
        ),
    )

    parser.add_argument(
        "--history-size",
        type=int,
        default=10,
        metavar="N",
        dest="history_size",
        help="Number of past scans to retain per target for trend tracking (default: 10)",
    )

    parser.add_argument(
        "--history-max-age-days",
        type=int,
        default=0,
        metavar="DAYS",
        dest="history_max_age_days",
        help="Also drop history entries older than DAYS (0 = retain by count only)",
    )

    parser.add_argument(
        "--sla-max-age",
        type=int,
        default=0,
        metavar="N",
        dest="sla_max_age",
        help=(
            "Warn (and notify, if --notify is set) when a finding has stayed open "
            "beyond N consecutive scans (0 = disabled). An SLA breach notifies even "
            "when nothing changed since the previous scan."
        ),
    )

    parser.add_argument(
        "--brief",
        action="store_true",
        help="Omit verbose deep-analysis and remediation guide from text/HTML report",
    )


    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        metavar="N",
        help="Maximum concurrent threads per module (default: 10)",
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.1,
        metavar="SECS",
        dest="rate_limit",
        help="Minimum seconds between requests within a module (default: 0.1)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECS",
        help="Per-request timeout in seconds (default: 10.0)",
    )

    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=2.0,
        metavar="SECS",
        dest="connect_timeout",
        help="TCP connect timeout for port scanning in seconds (default: 2.0)",
    )

    parser.add_argument(
        "--ports",
        type=int,
        nargs="+",
        metavar="PORT",
        help="Custom port list for STANDARD scan depth (overrides defaults)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Show what would be scanned without sending any network traffic",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )

    parser.add_argument(
        "--yes",
        "--i-am-authorized",
        action="store_true",
        dest="authorized",
        help="Confirm that you are authorized to scan the target and skip the interactive prompt",
    )

    active_group = parser.add_argument_group("active testing (sends payloads)")
    active_group.add_argument(
        "--active",
        action="store_true",
        help=(
            "Enable ACTIVE scanning (sends payloads via the selected active engine). NOT read-only. "
            "Requires authorization; prompts unless --yes is given."
        ),
    )
    active_group.add_argument(
        "--active-engine",
        choices=["nuclei", "zap"],
        default="nuclei",
        dest="active_engine",
        help="Active scanner engine to run when --active is set (default: nuclei)",
    )
    active_group.add_argument(
        "--auth-header",
        metavar="HEADER",
        default="",
        dest="auth_header",
        help="Authentication header for authenticated scanning, e.g. 'Authorization: Bearer <token>'",
    )
    active_group.add_argument(
        "--auth-cookie",
        metavar="COOKIE",
        default="",
        dest="auth_cookie",
        help="Cookie header for authenticated scanning, e.g. 'session=<value>'",
    )

    return parser.parse_args(argv)


def _gather_targets(args: argparse.Namespace) -> list[str]:
    """Merge positional targets with --targets-file, de-duplicated, order-preserving."""
    targets: list[str] = list(args.target)
    if args.targets_file:
        try:
            with open(args.targets_file, encoding="utf-8") as fh:
                for line in fh:
                    host = line.strip()
                    if host and not host.startswith("#"):
                        targets.append(host)
        except OSError as exc:
            from ui import print_error
            print_error(f"could not read --targets-file {args.targets_file}", str(exc))
            sys.exit(2)

    seen: set[str] = set()
    unique: list[str] = []
    for host in targets:
        if host not in seen:
            seen.add(host)
            unique.append(host)
    return unique


def _output_path_for(output: str | None, target: str, fmt: ReportFormat, multi: bool) -> str | None:
    """Per-target output path. For multiple targets, --output is treated as a directory."""
    if not multi:
        return output
    if not output:
        return None  # run_scan auto-names under reports/
    ext = {ReportFormat.JSON: "json", ReportFormat.HTML: "html",
           ReportFormat.SARIF: "sarif"}.get(fmt, "txt")
    safe = "".join(c if c.isalnum() or c in "-." else "_" for c in target)
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    return str(out_dir / f"{safe}.{ext}")


def _run_targets(
    targets: list[str], scan_fn: Callable[[str], ScanReport], *, jobs: int
) -> list[ScanReport]:
    """Run scan_fn over targets, returning reports in target order.

    With jobs > 1, targets run concurrently and a concise per-target line is
    printed as each finishes (the scans themselves run quiet to avoid interleaved
    output). Order of the returned list always matches the input target order.
    """
    if jobs <= 1:
        return [scan_fn(t) for t in targets]

    from concurrent.futures import ThreadPoolExecutor, as_completed
    from ui import print_info

    results: dict[int, ScanReport] = {}
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(scan_fn, t): i for i, t in enumerate(targets)}
        done = 0
        for fut in as_completed(futures):
            report = fut.result()
            results[futures[fut]] = report
            done += 1
            highest = report.highest_severity()
            total = sum(report.summary_counts().values())
            print_info(
                f"[{done}/{len(targets)}] {report.target} — "
                f"{total} finding(s), highest {highest.value if highest else 'none'}"
            )
    return [results[i] for i in range(len(targets))]


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s  %(name)s: %(message)s")

    targets = _gather_targets(args)
    if not targets:
        from ui import print_error
        print_error("no targets given", "pass one or more hostnames, or use --targets-file")
        sys.exit(2)

    # Build shared ScanConfig fields
    depth = ScanDepth(args.depth)
    report_format = ReportFormat(args.report_format)

    default_ports: tuple[int, ...] = (
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
    )
    ports = tuple(args.ports) if args.ports else default_ports

    from models import ScanReport, Severity, severity_at_least
    multi = len(targets) > 1
    combined = bool(args.combined_output)
    concurrent = args.jobs > 1 and multi
    threshold = Severity(args.fail_on) if args.fail_on else None

    def _scan(target: str) -> ScanReport:
        config = ScanConfig(
            target=target,
            depth=depth,
            report_format=report_format,
            max_threads=args.threads,
            safe_mode=True,
            dry_run=args.dry_run,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            connect_timeout=args.connect_timeout,
            ports=ports,
            active=args.active,
            active_engine=args.active_engine,
            auth_header=args.auth_header,
            auth_cookie=args.auth_cookie,
            sla_max_age=args.sla_max_age,
        )
        return run_scan(
            config,
            skip_auth=args.authorized or args.dry_run,
            brief=args.brief,
            # In combined mode, suppress per-target files; one artifact is written below.
            output_path=None if combined else _output_path_for(args.output, target, report_format, multi),
            notify_url=args.notify_url,
            notify_min_severity=Severity(args.notify_min_severity),
            notify_on=args.notify_on,
            write_report=not combined,
            history_size=args.history_size,
            history_max_age_days=args.history_max_age_days,
            quiet=concurrent,
        )

    try:
        reports = _run_targets(targets, _scan, jobs=args.jobs if concurrent else 1)
    except KeyboardInterrupt:
        from ui import print_interrupted
        print_interrupted()
        sys.exit(130)

    fleet_rows: list[dict[str, object]] = []
    fail_triggered = False
    for report in reports:
        highest = report.highest_severity()
        fleet_rows.append({
            "target": report.target,
            "counts": report.summary_counts(),
            "highest": highest.value if highest else None,
            "report": report.report_path,
        })
        if threshold and not args.dry_run and highest is not None and severity_at_least(highest, threshold):
            fail_triggered = True

    # --- Combined artifact spanning all targets ---
    if combined:
        from report import render_combined
        from ui import print_info, print_error
        artifact = render_combined(reports, report_format, brief=args.brief)
        try:
            with open(args.combined_output, "w", encoding="utf-8") as fh:
                fh.write(artifact)
            for row in fleet_rows:
                row["report"] = args.combined_output
            print_info(f"combined {len(reports)} report(s) into {args.combined_output}")
        except OSError as exc:
            print_error(f"could not write combined artifact to {args.combined_output}", str(exc))
            sys.exit(2)

    # --- Fleet overview (only when more than one target was scanned) ---
    if multi:
        from ui import print_fleet_summary
        print_fleet_summary(fleet_rows)

    # --- CI gating: exit non-zero when any target meets the --fail-on threshold ---
    if fail_triggered:
        from ui import print_warning
        print_warning(
            f"fail-on: a finding meets threshold '{threshold.value}' — exiting 1"  # type: ignore[union-attr]
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
