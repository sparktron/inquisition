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

from models import ReportFormat, ScanConfig, ScanDepth
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
        ),
    )

    parser.add_argument(
        "target",
        help="Hostname or IP address to scan",
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
        "--output", "-o",
        metavar="FILE",
        help="Write report to FILE instead of stdout",
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


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s  %(name)s: %(message)s")

    # Build ScanConfig
    depth = ScanDepth(args.depth)
    report_format = ReportFormat(args.report_format)

    default_ports: tuple[int, ...] = (
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
    )
    ports = tuple(args.ports) if args.ports else default_ports

    config = ScanConfig(
        target=args.target,
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
    )

    try:
        from models import Severity
        report = run_scan(
            config,
            skip_auth=args.authorized or args.dry_run,
            brief=args.brief,
            output_path=args.output,
            notify_url=args.notify_url,
            notify_min_severity=Severity(args.notify_min_severity),
        )
    except KeyboardInterrupt:
        from ui import print_interrupted
        print_interrupted()
        sys.exit(130)

    # --- CI gating: exit non-zero when findings meet the --fail-on threshold ---
    if args.fail_on and not args.dry_run:
        from models import Severity, severity_at_least
        threshold = Severity(args.fail_on)
        highest = report.highest_severity()
        if highest is not None and severity_at_least(highest, threshold):
            from ui import print_warning
            print_warning(
                f"fail-on: highest finding severity '{highest.value}' "
                f"meets threshold '{threshold.value}' — exiting 1"
            )
            sys.exit(1)


if __name__ == "__main__":
    main()
