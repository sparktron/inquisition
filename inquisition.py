"""Command-line interface for Inquisition — website fingerprinting and security recon tool."""

from __future__ import annotations

import argparse
import logging
import sys

# Suppress urllib3 SSL warnings (read-only reconnaissance, unverified requests expected)
import urllib3
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
        choices=["text", "json", "html"],
        default="text",
        dest="report_format",
        help="Report output format. Default: text",
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
        ports=ports,
    )

    try:
        run_scan(
            config,
            skip_auth=True,
            brief=args.brief,
            output_path=args.output,
        )
    except KeyboardInterrupt:
        from ui import print_interrupted
        print_interrupted()
        sys.exit(130)


if __name__ == "__main__":
    main()
