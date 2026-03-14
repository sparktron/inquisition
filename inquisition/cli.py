"""Command-line interface for inquisition."""

from __future__ import annotations

import argparse
import sys

from inquisition.models import ReportFormat, ScanConfig, ScanDepth


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inquisition",
        description="Website fingerprinting and security reconnaissance tool.",
        epilog="This tool performs read-only, non-intrusive probing only.",
    )

    parser.add_argument(
        "target",
        help="Hostname or IP address to scan (e.g. example.com or 93.184.216.34)",
    )

    parser.add_argument(
        "-d", "--depth",
        choices=[d.value for d in ScanDepth],
        default=ScanDepth.STANDARD.value,
        help="Scan depth: quick (top ports, basic checks), standard (default), "
             "deep (full port range, thorough probing)",
    )

    parser.add_argument(
        "-f", "--format",
        choices=[f.value for f in ReportFormat],
        default=ReportFormat.TEXT.value,
        help="Report output format (default: text)",
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Maximum number of concurrent threads (default: 10)",
    )

    parser.add_argument(
        "--safe-mode",
        action="store_true",
        default=True,
        help="Enable safe mode — restrict to read-only probes (default: on)",
    )
    parser.add_argument(
        "--no-safe-mode",
        dest="safe_mode",
        action="store_false",
        help="Disable safe mode (not recommended)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what would be done without sending any network traffic",
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.1,
        help="Minimum seconds between requests (default: 0.1)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        default=False,
        help="Skip the interactive authorization prompt",
    )

    return parser


def parse_args(argv: list[str] | None = None) -> tuple[ScanConfig, bool]:
    """Parse CLI arguments and return a ScanConfig and skip-auth flag."""

    parser = build_parser()
    args = parser.parse_args(argv)

    config = ScanConfig(
        target=args.target,
        depth=ScanDepth(args.depth),
        report_format=ReportFormat(args.format),
        max_threads=args.threads,
        safe_mode=args.safe_mode,
        dry_run=args.dry_run,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
    )

    return config, args.yes


def main(argv: list[str] | None = None) -> None:
    """Entry point for the CLI."""

    from inquisition.scanner import run_scan  # avoid circular imports

    config, skip_auth = parse_args(argv)
    try:
        run_scan(config, skip_auth=skip_auth)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
