"""Command-line interface for Inquisition — website fingerprinting and security recon tool."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Callable

# Suppress urllib3 SSL warnings (read-only reconnaissance, unverified requests expected)
import urllib3  # type: ignore[import-untyped]

from config_validation import (
    ConfigValidationError,
    coerce_float,
    coerce_int,
    coerce_ports,
    validate_auth_material,
)
from models import ReportFormat, ScanConfig, ScanDepth, ScanReport, Severity
from scanner import run_scan

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
            "  inquisition 192.168.1.0/24 --depth quick  # scan every host on a /24\n"
            "  inquisition --targets-file hosts.txt --format sarif --output reports/\n"
        ),
    )

    parser.add_argument(
        "target",
        nargs="*",
        help="One or more hostnames, IP addresses, or CIDR ranges to scan "
        "(space-separated). A CIDR range such as 192.168.1.0/24 expands "
        "to its individual host addresses.",
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
        "--discovery",
        action="store_true",
        help=(
            "Discovery sweep only: liveness + role classification (open ports + "
            "reverse DNS), skipping TLS/HTTP/CVE. Fast across large ranges and the "
            "default for a subnet/CIDR scan."
        ),
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "Run full per-host recon even on a subnet/CIDR scan (opt out of the "
            "default discovery sweep). Implied by --depth deep."
        ),
    )

    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "html", "sarif", "markdown"],
        default="text",
        dest="report_format",
        help="Report output format (sarif for CI / GitHub code scanning, markdown for PRs / docs). Default: text",
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
        default=None,
        metavar="N",
        help=(
            "Scan up to N targets concurrently. Default: sequential for a normal "
            "run, but a subnet/CIDR scan auto-parallelizes (up to "
            f"{_AUTO_JOBS_CAP}) unless you set N. With more than one target, N>1 "
            "suppresses each scan's live UI and prints a concise per-target line "
            "as it finishes, then the fleet table."
        ),
    )
    parser.add_argument(
        "--per-host-logs",
        action="store_true",
        dest="per_host_logs",
        help=(
            "On a subnet/CIDR scan, show each host's full scan log instead of the "
            "single consolidated subnet log (implies sequential unless --jobs is set)."
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
        "--sla-by-severity",
        metavar="SPEC",
        dest="sla_by_severity",
        help=(
            "Per-severity SLA overrides as comma-separated severity=scans pairs, "
            "e.g. 'critical=1,high=3,medium=10'. Falls back to --sla-max-age for "
            "severities not listed. A value of 0 disables the SLA for that severity."
        ),
    )

    parser.add_argument(
        "--attack-navigator",
        metavar="FILE",
        dest="attack_navigator",
        help=(
            "Write a MITRE ATT&CK Navigator layer (layer.json) covering all "
            "targets to FILE. Import at mitre-attack.github.io/attack-navigator/ "
            "to overlay observed attacker techniques on the ATT&CK matrix."
        ),
    )

    parser.add_argument(
        "--fix-script",
        metavar="FILE",
        dest="fix_script",
        help=(
            "Write a bash runbook to FILE bundling every 'quick fix' finding "
            "(CRITICAL/HIGH/MEDIUM, config-only) across all targets as a "
            "reviewable checklist. Only read-only verification commands are left "
            "runnable; remediation steps stay commented since they routinely "
            "branch on your mail provider/framework/infra."
        ),
    )

    parser.add_argument(
        "--network-map",
        metavar="FILE",
        dest="network_map",
        help=(
            "Write an interactive HTML network-topology map spanning all targets "
            "to FILE: a hub-and-spoke diagram with the gateway/router at the "
            "centre and every live host around it, coloured by role "
            "(gateway/server/endpoint). Ideal after a subnet/CIDR discovery sweep."
        ),
    )

    parser.add_argument(
        "--metrics-output",
        metavar="FILE",
        dest="metrics_output",
        help=(
            "Write Prometheus/OpenMetrics text exposition (findings by severity, "
            "risk score, CVE/misconfig counts, max finding age, scan duration) for "
            "all targets to FILE, in addition to the normal report."
        ),
    )

    parser.add_argument(
        "--metrics-push",
        metavar="URL",
        dest="metrics_push",
        help=(
            "Push the Prometheus metrics to a Pushgateway base URL "
            "(e.g. http://localhost:9091). Uses PUT under --metrics-job."
        ),
    )

    parser.add_argument(
        "--metrics-job",
        metavar="NAME",
        default="inquisition",
        dest="metrics_job",
        help="Pushgateway job name for --metrics-push (default: inquisition)",
    )

    parser.add_argument(
        "--metrics-history",
        action="store_true",
        dest="metrics_history",
        help=(
            "In --metrics-output, emit the findings trend as timestamped samples "
            "per stored history scan (for backfill; not used by --metrics-push)."
        ),
    )

    parser.add_argument(
        "--fleet-config",
        metavar="FILE",
        dest="fleet_config",
        help=(
            "JSON or YAML file defining targets and per-target scan overrides "
            "(depth, ports, auth, SLA, …). ${VAR} references are filled from the "
            "environment. Supplies the target list; positional targets and "
            "--targets-file are not used with it."
        ),
    )

    parser.add_argument(
        "--watch",
        type=int,
        default=0,
        metavar="SECONDS",
        help=(
            "Run continuously: re-scan all targets every SECONDS until interrupted "
            "(Ctrl-C). Pairs with --notify/--metrics-push for monitoring. --fail-on "
            "only warns in watch mode rather than exiting. On SIGHUP, a --fleet-config "
            "is reloaded without restarting."
        ),
    )

    parser.add_argument(
        "--watch-jitter",
        type=float,
        default=0.0,
        metavar="SECONDS",
        dest="watch_jitter",
        help=(
            "In watch mode, stagger each target's scan by a random 0–SECONDS delay "
            "so they don't all fire at once (spreads load; avoids synchronized "
            "scrapes across instances)."
        ),
    )

    parser.add_argument(
        "--metrics-serve",
        type=int,
        default=0,
        metavar="PORT",
        dest="metrics_serve",
        help=(
            "Serve the latest metrics for Prometheus to scrape at "
            "http://HOST:PORT/metrics (refreshed after each scan), plus liveness "
            "/healthz and readiness /readyz. The pull-based alternative to "
            "--metrics-push; most useful with --watch."
        ),
    )

    parser.add_argument(
        "--audit-log",
        metavar="FILE",
        dest="audit_log",
        help=(
            "Append one JSON line per scan cycle (targets, severity counts, "
            "highest severity, durations, fail-on status) to FILE for ingestion."
        ),
    )

    parser.add_argument(
        "--audit-max-bytes",
        type=int,
        default=0,
        metavar="N",
        dest="audit_max_bytes",
        help="Rotate the audit log when it would exceed N bytes (0 = no rotation)",
    )

    parser.add_argument(
        "--audit-backups",
        type=int,
        default=3,
        metavar="N",
        dest="audit_backups",
        help="Number of rotated audit-log backups to keep (default: 3)",
    )

    parser.add_argument(
        "--audit-max-age-days",
        type=float,
        default=0,
        metavar="DAYS",
        dest="audit_max_age_days",
        help="Rotate the audit log when its oldest record is older than DAYS (0 = off)",
    )

    parser.add_argument(
        "--brief",
        action="store_true",
        help="Omit verbose deep-analysis and remediation guide from text/HTML report",
    )

    parser.add_argument(
        "--attacker-pov",
        action="store_true",
        dest="attacker_pov",
        help=(
            "Render findings from an attacker's perspective: ordered by exploitability "
            "(easiest-to-exploit first), with PoC commands highlighted and kill chains "
            "annotated. Useful for prioritising patching under time pressure."
        ),
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
        help="Skip the active-scan authorization prompt when used with --active",
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
        "--validate",
        action="store_true",
        dest="validate_poc",
        help=(
            "Run the READ-ONLY verification probes attached to findings (curl -sI, dig, "
            "openssl s_client, status checks) to capture live evidence and confirm modeled "
            "findings. Mutating PoCs are never executed. Requires authorization; prompts unless --yes."
        ),
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

    args = parser.parse_args(argv)
    try:
        _validate_cli_numbers(args)
    except ConfigValidationError as exc:
        parser.error(str(exc))
    return args


def _validate_cli_numbers(args: argparse.Namespace) -> None:
    """Apply explicit range and zero semantics to every numeric CLI option."""
    if args.jobs is not None:
        coerce_int(args.jobs, "--jobs", minimum=1)
    coerce_int(args.history_size, "--history-size", minimum=1)
    coerce_int(args.history_max_age_days, "--history-max-age-days", minimum=0)
    coerce_int(args.sla_max_age, "--sla-max-age", minimum=0)
    coerce_int(args.watch, "--watch", minimum=0)
    coerce_float(args.watch_jitter, "--watch-jitter", minimum=0)
    metrics_port = coerce_int(args.metrics_serve, "--metrics-serve", minimum=0)
    if metrics_port > 65535:
        raise ConfigValidationError(f"--metrics-serve must be 0 or in 1..65535, got {metrics_port}")
    coerce_int(args.audit_max_bytes, "--audit-max-bytes", minimum=0)
    coerce_int(args.audit_backups, "--audit-backups", minimum=0)
    coerce_float(args.audit_max_age_days, "--audit-max-age-days", minimum=0)
    coerce_int(args.threads, "--threads", minimum=1)
    coerce_float(args.rate_limit, "--rate-limit", minimum=0)
    coerce_float(args.timeout, "--timeout", exclusive_minimum=0)
    coerce_float(args.connect_timeout, "--connect-timeout", exclusive_minimum=0)
    if args.ports is not None:
        coerce_ports(args.ports, "--ports")
    validate_auth_material(args.auth_header, args.auth_cookie)


# Upper bound on the number of addresses a single CIDR target may expand to.
# Guards against a fat-fingered prefix (e.g. a /8) silently launching a sweep
# of millions of hosts; a /20 (4096 addresses) is the widest range accepted.
_MAX_CIDR_HOSTS = 4096


def _expand_target_token(token: str) -> list[str]:
    """Expand a CIDR target into individual host addresses.

    A token without a ``/`` is a hostname or bare IP and is returned unchanged.
    A token containing ``/`` is treated as an IP network: host bits are allowed
    (``192.168.1.5/24`` scans the whole ``/24``); the network and broadcast
    addresses are dropped for ranges wider than a ``/31``, while a ``/32`` (or
    IPv6 ``/128``) yields its single address. An unparseable network, or one
    larger than ``_MAX_CIDR_HOSTS`` addresses, is a hard error (exit code 2) so
    a mistyped prefix cannot silently expand into a massive scan.
    """
    if "/" not in token:
        return [token]
    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError as exc:
        from ui import print_error
        print_error(f"invalid target {token!r}", f"not a valid IP network: {exc}")
        sys.exit(2)
    if network.num_addresses > _MAX_CIDR_HOSTS:
        from ui import print_error
        print_error(
            f"target range {token!r} is too large",
            f"{network.num_addresses} addresses exceeds the {_MAX_CIDR_HOSTS} limit; "
            "use a narrower prefix (a /24 is 256) or list hosts explicitly",
        )
        sys.exit(2)
    hosts = [str(h) for h in network.hosts()]
    # hosts() is non-empty for /31, /32, /127 and /128, but never let a valid
    # network expand to nothing.
    return hosts or [str(network.network_address)]


def _gather_targets_and_meta(args: argparse.Namespace) -> tuple[list[str], bool]:
    """Merge positional targets with --targets-file and expand CIDR ranges.

    Returns the de-duplicated, order-preserving target list and whether the run
    originates from a subnet — i.e. at least one input token expanded to more
    than one address (a ``/32`` or a bare host does not count).
    """
    raw: list[str] = list(args.target)
    if args.targets_file:
        try:
            with open(args.targets_file, encoding="utf-8") as fh:
                for line in fh:
                    host = line.strip()
                    if host and not host.startswith("#"):
                        raw.append(host)
        except OSError as exc:
            from ui import print_error
            print_error(f"could not read --targets-file {args.targets_file}", str(exc))
            sys.exit(2)

    seen: set[str] = set()
    unique: list[str] = []
    is_subnet = False
    for token in raw:
        expanded = _expand_target_token(token)
        if len(expanded) > 1:
            is_subnet = True
        for host in expanded:
            if host not in seen:
                seen.add(host)
                unique.append(host)
    return unique, is_subnet


def _gather_targets(args: argparse.Namespace) -> list[str]:
    """The target list only (see ``_gather_targets_and_meta``)."""
    return _gather_targets_and_meta(args)[0]


def _parse_sla_overrides(spec: str | None) -> tuple[tuple[str, int], ...]:
    """Parse 'critical=1,high=3' into (('critical',1),('high',3)). Exits on bad input."""
    if not spec:
        return ()
    valid = {s.value for s in Severity}
    pairs: list[tuple[str, int]] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, sep, value = chunk.partition("=")
        key = key.strip().lower()
        if not sep or key not in valid or not value.strip().lstrip("-").isdigit():
            from ui import print_error
            print_error(
                f"invalid --sla-by-severity entry: {chunk!r}",
                "use severity=scans pairs, e.g. critical=1,high=3 (severities: "
                + ", ".join(sorted(valid)) + ")",
            )
            sys.exit(2)
        n = int(value.strip())
        if n < 0:
            from ui import print_error
            print_error(
                f"invalid --sla-by-severity entry: {chunk!r}",
                "values must be non-negative (use 0 to disable a severity)",
            )
            sys.exit(2)
        pairs.append((key, n))
    return tuple(pairs)


def _output_path_for(output: str | None, target: str, fmt: ReportFormat, multi: bool) -> str | None:
    """Per-target output path. For multiple targets, --output is treated as a directory."""
    if not multi:
        return output
    if not output:
        return None  # run_scan auto-names under reports/
    ext = {ReportFormat.JSON: "json", ReportFormat.HTML: "html",
           ReportFormat.SARIF: "sarif", ReportFormat.MARKDOWN: "md"}.get(fmt, "txt")
    safe = "".join(c if c.isalnum() or c in "-." else "_" for c in target)
    # Each website gets its own subfolder under the --output directory, so a
    # fleet run produces reports/<dir>/<site>/<site>.<ext> rather than a flat pile.
    out_dir = Path(output) / safe
    out_dir.mkdir(parents=True, exist_ok=True)
    return str(out_dir / f"{safe}.{ext}")


def _discovery_mode(args: argparse.Namespace, is_subnet: bool) -> bool:
    """Whether to run the fast discovery sweep (liveness + role signals only).

    Explicit ``--discovery`` always wins; ``--full`` or ``--depth deep`` force
    full recon; otherwise a subnet/CIDR scan defaults to discovery.
    """
    if args.discovery:
        return True
    if args.full or args.depth == "deep":
        return False
    return is_subnet


def _resolve_targets(
    args: argparse.Namespace, base_config: ScanConfig
) -> tuple[list[str], dict[str, ScanConfig], bool]:
    """Resolve the target list, per-target configs, and whether this is a subnet run.

    Raises ``fleet_config.FleetConfigError`` on a bad fleet config (so callers can
    choose to exit on first load but keep running on a failed live reload). A
    fleet-config run is never treated as a subnet scan. Discovery mode (fast
    liveness + role sweep) is applied per target: it is the default for a subnet
    scan and can be forced on/off with --discovery / --full.
    """
    if args.fleet_config:
        from fleet_config import interpolate_env, load_fleet_config, resolved_configs
        raw = interpolate_env(load_fleet_config(args.fleet_config))
        configs = resolved_configs(raw, base_config)
        config_by_target = {c.target: c for c in configs}
        if args.discovery or args.full:
            disc = _discovery_mode(args, False)
            config_by_target = {t: replace(c, discovery=disc) for t, c in config_by_target.items()}
        return list(config_by_target.keys()), config_by_target, False
    targets, is_subnet = _gather_targets_and_meta(args)
    discovery = _discovery_mode(args, is_subnet)
    return (
        targets,
        {t: replace(base_config, target=t, discovery=discovery) for t in targets},
        is_subnet,
    )


def _jitter_delay(jitter: float) -> float:
    """A random delay in [0, jitter] seconds (0 when jitter is non-positive)."""
    if jitter <= 0:
        return 0.0
    import random
    return random.uniform(0, jitter)


def _install_sighup_reload(
    args: argparse.Namespace, announce: Callable[[str], None]
) -> threading.Event:
    """Return an Event set on SIGHUP, used to trigger a fleet-config reload."""
    flag = threading.Event()
    import signal
    if args.fleet_config and hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda *_: flag.set())
        announce("watch: send SIGHUP to reload the fleet config without restarting")
    return flag


def _install_sigterm_drain(announce: Callable[[str], None]) -> threading.Event:
    """Return an Event set on SIGTERM, used to drain after the current cycle."""
    flag = threading.Event()
    import signal
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: flag.set())
        announce("watch: SIGTERM will drain (finish the current cycle, then exit)")
    return flag


def _install_sigusr1_runnow(announce: Callable[[str], None]) -> threading.Event:
    """Return an Event set on SIGUSR1, used to trigger an immediate scan cycle."""
    flag = threading.Event()
    import signal
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, lambda *_: flag.set())
        announce("watch: send SIGUSR1 to run a scan cycle immediately")
    return flag


def _sleep_interruptible(seconds: float, *events: threading.Event) -> bool:
    """Sleep up to ``seconds``, returning True early if any of ``events`` is set.

    Sleeps in short steps so a signal during the inter-cycle wait is honored
    within ~1s instead of blocking for the full interval.
    """
    def _any() -> bool:
        return any(e.is_set() for e in events)

    remaining = float(seconds)
    while remaining > 0:
        if _any():
            return True
        time.sleep(min(1.0, remaining))
        remaining -= 1.0
    return _any()


_AUTO_JOBS_CAP = 16


def _resolve_jobs(explicit: int | None, target_count: int, *, consolidated: bool) -> int:
    """Effective concurrency for a run.

    Honors an explicit ``--jobs`` value. Otherwise a consolidated (subnet) run
    auto-parallelizes up to ``_AUTO_JOBS_CAP``; any other run stays sequential.
    """
    if explicit is not None:
        return explicit
    if consolidated and target_count > 1:
        return min(target_count, _AUTO_JOBS_CAP)
    return 1


def _print_progress_line(done: int, total: int, report: ScanReport) -> None:
    """One concise per-host line for the consolidated multi-target log.

    Shows the classified role and liveness so a subnet sweep reads as a map in
    progress (e.g. "gateway", "server", or "down" for a host that never answered).
    """
    from host_classification import HostRole, classify
    from ui import print_info
    profile = classify(report)
    findings = sum(report.summary_counts().values())
    if not profile.live:
        print_info(f"[{done}/{total}] {report.target} — down")
        return
    role = "" if profile.role is HostRole.UNKNOWN else f"{profile.role.value} · "
    highest = report.highest_severity()
    print_info(
        f"[{done}/{total}] {report.target} — {role}"
        f"{findings} finding(s), highest {highest.value if highest else 'none'}"
    )


def _run_targets(
    targets: list[str],
    scan_fn: Callable[[str], ScanReport],
    *,
    jobs: int,
    on_done: Callable[[int, int, ScanReport], None] | None = None,
) -> list[ScanReport]:
    """Run scan_fn over targets, returning reports in target order.

    ``on_done(done, total, report)`` is invoked on the calling thread as each
    report completes — in both sequential and concurrent modes — so a caller can
    emit one consolidated progress line per host. With jobs > 1 the scans run
    concurrently (they should run quiet to avoid interleaved output); the
    returned list always matches the input target order regardless of jobs.
    """
    if jobs <= 1:
        reports: list[ScanReport] = []
        for i, target in enumerate(targets):
            report = scan_fn(target)
            reports.append(report)
            if on_done is not None:
                on_done(i + 1, len(targets), report)
        return reports

    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: dict[int, ScanReport] = {}
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(scan_fn, t): i for i, t in enumerate(targets)}
        done = 0
        for fut in as_completed(futures):
            report = fut.result()
            results[futures[fut]] = report
            done += 1
            if on_done is not None:
                on_done(done, len(targets), report)
    return [results[i] for i in range(len(targets))]


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s  %(name)s: %(message)s")

    # Build shared ScanConfig fields
    depth = ScanDepth(args.depth)
    report_format = ReportFormat(args.report_format)

    default_ports: tuple[int, ...] = (
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
    )
    ports = tuple(args.ports) if args.ports else default_ports
    sla_overrides = _parse_sla_overrides(args.sla_by_severity)

    # A base config (target filled in per scan) shared by all targets unless a
    # fleet config overrides fields per target.
    base_config = ScanConfig(
        target="",
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
        discovery=args.discovery,
        validate_poc=args.validate_poc,
        auth_header=args.auth_header,
        auth_cookie=args.auth_cookie,
        sla_max_age=args.sla_max_age,
        sla_severity_overrides=sla_overrides,
    )

    from fleet_config import FleetConfigError
    from models import severity_at_least
    from ui import print_error, print_info, print_interrupted, print_warning

    combined = bool(args.combined_output)
    threshold = Severity(args.fail_on) if args.fail_on else None

    # Targets and their per-target configs (mutated in place on SIGHUP reload).
    try:
        targets, config_by_target, is_subnet = _resolve_targets(args, base_config)
    except FleetConfigError as exc:
        print_error(f"fleet config error: {exc}", f"check {args.fleet_config}")
        sys.exit(2)
    if not targets:
        print_error("no targets given", "pass hostnames, --targets-file, or --fleet-config")
        sys.exit(2)

    # Optional scrape + health endpoints, refreshed after every cycle.
    metrics_holder = None
    health = None
    if args.metrics_serve:
        from metrics_server import HealthState, MetricsHolder, start_metrics_server
        metrics_holder = MetricsHolder()
        health = HealthState()
        try:
            start_metrics_server(args.metrics_serve, metrics_holder, health=health)
            print_info(
                f"serving metrics at http://0.0.0.0:{args.metrics_serve}/metrics "
                "(+ /healthz, /readyz)"
            )
        except OSError as exc:
            print_error(f"could not start metrics server on :{args.metrics_serve}", str(exc))
            sys.exit(2)

    def _cycle(cycle: int) -> bool:
        """Run one full pass over the current targets. Returns whether --fail-on was met."""
        multi = len(targets) > 1
        # A subnet scan collapses to one consolidated log unless --per-host-logs
        # is set, and auto-parallelizes when --jobs was not given explicitly.
        consolidated = is_subnet and not args.per_host_logs
        jobs = _resolve_jobs(args.jobs, len(targets), consolidated=consolidated)
        concurrent = jobs > 1 and multi
        quiet = concurrent or consolidated
        if consolidated:
            disc = any(c.discovery for c in config_by_target.values())
            print_info(
                f"subnet scan: {len(targets)} host(s), "
                f"{jobs if concurrent else 1}-way concurrent — "
                f"{'discovery sweep' if disc else 'full recon'}, consolidated log"
            )

        def _scan(target: str) -> ScanReport:
            if args.watch > 0 and args.watch_jitter > 0:
                time.sleep(_jitter_delay(args.watch_jitter))
            return run_scan(
                config_by_target[target],
                skip_auth=args.authorized or args.dry_run,
                brief=args.brief,
                attacker_pov=args.attacker_pov,
                # In combined mode, suppress per-target files; one artifact is written below.
                output_path=None if combined else _output_path_for(args.output, target, report_format, multi),
                notify_url=args.notify_url,
                notify_min_severity=Severity(args.notify_min_severity),
                notify_on=args.notify_on,
                write_report=not combined,
                history_size=args.history_size,
                history_max_age_days=args.history_max_age_days,
                quiet=quiet,
            )

        on_done = _print_progress_line if (concurrent or consolidated) else None
        try:
            reports = _run_targets(
                targets, _scan, jobs=jobs if multi else 1, on_done=on_done
            )
        except KeyboardInterrupt:
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
            artifact = render_combined(reports, report_format, brief=args.brief, attacker_pov=args.attacker_pov)
            try:
                with open(args.combined_output, "w", encoding="utf-8") as fh:
                    fh.write(artifact)
                for row in fleet_rows:
                    row["report"] = args.combined_output
                print_info(f"combined {len(reports)} report(s) into {args.combined_output}")
            except OSError as exc:
                print_error(f"could not write combined artifact to {args.combined_output}", str(exc))
                sys.exit(2)

        # --- MITRE ATT&CK Navigator layer export ---
        if args.attack_navigator:
            from mitre import render_navigator_layer
            try:
                with open(args.attack_navigator, "w", encoding="utf-8") as fh:
                    fh.write(render_navigator_layer(reports))
                print_info(f"wrote ATT&CK Navigator layer for {len(reports)} target(s) to {args.attack_navigator}")
            except OSError as exc:
                print_error(f"could not write ATT&CK Navigator layer to {args.attack_navigator}", str(exc))
                sys.exit(2)

        # --- Quick-fix runbook export ---
        if args.fix_script:
            from fix_script import render_fix_script
            try:
                with open(args.fix_script, "w", encoding="utf-8") as fh:
                    fh.write(render_fix_script(reports))
                print_info(f"wrote quick-fix runbook for {len(reports)} target(s) to {args.fix_script}")
            except OSError as exc:
                print_error(f"could not write quick-fix runbook to {args.fix_script}", str(exc))
                sys.exit(2)

        # --- Interactive network-topology map ---
        if args.network_map:
            from host_classification import detect_default_gateway
            from report import render_network_map
            try:
                gateway = detect_default_gateway()
                with open(args.network_map, "w", encoding="utf-8") as fh:
                    fh.write(render_network_map(reports, default_gateway=gateway))
                print_info(f"wrote network map for {len(reports)} host(s) to {args.network_map}")
            except OSError as exc:
                print_error(f"could not write network map to {args.network_map}", str(exc))
                sys.exit(2)

        # --- Prometheus / OpenMetrics export (file / push / scrape) ---
        if args.metrics_output or args.metrics_push or metrics_holder is not None:
            from metrics import push_metrics, render_prometheus
            if args.metrics_output:
                try:
                    with open(args.metrics_output, "w", encoding="utf-8") as fh:
                        fh.write(render_prometheus(reports, include_history=args.metrics_history))
                    print_info(f"wrote metrics for {len(reports)} target(s) to {args.metrics_output}")
                except OSError as exc:
                    print_error(f"could not write metrics to {args.metrics_output}", str(exc))
                    sys.exit(2)
            if metrics_holder is not None:
                metrics_holder.set(render_prometheus(reports))
            if args.metrics_push:
                # Pushgateway rejects timestamped samples, so push current gauges only.
                try:
                    push_metrics(args.metrics_push, render_prometheus(reports), job=args.metrics_job)
                    print_info(f"pushed metrics to {args.metrics_push} (job={args.metrics_job})")
                except Exception as exc:
                    print_error(f"could not push metrics to {args.metrics_push}", str(exc))
                    sys.exit(2)

        # --- Fleet overview (only when more than one target was scanned) ---
        if len(targets) > 1:
            from ui import print_fleet_summary
            print_fleet_summary(fleet_rows)

        # --- Audit log (one JSON line per cycle) ---
        if args.audit_log:
            from audit import append_jsonl, build_cycle_record
            try:
                append_jsonl(
                    args.audit_log,
                    build_cycle_record(reports, cycle=cycle, fail_triggered=fail_triggered),
                    max_bytes=args.audit_max_bytes,
                    backups=args.audit_backups,
                    max_age_days=args.audit_max_age_days,
                )
            except OSError as exc:
                print_warning(f"could not write audit log {args.audit_log}: {exc}")

        # --- Health / readiness state for the scrape server ---
        if health is not None:
            health.record_cycle(len(reports))

        return fail_triggered

    # --- Watch mode: loop on an interval until interrupted ---
    # SIGHUP reloads the fleet config; SIGTERM drains (finish the in-flight cycle
    # then exit cleanly); Ctrl-C / SIGINT stops immediately.
    if args.watch > 0:
        reload_flag = _install_sighup_reload(args, print_info)
        stop_flag = _install_sigterm_drain(print_info)
        runnow_flag = _install_sigusr1_runnow(print_info)
        cycle = 0
        try:
            while True:
                if reload_flag.is_set():
                    reload_flag.clear()
                    try:
                        new_targets, new_cfg, _ = _resolve_targets(args, base_config)
                        targets[:] = new_targets
                        config_by_target.clear()
                        config_by_target.update(new_cfg)
                        print_info(f"watch: reloaded fleet config — {len(targets)} target(s)")
                    except FleetConfigError as exc:
                        print_warning(f"watch: fleet reload failed, keeping previous config: {exc}")
                runnow_flag.clear()
                cycle += 1
                print_info(f"watch: scan cycle {cycle} ({len(targets)} target(s))")
                if _cycle(cycle) and threshold:
                    print_warning(
                        f"fail-on: a finding meets threshold '{threshold.value}' "
                        "(watch mode — not exiting)"
                    )
                if stop_flag.is_set():
                    print_info("watch: SIGTERM received — drained after current cycle, exiting")
                    sys.exit(0)
                print_info(f"watch: sleeping {args.watch}s — Ctrl-C to stop")
                if _sleep_interruptible(args.watch, stop_flag, runnow_flag):
                    if stop_flag.is_set():
                        print_info("watch: SIGTERM received — exiting")
                        sys.exit(0)
                    print_info("watch: SIGUSR1 received — running now")
        except KeyboardInterrupt:
            print_interrupted()
            sys.exit(130)

    # --- Single run ---
    failed = _cycle(1)
    if metrics_holder is not None:
        # Keep serving the single result for scraping until interrupted.
        print_info(f"serving metrics on :{args.metrics_serve} — Ctrl-C to stop")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print_interrupted()
            sys.exit(130)
    if failed and threshold:
        print_warning(f"fail-on: a finding meets threshold '{threshold.value}' — exiting 1")
        sys.exit(1)


if __name__ == "__main__":
    main()
