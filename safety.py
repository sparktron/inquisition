"""Safety guardrails — authorization, dry-run enforcement, read-only checks."""

from __future__ import annotations

import sys

from models import ScanConfig


_AUTHORIZATION_BANNER = """\
╔══════════════════════════════════════════════════════════════════╗
║                    AUTHORIZATION REQUIRED                       ║
╠══════════════════════════════════════════════════════════════════╣
║  Target : {target:<52s} ║
║  Depth  : {depth:<52s} ║
║  Mode   : {mode:<52s} ║
╠══════════════════════════════════════════════════════════════════╣
║  This tool performs READ-ONLY reconnaissance against the target ║
║  host.  No exploit payloads, authentication bypasses, or        ║
║  injection attempts will be sent.                               ║
║                                                                 ║
║  You MUST have authorization to scan the target.                ║
╚══════════════════════════════════════════════════════════════════╝
"""


def prompt_authorization(config: ScanConfig) -> bool:
    """Display authorization banner and ask the user to confirm.

    Returns True if the user confirms, False otherwise.
    """
    mode = "DRY-RUN (no traffic)" if config.dry_run else (
        "safe / read-only" if config.safe_mode else "standard"
    )

    print(_AUTHORIZATION_BANNER.format(
        target=config.target,
        depth=config.depth.value,
        mode=mode,
    ))

    try:
        answer = input("Do you have authorization to scan this target? [y/N] ").strip().lower()
    except EOFError:
        return False

    return answer in ("y", "yes")


def enforce_dry_run(config: ScanConfig) -> bool:
    """Return True when network calls should be suppressed."""
    return config.dry_run


def validate_config(config: ScanConfig) -> list[str]:
    """Return a list of validation warnings (empty if everything is fine)."""
    warnings: list[str] = []

    if not config.target:
        warnings.append("No target specified.")

    if config.max_threads < 1:
        warnings.append("Thread count must be >= 1.")

    if config.rate_limit < 0:
        warnings.append("Rate limit cannot be negative.")

    if config.timeout <= 0:
        warnings.append("Timeout must be positive.")

    return warnings


def abort(message: str) -> None:
    """Print an error message and exit."""
    print(f"[!] {message}", file=sys.stderr)
    sys.exit(1)
