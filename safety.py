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


_ACTIVE_SCAN_BANNER = """\
================================================================
  !!  ACTIVE SCAN MODE  !!
================================================================
  Target : {target}

  Active mode sends ACTIVE PAYLOADS to the target via an external
  engine (Nuclei). This is NO LONGER read-only reconnaissance —
  it actively probes for vulnerabilities.

  Only proceed against systems you OWN or are EXPLICITLY
  AUTHORIZED in writing to test. Unauthorized active scanning
  may be illegal.
================================================================
"""


def confirm_active_scan(config: ScanConfig, *, assume_yes: bool) -> bool:
    """Show the active-scan warning and confirm intent to send payloads.

    ``assume_yes`` is True when the operator passed an explicit authorization
    flag (--yes). The warning is always shown; the prompt is skipped only when
    authorization was pre-asserted.
    """
    print(_ACTIVE_SCAN_BANNER.format(target=config.target))
    if assume_yes:
        return True
    try:
        answer = input(
            "Type 'I AM AUTHORIZED' to run active payload-based scanning: "
        ).strip()
    except EOFError:
        return False
    return answer == "I AM AUTHORIZED"


_VALIDATION_BANNER = """\
================================================================
  PoC VALIDATION MODE
================================================================
  Target : {target}

  Validation runs the READ-ONLY verification commands attached to
  findings (curl -sI, dig, openssl s_client, status probes) to
  capture live evidence. No payloads, writes, or mutating requests
  are sent — display-only PoCs are never executed.

  Only run this against systems you OWN or are AUTHORIZED to test.
================================================================
"""


def confirm_validation(config: ScanConfig, *, assume_yes: bool) -> bool:
    """Show the PoC-validation notice and confirm intent to run probes.

    Validation only executes the read-only, verification-class subset of PoC
    commands, so the gate is lighter than ``confirm_active_scan``: the notice is
    always shown, and a simple ``[y/N]`` confirms unless authorization was
    pre-asserted via ``assume_yes``.
    """
    print(_VALIDATION_BANNER.format(target=config.target))
    if assume_yes:
        return True
    try:
        answer = input(
            "Run read-only PoC verification probes against this target? [y/N] "
        ).strip().lower()
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

    if config.connect_timeout <= 0:
        warnings.append("Connect timeout must be positive.")

    return warnings


def abort(message: str) -> None:
    """Print an error message and exit."""
    print(f"[!] {message}", file=sys.stderr)
    sys.exit(1)
