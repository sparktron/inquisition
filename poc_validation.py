"""Safe PoC auto-validation harness (Theme E / E1).

Many findings carry an illustrative ``poc_command`` — the command an attacker (or
auditor) would run to demonstrate the issue. A large share of those are
**read-only verification probes**: ``curl -sI``, ``dig``, ``openssl s_client``,
status-code checks. Running them sends no payload and changes nothing on the
target, yet turns a *modeled* finding into one backed by **live captured
evidence**.

This module classifies a ``poc_command`` as safe-to-run or display-only, executes
only the safe, verification-class commands through an **injectable runner** (so
the logic is unit-testable without touching the network), captures their output,
and annotates the finding:

* ``finding.verification`` gets a human-readable summary,
* ``finding.metadata["poc_validation"]`` gets the structured evidence bundle
  (consumed by the report renderers — see Theme E / E2),
* ``finding.confidence`` is promoted to ``CONFIRMED`` once a probe has run and
  produced evidence.

Anything that mutates state — a POST/PUT, an upload, a shell pipeline, an
injection payload — is **never executed**; it stays display-only. The classifier
fails closed: when in doubt, a command is rejected.

A probe only *confirms* a finding when it exits cleanly with **evidence of a
successful response**. ``curl`` is therefore run with ``--fail`` injected so its
exit code reflects the HTTP status (>= 400 → non-zero); without it curl exits 0
on a 404 and a missing resource would masquerade as confirmation.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable

from models import Confidence, Finding

# Binaries whose verification-class invocations are read-only by nature. The
# allowlist is intentionally tiny; adding a binary here is a security decision.
_SAFE_BINARIES: frozenset[str] = frozenset(
    {"curl", "dig", "host", "nslookup", "openssl"}
)

# openssl is only read-only for connection/inspection subcommands; ``req``,
# ``genrsa``, ``ca`` etc. generate or write material and are rejected.
_SAFE_OPENSSL_SUBCOMMANDS: frozenset[str] = frozenset(
    {"s_client", "x509", "ocsp", "ciphers", "crl", "verify"}
)

# Shell metacharacters that imply chaining, redirection, or substitution. Their
# presence means the command is more than a single read-only probe — reject it
# even though we always execute with ``shell=False``.
_SHELL_METACHARS = re.compile(r"[;&|<>`$()\n\r{}]|&&|\|\|")

# curl flags that send a body, upload a file, or change the method to a mutating
# verb. Any of these disqualifies a curl command from auto-validation.
_CURL_MUTATING_FLAGS: frozenset[str] = frozenset(
    {
        "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
        "--data-ascii", "-F", "--form", "--form-string", "-T", "--upload-file",
        "-o", "--output", "-O", "--remote-name", "--remote-name-all",
    }
)

_CURL_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# curl reads these as a config file that can itself declare mutating options
# (-d, -o, -X POST, …), so an apparently read-only command could smuggle a write
# past the flag scan. Reject them outright.
_CURL_CONFIG_FLAGS: frozenset[str] = frozenset({"-K", "--config"})

# Only web schemes are in scope for a read-only probe. ``file://``, ``gopher://``,
# ``dict://`` etc. can read local files or reach internal services, so a curl
# carrying any non-web scheme is rejected.
_CURL_SAFE_SCHEMES: frozenset[str] = frozenset({"http", "https"})
_URL_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")

# curl flags that already make the exit code reflect HTTP success, so we don't
# inject our own. ``--fail`` / ``-f`` make curl exit non-zero on HTTP >= 400.
_CURL_FAIL_FLAGS: frozenset[str] = frozenset({"-f", "--fail", "--fail-with-body", "--fail-early"})

# Cap captured output so a chatty probe can't bloat the report / state file.
_MAX_OUTPUT_CHARS = 4000

# Per-command wall-clock ceiling (seconds). Verification probes are quick; this
# stops a hung handshake from stalling the whole scan.
_DEFAULT_TIMEOUT = 15.0


@dataclass
class PocCheck:
    """The outcome of considering (and possibly running) a single command."""

    command: str
    safe: bool
    ran: bool = False
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    skipped_reason: str = ""

    @property
    def confirming(self) -> bool:
        """True when the probe executed cleanly and produced evidence."""
        return self.ran and self.exit_code == 0


@dataclass
class PocValidation:
    """All validation checks attempted for one finding."""

    finding_title: str
    checks: list[PocCheck] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return any(c.confirming for c in self.checks)

    @property
    def attempted(self) -> bool:
        return any(c.ran for c in self.checks)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the evidence bundle for embedding in reports / metadata."""
        return {
            "confirmed": self.confirmed,
            "checks": [
                {
                    "command": c.command,
                    "safe": c.safe,
                    "ran": c.ran,
                    "exit_code": c.exit_code,
                    "stdout": c.stdout,
                    "stderr": c.stderr,
                    "skipped_reason": c.skipped_reason,
                }
                for c in self.checks
            ],
        }


def classify_command(command: str) -> tuple[bool, str]:
    """Decide whether ``command`` is a safe, read-only verification probe.

    Returns ``(is_safe, reason)``. ``reason`` explains a rejection (empty when
    safe). Fails closed: anything that cannot be parsed, uses an unknown binary,
    contains shell metacharacters, or would send a body is rejected.
    """
    command = command.strip()
    if not command:
        return False, "empty command"
    if command.startswith("#"):
        return False, "comment, not a command"
    if _SHELL_METACHARS.search(command):
        return False, "contains shell metacharacters (chaining/redirection)"

    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return False, f"unparseable command ({exc})"
    if not tokens:
        return False, "empty command"

    binary = os.path.basename(tokens[0])
    if binary not in _SAFE_BINARIES:
        return False, f"binary '{binary}' is not in the read-only allowlist"

    if binary == "curl":
        return _classify_curl(tokens)
    if binary == "openssl":
        return _classify_openssl(tokens)
    # dig / host / nslookup are read-only DNS lookups by construction.
    return True, ""


def _classify_curl(tokens: list[str]) -> tuple[bool, str]:
    for i, tok in enumerate(tokens[1:], start=1):
        # Split combined short flags' value form like --data=x.
        flag = tok.split("=", 1)[0]
        if flag in _CURL_MUTATING_FLAGS:
            return False, f"curl flag '{flag}' sends data or writes a file"
        if flag in _CURL_CONFIG_FLAGS:
            return False, f"curl flag '{flag}' reads a config file that can declare mutating options"
        if flag in ("-X", "--request"):
            method = ""
            if "=" in tok:
                method = tok.split("=", 1)[1]
            elif i + 1 < len(tokens):
                method = tokens[i + 1]
            if method.upper() not in _CURL_SAFE_METHODS:
                return False, f"curl uses mutating method '{method}'"
        # Any token carrying an explicit URL scheme must be a web scheme; reject
        # file://, gopher://, dict:// etc. that read local files or reach inward.
        scheme_match = _URL_SCHEME_RE.match(tok)
        if scheme_match and scheme_match.group(1).lower() not in _CURL_SAFE_SCHEMES:
            return False, f"curl URL scheme '{scheme_match.group(1)}' is not http(s)"
    return True, ""


def _classify_openssl(tokens: list[str]) -> tuple[bool, str]:
    if len(tokens) < 2:
        return False, "openssl with no subcommand"
    sub = tokens[1]
    if sub not in _SAFE_OPENSSL_SUBCOMMANDS:
        return False, f"openssl subcommand '{sub}' is not read-only"
    return True, ""


def _harden_curl(argv: list[str]) -> list[str]:
    """Make a curl probe's exit code reflect HTTP success.

    Without ``--fail``, ``curl`` exits 0 even on a 4xx/5xx response — it only
    fails on transport errors. That means a probe hitting a **404** (e.g. the
    ``.env`` an attacker hoped to read is gone) would still exit 0 and be
    treated as confirmation, falsely promoting the finding to *confirmed*.
    Injecting ``--fail`` makes curl exit non-zero on HTTP >= 400, so an exit 0
    genuinely means the resource responded successfully.

    Leaves non-curl argv untouched, and respects a ``--fail`` the author already
    supplied. (A 3xx redirect still exits 0 without ``-L``; that is an accepted
    limitation — the resource did respond.)
    """
    if not argv or os.path.basename(argv[0]) != "curl":
        return argv
    flags = {tok.split("=", 1)[0] for tok in argv[1:]}
    if flags & _CURL_FAIL_FLAGS:
        return argv
    return [argv[0], "--fail", *argv[1:]]


def _candidate_commands(poc_command: str) -> list[str]:
    """Split a possibly multi-line ``poc_command`` into individual commands."""
    return [line.strip() for line in poc_command.splitlines() if line.strip()]


def _truncate(text: str) -> str:
    text = text or ""
    if len(text) > _MAX_OUTPUT_CHARS:
        return text[:_MAX_OUTPUT_CHARS] + "\n…[truncated]"
    return text


def validate_finding(
    finding: Finding,
    *,
    runner: Callable[..., Any] = subprocess.run,
    timeout: float = _DEFAULT_TIMEOUT,
) -> PocValidation | None:
    """Run the safe verification probes for one finding and annotate it.

    Returns the :class:`PocValidation` (``None`` when the finding has no PoC at
    all). Mutates ``finding`` in place: records the evidence bundle in
    ``metadata['poc_validation']``, writes a ``verification`` summary, and — when
    a probe confirmed the finding — promotes ``confidence`` to ``CONFIRMED``.
    """
    if not finding.poc_command.strip():
        return None

    validation = PocValidation(finding_title=finding.title)

    for command in _candidate_commands(finding.poc_command):
        safe, reason = classify_command(command)
        check = PocCheck(command=command, safe=safe)
        if not safe:
            check.skipped_reason = reason
            validation.checks.append(check)
            continue
        _run_check(check, runner=runner, timeout=timeout)
        validation.checks.append(check)

    if not validation.checks:
        return None

    _annotate(finding, validation)
    return validation


def _run_check(
    check: PocCheck,
    *,
    runner: Callable[..., Any],
    timeout: float,
) -> None:
    try:
        argv = shlex.split(check.command)
    except ValueError as exc:
        check.skipped_reason = f"unparseable at run time ({exc})"
        check.safe = False
        return
    # Harden curl so exit 0 means a successful HTTP response, not just a
    # completed request (see _harden_curl). check.command keeps the original
    # text for display; only the executed argv is adjusted.
    argv = _harden_curl(argv)
    try:
        proc = runner(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        check.ran = True
        check.exit_code = None
        check.skipped_reason = "timed out"
        return
    except OSError as exc:  # FileNotFoundError is an OSError subclass
        check.skipped_reason = f"could not execute ({exc})"
        return

    check.ran = True
    check.exit_code = getattr(proc, "returncode", None)
    check.stdout = _truncate(getattr(proc, "stdout", "") or "")
    check.stderr = _truncate(getattr(proc, "stderr", "") or "")


def _annotate(finding: Finding, validation: PocValidation) -> None:
    finding.metadata["poc_validation"] = validation.as_dict()

    if validation.confirmed:
        finding.confidence = Confidence.CONFIRMED
        ran = next(c for c in validation.checks if c.confirming)
        finding.verification = (
            f"Validated live: `{ran.command}` ran successfully (exit 0); "
            "captured output attached as evidence."
        )
    elif validation.attempted:
        # A probe ran but did not return cleanly — note it without overclaiming.
        ran = next(c for c in validation.checks if c.ran)
        code = "timed out" if ran.exit_code is None else f"exit {ran.exit_code}"
        finding.verification = (
            f"Attempted validation: `{ran.command}` ({code}); see captured output."
        )


def validate_findings(
    findings: list[Finding],
    *,
    runner: Callable[..., Any] = subprocess.run,
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[PocValidation]:
    """Validate every finding that carries a PoC. Returns the validations run."""
    results: list[PocValidation] = []
    for finding in findings:
        validation = validate_finding(finding, runner=runner, timeout=timeout)
        if validation is not None:
            results.append(validation)
    return results
