"""Active testing engine — sends payloads via an external scanner (Nuclei).

This is the one part of Inquisition that crosses the read-only boundary: it can
send active probes/payloads. It is therefore **off by default** and only invoked
when the operator passes ``--active`` and clears the active-scan authorization
gate.

Inquisition does not implement payloads itself; it shells out to Nuclei
(https://github.com/projectdiscovery/nuclei), a widely used template engine,
and maps its findings into Inquisition ``Finding`` objects. Intrusive, DoS,
brute-force, and fuzzing templates are excluded so the active phase stays a
vulnerability check, not an attack.

The subprocess runner is injectable so parsing and command construction can be
unit-tested without invoking the real binary.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Callable

from models import Finding, FindingCategory, ScanConfig, Severity

_NUCLEI_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

# Excluded to keep the active phase a safe vulnerability check, not an attack.
_EXCLUDED_TAGS = "dos,intrusive,fuzz,brute-force"


def is_nuclei_available() -> bool:
    """Return True if the nuclei binary is on PATH."""
    return shutil.which("nuclei") is not None


def _target_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def build_nuclei_command(target_url: str, *, timeout: float, auth_header: str = "") -> list[str]:
    """Construct the nuclei command line for a single target."""
    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-silent",
        "-severity", "low,medium,high,critical",
        "-exclude-tags", _EXCLUDED_TAGS,
        "-timeout", str(int(timeout)),
        "-disable-update-check",
    ]
    if auth_header:
        cmd += ["-H", auth_header]
    return cmd


def parse_nuclei_output(stdout: str) -> list[Finding]:
    """Parse nuclei JSONL output into Finding objects."""
    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue

        info = item.get("info", {}) if isinstance(item, dict) else {}
        severity = _NUCLEI_SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        name = info.get("name") or item.get("template-id") or "active finding"
        template_id = item.get("template-id", "?")
        matched = item.get("matched-at") or item.get("host") or ""

        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        references = [r for r in references if isinstance(r, str)]

        findings.append(Finding(
            title=f"[active] {name}",
            category=FindingCategory.VULNERABILITY,
            severity=severity,
            evidence=f"Nuclei template '{template_id}' matched at {matched}",
            impact=str(info.get("description", "")),
            remediation=str(info.get("remediation", ""))
            or "Review the matched Nuclei template and remediate the underlying issue.",
            references=references,
        ))
    return findings


def run_active_scan(
    config: ScanConfig,
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> tuple[list[Finding], list[str]]:
    """Run the active engine against the target. Returns (findings, errors)."""
    errors: list[str] = []
    if not is_nuclei_available():
        errors.append(
            "Active scan requested but 'nuclei' was not found on PATH — skipping the "
            "active phase. Install it from https://github.com/projectdiscovery/nuclei"
        )
        return [], errors

    cmd = build_nuclei_command(
        _target_url(config.target),
        timeout=config.timeout,
        auth_header=config.auth_header,
    )
    try:
        proc = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(60.0, config.timeout * 30),
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        errors.append(f"Active scan failed to run: {exc}")
        return [], errors

    stdout = getattr(proc, "stdout", "") or ""
    return parse_nuclei_output(stdout), errors
