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
import re
import shlex
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

_ZAP_SEVERITY: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

# Excluded to keep the active phase a safe vulnerability check, not an attack.
_EXCLUDED_TAGS = "dos,intrusive,fuzz,brute-force"


def is_nuclei_available() -> bool:
    """Return True if the nuclei binary is on PATH."""
    return shutil.which("nuclei") is not None


def is_zap_available() -> bool:
    """Return True if the ZAP baseline script is on PATH."""
    return shutil.which("zap-baseline.py") is not None


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


def build_zap_command(
    target_url: str,
    *,
    timeout: float,
    auth_header: str = "",
    auth_cookie: str = "",
) -> list[str]:
    """Construct the OWASP ZAP baseline command line for a single target."""
    minutes = max(1, int(timeout // 60) or 1)
    cmd = [
        "zap-baseline.py",
        "-t", target_url,
        "-J", "-",
        "-m", str(minutes),
        "-I",
    ]
    zap_config = _zap_replacer_config(auth_header=auth_header, auth_cookie=auth_cookie)
    if zap_config:
        cmd += ["-z", zap_config]
    return cmd


def _zap_replacer_config(*, auth_header: str, auth_cookie: str) -> str:
    headers: list[tuple[str, str]] = []
    if auth_header and ":" in auth_header:
        name, _, value = auth_header.partition(":")
        headers.append((name.strip(), value.strip()))
    if auth_cookie:
        headers.append(("Cookie", auth_cookie.strip()))

    parts: list[str] = []
    for index, (name, value) in enumerate(headers):
        prefix = f"replacer.full_list({index})"
        parts.extend([
            f"-config {prefix}.description=inquisition-{name.lower()}",
            f"-config {prefix}.enabled=true",
            f"-config {prefix}.matchtype=REQ_HEADER",
            f"-config {prefix}.matchstr={shlex.quote(name)}",
            f"-config {prefix}.regex=false",
            f"-config {prefix}.replacement={shlex.quote(value)}",
        ])
    return " ".join(parts)


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


def parse_zap_output(stdout: str) -> list[Finding]:
    """Parse OWASP ZAP baseline JSON output into Finding objects."""
    try:
        payload = json.loads(_extract_json_object(stdout))
    except ValueError:
        return []

    sites = payload.get("site", []) if isinstance(payload, dict) else []
    if isinstance(sites, dict):
        sites = [sites]

    findings: list[Finding] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if isinstance(alerts, dict):
            alerts = [alerts]
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            risk = _zap_risk(alert)
            if risk == Severity.INFO:
                continue
            name = str(alert.get("name") or alert.get("alert") or "ZAP alert")
            plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or "?")
            matched = _zap_first_instance_uri(alert)
            references = _zap_references(alert.get("reference", ""))
            findings.append(Finding(
                title=f"[active] {name}",
                category=FindingCategory.VULNERABILITY,
                severity=risk,
                evidence=f"ZAP alert '{plugin_id}' at {matched}",
                impact=_strip_markup(str(alert.get("desc", ""))),
                remediation=_strip_markup(str(alert.get("solution", "")))
                or "Review the matched ZAP alert and remediate the underlying issue.",
                references=references,
            ))
    return findings


def _extract_json_object(stdout: str) -> str:
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found")
    return stdout[start:end + 1]


def _zap_risk(alert: dict[str, Any]) -> Severity:
    risk = str(alert.get("riskdesc") or alert.get("risk") or "").split("(", 1)[0].strip().lower()
    if risk:
        return _ZAP_SEVERITY.get(risk, Severity.INFO)
    risk_code = str(alert.get("riskcode", "")).strip()
    return {
        "3": Severity.HIGH,
        "2": Severity.MEDIUM,
        "1": Severity.LOW,
        "0": Severity.INFO,
    }.get(risk_code, Severity.INFO)


def _zap_first_instance_uri(alert: dict[str, Any]) -> str:
    instances = alert.get("instances", [])
    if isinstance(instances, dict):
        instances = [instances]
    for instance in instances:
        if isinstance(instance, dict) and instance.get("uri"):
            return str(instance["uri"])
    return ""


def _zap_references(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    refs = re.split(r"<br\s*/?>|\n", value)
    return [ref.strip() for ref in refs if ref.strip().startswith(("http://", "https://"))]


def _strip_markup(value: str) -> str:
    return re.sub(r"<[^>]+>", " ", value).strip()


def run_active_scan(
    config: ScanConfig,
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> tuple[list[Finding], list[str]]:
    """Run the active engine against the target. Returns (findings, errors)."""
    errors: list[str] = []
    engine = config.active_engine.lower()
    if engine == "zap":
        return _run_zap_scan(config, runner=runner)
    if engine != "nuclei":
        errors.append(f"Unknown active scan engine '{config.active_engine}'")
        return [], errors

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


def _run_zap_scan(
    config: ScanConfig,
    *,
    runner: Callable[..., Any],
) -> tuple[list[Finding], list[str]]:
    errors: list[str] = []
    if not is_zap_available():
        errors.append(
            "Active scan requested with engine 'zap' but 'zap-baseline.py' was not "
            "found on PATH — skipping the active phase. Install OWASP ZAP or use "
            "--active-engine nuclei."
        )
        return [], errors

    cmd = build_zap_command(
        _target_url(config.target),
        timeout=config.timeout,
        auth_header=config.auth_header,
        auth_cookie=config.auth_cookie,
    )
    try:
        proc = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(120.0, config.timeout * 60),
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        errors.append(f"ZAP active scan failed to run: {exc}")
        return [], errors

    stdout = getattr(proc, "stdout", "") or ""
    return parse_zap_output(stdout), errors
