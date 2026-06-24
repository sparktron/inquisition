"""Active testing engine — sends payloads via an external scanner (Nuclei or OWASP ZAP).

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
import tempfile
import time
from pathlib import Path
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

# Minimum recommended Nuclei version. Older versions may lack -jsonl or -disable-update-check.
_MIN_NUCLEI_VERSION: tuple[int, int, int] = (3, 0, 0)

# Warn when the local template library (.checksum mtime) is older than this.
_TEMPLATE_STALE_DAYS = 7

# Nuclei prints these prefixes on normal informational stderr lines — filter them out
# so only genuine errors surface in the report.
_NUCLEI_NOISY_STDERR = re.compile(
    r"^\[INF\]|^\[WRN\] Could not|^Templates|^nuclei -|^\[WRN\] Use",
    re.IGNORECASE,
)

# Mapping from common Nuclei template tags to MITRE ATT&CK technique IDs.
_TAG_TO_MITRE: dict[str, list[str]] = {
    "rce":              ["T1059", "T1190"],
    "sqli":             ["T1190", "T1059.003"],
    "xss":              ["T1059.007"],
    "lfi":              ["T1083"],
    "ssrf":             ["T1090.002"],
    "xxe":              ["T1190"],
    "ssti":             ["T1059"],
    "auth-bypass":      ["T1078"],
    "exposure":         ["T1552"],
    "misconfig":        ["T1190"],
    "default-login":    ["T1078.001"],
    "upload":           ["T1105"],
    "traversal":        ["T1083"],
    "path-traversal":   ["T1083"],
    "redirect":         ["T1090"],
    "injection":        ["T1190"],
    "cve":              ["T1190"],
    "log4j":            ["T1059", "T1190"],
    "deserialization":  ["T1059"],
    "fileread":         ["T1083"],
    "disclosure":       ["T1552"],
    "idor":             ["T1078"],
    "oast":             ["T1071"],
    "springboot":       ["T1190"],
}


def is_nuclei_available() -> bool:
    """Return True if the nuclei binary is on PATH."""
    return shutil.which("nuclei") is not None


def is_zap_available() -> bool:
    """Return True if the ZAP baseline script is on PATH."""
    return shutil.which("zap-baseline.py") is not None


def _nuclei_version(
    runner: Callable[..., Any] = subprocess.run,
) -> tuple[int, int, int] | None:
    """Return the installed Nuclei version as a (major, minor, patch) tuple, or None."""
    try:
        proc = runner(["nuclei", "-version"], capture_output=True, text=True, timeout=10)
        output = (getattr(proc, "stdout", "") or "") + (getattr(proc, "stderr", "") or "")
        m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", output)
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3))
    except Exception:
        pass
    return None


def _templates_stale() -> bool:
    """Return True if the local Nuclei template library is older than _TEMPLATE_STALE_DAYS."""
    for candidate in (
        Path.home() / ".local" / "nuclei-templates",
        Path.home() / "nuclei-templates",
    ):
        checksum = candidate / ".checksum"
        if checksum.exists():
            age_days = (time.time() - checksum.stat().st_mtime) / 86400
            return age_days > _TEMPLATE_STALE_DAYS
    return False  # templates dir not found — can't determine staleness, don't warn


def _mitre_from_tags(tags: list[Any]) -> list[str]:
    """Map Nuclei template tags to MITRE ATT&CK technique IDs (ordered, deduplicated)."""
    techniques: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        for t in _TAG_TO_MITRE.get(str(tag).lower(), []):
            if t not in seen:
                seen.add(t)
                techniques.append(t)
    return techniques


def _target_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def build_nuclei_command(
    target_url: str,
    *,
    timeout: float,
    auth_header: str = "",
    auth_cookie: str = "",
    rate_limit: float = 0.0,
    target_list_path: str = "",
) -> list[str]:
    """Construct the nuclei command line.

    When ``target_list_path`` is given (a file of newline-separated URLs), it is
    passed via ``-list`` instead of ``-u`` so the full discovered URL surface is
    covered.  ``rate_limit`` is the per-request delay in seconds (matching
    ScanConfig.rate_limit); it is converted to requests-per-second for Nuclei's
    ``-rl`` flag.  ``auth_cookie`` is injected as a ``Cookie:`` header alongside
    any ``auth_header``.
    """
    cmd = [
        "nuclei",
        "-jsonl",
        "-silent",
        "-severity", "low,medium,high,critical",
        "-exclude-tags", _EXCLUDED_TAGS,
        "-timeout", str(int(timeout)),
        "-disable-update-check",
    ]
    if target_list_path:
        cmd += ["-list", target_list_path]
    else:
        cmd += ["-u", target_url]
    if auth_header:
        cmd += ["-H", auth_header]
    if auth_cookie:
        cmd += ["-H", f"Cookie: {auth_cookie}"]
    if rate_limit > 0:
        rps = max(1, int(1.0 / rate_limit))
        cmd += ["-rl", str(rps)]
    return cmd


def parse_nuclei_output(stdout: str) -> list[Finding]:
    """Parse Nuclei JSONL output into Finding objects.

    Enriches each finding with:
    - CVE IDs and CVSS score from ``info.classification``
    - MITRE ATT&CK technique IDs derived from template tags
    - ``curl-command`` field as a ready-to-run PoC command
    - Attack scenario built from description + CVE context + matched URL

    Findings with the same title are deduplicated (same template matched on
    multiple URLs produces one finding — the first match wins).
    """
    findings: list[Finding] = []
    seen_titles: set[str] = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue

        info = item.get("info") or {}
        severity_str = str(info.get("severity", "info")).lower()
        severity = _NUCLEI_SEVERITY.get(severity_str, Severity.INFO)

        name = info.get("name") or item.get("template-id") or "active finding"
        template_id = item.get("template-id", "?")
        matched = item.get("matched-at") or item.get("host") or ""

        title = f"[active] {name}"
        if title in seen_titles:
            continue
        seen_titles.add(title)

        # --- Classification metadata ---
        classification = info.get("classification") or {}
        cve_ids: list[str] = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cve_ids = [c for c in cve_ids if isinstance(c, str)]

        cvss_score: float = 0.0
        raw_cvss = classification.get("cvss-score")
        if raw_cvss is not None:
            try:
                cvss_score = float(raw_cvss)
            except (TypeError, ValueError):
                pass

        # --- References ---
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        references = [r for r in references if isinstance(r, str)]

        # --- MITRE ATT&CK techniques from template tags ---
        tags: list[Any] = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        mitre = _mitre_from_tags(tags)

        # --- PoC command from Nuclei's curl-command field ---
        poc = str(item.get("curl-command", "")).strip()

        # --- Attack scenario ---
        description = str(info.get("description", "")).strip()
        scenario_parts: list[str] = []
        if description:
            scenario_parts.append(description)
        if cve_ids:
            scenario_parts.append(f"CVE reference: {', '.join(cve_ids)}")
        if cvss_score:
            scenario_parts.append(f"CVSS score: {cvss_score:.1f}")
        if matched:
            scenario_parts.append(f"Confirmed vulnerable endpoint: {matched}")
        attack_scenario = "\n".join(scenario_parts)

        # --- Evidence string (keep template-id and CVE IDs for test compatibility) ---
        evidence_parts = [f"Nuclei template '{template_id}' matched at {matched}"]
        if cve_ids:
            evidence_parts.append(f"CVE: {', '.join(cve_ids)}")
        if cvss_score:
            evidence_parts.append(f"CVSS: {cvss_score:.1f}")
        evidence = " | ".join(evidence_parts)

        findings.append(Finding(
            title=title,
            category=FindingCategory.VULNERABILITY,
            severity=severity,
            evidence=evidence,
            impact=description,
            remediation=(
                str(info.get("remediation", "")).strip()
                or "Review the matched Nuclei template and remediate the underlying issue."
            ),
            references=references,
            mitre_techniques=mitre,
            poc_command=poc,
            attack_scenario=attack_scenario,
        ))

    return findings


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

    # --- Version check (warn, don't abort) ---
    ver = _nuclei_version(runner)
    if ver is None:
        errors.append(
            "Could not determine Nuclei version — proceeding, but consider running "
            "'nuclei -version' to verify your installation"
        )
    elif ver < _MIN_NUCLEI_VERSION:
        errors.append(
            f"Nuclei {'.'.join(str(v) for v in ver)} is older than the recommended "
            f"{'.'.join(str(v) for v in _MIN_NUCLEI_VERSION)} — upgrade for best "
            "template coverage and flag compatibility"
        )

    # --- Template staleness check ---
    if _templates_stale():
        errors.append(
            f"Nuclei templates appear to be more than {_TEMPLATE_STALE_DAYS} days old — "
            "run 'nuclei -update-templates' to get the latest CVE coverage"
        )

    root_url = _target_url(config.target)

    # Build the full target list: root URL + crawler-discovered URLs.
    all_targets = [root_url] + [u for u in config.discovered_urls if u != root_url]

    tmp_path = ""
    try:
        if len(all_targets) > 1:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="inquisition-nuclei-"
            ) as fh:
                fh.write("\n".join(all_targets) + "\n")
                tmp_path = fh.name

        cmd = build_nuclei_command(
            root_url,
            timeout=config.timeout,
            auth_header=config.auth_header,
            auth_cookie=config.auth_cookie,
            rate_limit=config.rate_limit,
            target_list_path=tmp_path,
        )

        # Subprocess timeout: 30 s per target with a 5-minute floor.
        process_timeout = max(300.0, len(all_targets) * 30.0)

        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=process_timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            errors.append(f"Active scan failed to run: {exc}")
            return [], errors

        # Surface meaningful stderr lines (filter Nuclei's normal informational output).
        stderr = getattr(proc, "stderr", "") or ""
        if stderr.strip():
            meaningful = [
                ln for ln in stderr.splitlines()
                if ln.strip() and not _NUCLEI_NOISY_STDERR.match(ln.strip())
            ]
            if meaningful:
                errors.append(f"Nuclei stderr: {'; '.join(meaningful[:5])}")

        stdout = getattr(proc, "stdout", "") or ""
        return parse_nuclei_output(stdout), errors

    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass


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
