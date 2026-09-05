"""Host liveness and role classification.

Turns a per-host :class:`~models.ScanReport` into a compact :class:`HostProfile`
— is the host live, and what role does it most likely play on the network
(gateway/router, server, or endpoint/user device). This is deliberately a
best-effort *heuristic* built only from signals the scan already produced
(open ports, reverse-DNS names, WAF/proxy detection) plus, when available, the
scanning host's own default-gateway address. It performs no additional network
probes of its own.

The classifier is the substrate for the network-topology map: it labels each
node so a `/24` sweep can be read at a glance.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from models import FindingCategory

if TYPE_CHECKING:
    from models import ScanReport


class HostRole(str, enum.Enum):
    """The role a host most likely plays on the network."""

    GATEWAY = "gateway"      # router / gateway / network edge device
    SERVER = "server"        # runs server services (SSH, databases, web server)
    ENDPOINT = "endpoint"    # user device / workstation
    UNKNOWN = "unknown"      # live but no distinctive fingerprint, or not live


# Reverse-DNS names that strongly imply a routing / gateway device.
_GATEWAY_NAME_RE = re.compile(
    r"\b(gw|gateway|router|rtr|fw|firewall|edge|modem|unifi|openwrt|"
    r"pfsense|fritz|fios|ddwrt|dd-wrt|mikrotik|dsldevice)\d*\b",
    re.IGNORECASE,
)

# Ports that lean workstation / user device.
_WORKSTATION_PORTS = frozenset({135, 139, 445, 3389, 5900, 5357, 3283})
# Ports that lean server (remote admin, mail, databases).
_SERVER_SIGNAL_PORTS = frozenset(
    {22, 25, 110, 143, 587, 993, 995, 3306, 5432, 6379, 8086, 9200, 9300, 27017, 5984, 7474, 8161}
)
# Web-admin / HTTP ports — a gateway usually exposes one, but so does a server.
_WEB_ADMIN_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888})

_OPEN_PORT_RE = re.compile(r"^Open port:\s*(\d+)\b")


@dataclass
class HostProfile:
    """Liveness + role verdict for a single host, with the signals behind it."""

    target: str
    live: bool
    role: HostRole
    open_ports: list[int] = field(default_factory=list)
    hostname: str | None = None
    confidence: str = "n/a"        # high | medium | low | n/a
    signals: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "live": self.live,
            "role": self.role.value,
            "open_ports": list(self.open_ports),
            "hostname": self.hostname,
            "confidence": self.confidence,
            "signals": list(self.signals),
        }


# --- Signal extraction ------------------------------------------------------

def open_ports(report: "ScanReport") -> list[int]:
    """Open TCP ports parsed from the port-scan findings, ascending and unique."""
    ports: set[int] = set()
    for f in report.findings:
        if f.category is FindingCategory.PORT:
            m = _OPEN_PORT_RE.match(f.title)
            if m:
                ports.add(int(m.group(1)))
    return sorted(ports)


def reverse_dns_name(report: "ScanReport") -> str | None:
    """The first reverse-DNS (PTR) hostname observed, if any."""
    for f in report.findings:
        if f.category is FindingCategory.DNS and f.title == "Reverse DNS":
            # Evidence is formatted "<ip> -> <hostname>".
            _, sep, name = f.evidence.partition("->")
            if sep and name.strip():
                return name.strip()
    return None


def resolved_ips(report: "ScanReport") -> list[str]:
    """IP addresses the target resolved to (from the DNS A/AAAA finding)."""
    for f in report.findings:
        if f.category is FindingCategory.DNS and f.title == "DNS A/AAAA records":
            ips = f.metadata.get("resolved_ips")
            if isinstance(ips, list):
                return [str(ip) for ip in ips]
    return []


def is_live(report: "ScanReport") -> bool:
    """True when the host answered something.

    A host is live if it has at least one open port, or produced any TLS,
    HTTP-header, or tech-stack finding — those categories are only emitted after
    a successful connection. A firewalled host that never answers on a scanned
    port cannot be distinguished from a down host and is reported not live.
    """
    if open_ports(report):
        return True
    contact = {FindingCategory.TLS, FindingCategory.HTTP_HEADER, FindingCategory.TECH_STACK}
    return any(f.category in contact for f in report.findings)


def _has_reverse_proxy(report: "ScanReport") -> bool:
    for f in report.findings:
        if f.category is FindingCategory.APPLICATION and "detected:" in f.title:
            low = f.title.lower()
            if any(k in low for k in ("waf", "cdn", "proxy", "cloudflare", "akamai", "fastly")):
                return True
    return False


def _as_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_common_gateway_ip(target: str) -> bool:
    """True for the conventional gateway addresses (last octet 1 or 254)."""
    ip = _as_ip(target)
    if isinstance(ip, ipaddress.IPv4Address):
        return int(ip) & 0xFF in (1, 254)
    return False


def _matches_default_gateway(target: str, report: "ScanReport", default_gateway: str) -> bool:
    gw = _as_ip(default_gateway)
    if gw is None:
        return False
    direct = _as_ip(target)
    if direct is not None:
        return direct == gw
    # Hostname target: compare against the addresses it resolved to.
    return any(_as_ip(ip) == gw for ip in resolved_ips(report))


def _has_web_admin(ports: set[int]) -> bool:
    return bool(ports & _WEB_ADMIN_PORTS)


def _fmt_ports(ports: set[int]) -> str:
    return ", ".join(str(p) for p in sorted(ports))


# --- Classification ---------------------------------------------------------

def classify(
    report: "ScanReport", target: str | None = None, *, default_gateway: str | None = None
) -> HostProfile:
    """Classify one host's liveness and network role from its scan report.

    ``default_gateway`` (when the scanning host's routing table is known) makes
    the gateway verdict definitive for the matching address.
    """
    host = target if target is not None else report.target
    hostname = reverse_dns_name(report)
    ports = open_ports(report)
    port_set = set(ports)

    if not is_live(report):
        return HostProfile(
            target=host, live=False, role=HostRole.UNKNOWN, open_ports=ports,
            hostname=hostname, confidence="n/a",
            signals=["no response on scanned ports"],
        )

    signals: list[str] = []
    role = HostRole.UNKNOWN
    confidence = "low"

    if default_gateway and _matches_default_gateway(host, report, default_gateway):
        role, confidence = HostRole.GATEWAY, "high"
        signals.append(f"matches the scanning host's default gateway ({default_gateway})")
    elif hostname and _GATEWAY_NAME_RE.search(hostname):
        role, confidence = HostRole.GATEWAY, "high"
        signals.append(f"reverse-DNS name '{hostname}' looks like a gateway/router")
    elif _is_common_gateway_ip(host) and _has_web_admin(port_set):
        role, confidence = HostRole.GATEWAY, "medium"
        signals.append("conventional gateway address (.1/.254) exposing a web admin port")
    elif (port_set & _WORKSTATION_PORTS) and not (port_set & _SERVER_SIGNAL_PORTS):
        role, confidence = HostRole.ENDPOINT, "medium"
        signals.append(f"workstation services open ({_fmt_ports(port_set & _WORKSTATION_PORTS)})")
    elif port_set & _SERVER_SIGNAL_PORTS:
        role, confidence = HostRole.SERVER, "medium"
        signals.append(f"server services open ({_fmt_ports(port_set & _SERVER_SIGNAL_PORTS)})")
    elif _has_web_admin(port_set):
        role, confidence = HostRole.SERVER, "low"
        signals.append(f"serving HTTP/HTTPS ({_fmt_ports(port_set & _WEB_ADMIN_PORTS)})")
    else:
        signals.append("live but no distinctive service fingerprint")

    if role is not HostRole.GATEWAY and _has_reverse_proxy(report):
        signals.append("reverse-proxy / CDN signature present")

    return HostProfile(
        target=host, live=True, role=role, open_ports=ports,
        hostname=hostname, confidence=confidence, signals=signals,
    )


def classify_reports(
    reports: list["ScanReport"], *, default_gateway: str | None = None
) -> list[HostProfile]:
    """Classify a fleet of reports (order preserved)."""
    return [classify(r, default_gateway=default_gateway) for r in reports]


# --- Default-gateway detection (best-effort, read-only) ---------------------

def parse_default_gateway(route_output: str) -> str | None:
    """Extract the gateway IP from `ip route` output (``default via <ip> ...``)."""
    for line in route_output.splitlines():
        parts = line.split()
        if "via" in parts:
            idx = parts.index("via")
            if idx + 1 < len(parts) and _as_ip(parts[idx + 1]) is not None:
                return parts[idx + 1]
    return None


def detect_default_gateway() -> str | None:
    """The scanning host's default-gateway IP, or None if it can't be determined.

    Best-effort and read-only: runs `ip route show default` with fixed arguments
    (no shell) and returns None on any error or on a platform without `ip`.
    """
    import subprocess

    for cmd in (["ip", "-4", "route", "show", "default"], ["ip", "route", "show", "default"]):
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        gw = parse_default_gateway(proc.stdout)
        if gw:
            return gw
    return None
