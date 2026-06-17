"""Rich terminal UI for Inquisition."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich import box

if TYPE_CHECKING:
    pass


_THEME = Theme(
    {
        "banner.border": "cyan",
        "banner.title": "bold white",
        "status.info": "bold cyan",
        "status.ok": "bold green",
        "status.warn": "bold yellow",
        "status.err": "bold red",
        "module.name": "white",
        "finding.count": "dim white",
        "sev.critical": "bold white on red",
        "sev.high": "bold red",
        "sev.medium": "bold yellow",
        "sev.low": "bold blue",
        "sev.info": "dim",
        "sev.none": "bold green",
        "dim": "dim white",
        "label": "dim white",
        "value": "white",
    }
)

console = Console(theme=_THEME, highlight=False)


def make_progress() -> Progress:
    """Create a styled progress bar for module scanning."""
    return Progress(
        SpinnerColumn("dots", style="cyan"),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=28, style="dim cyan", complete_style="cyan", finished_style="green"),
        MofNCompleteColumn(),
        TextColumn("[dim]•"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def print_header(target: str, depth: str, fmt: str, dry_run: bool = False) -> None:
    """Print the scan header panel."""
    mode_style = "bold yellow" if dry_run else "bold green"
    mode_label = "DRY RUN" if dry_run else "LIVE"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="label", justify="right")
    grid.add_column(style="value")

    grid.add_row("target", Text(target, style="bold cyan"))
    grid.add_row("depth", Text(depth.upper(), style="bold white"))
    grid.add_row("format", Text(fmt.upper(), style="dim white"))
    grid.add_row("mode", Text(mode_label, style=mode_style))

    console.print()
    console.print(
        Panel(
            grid,
            title="[bold white] ⚡ Inquisition [/bold white]",
            subtitle="[dim]reconnaissance scan[/dim]",
            border_style="cyan",
            padding=(1, 3),
            box=box.ROUNDED,
        )
    )
    console.print()


def print_module_result(mod_name: str, finding_count: int, error_count: int) -> None:
    """Print a single completed module result."""
    if error_count > 0:
        icon = Text("  ⚠  ", style="status.warn")
    else:
        icon = Text("  ✓  ", style="status.ok")

    name = Text(f"{mod_name:<22}", style="module.name")

    n = finding_count
    findings_str = f"{n} finding" + ("s" if n != 1 else " ")
    findings = Text(findings_str, style="finding.count")

    line = Text.assemble(icon, name, findings)

    if error_count > 0:
        line.append(f"  ({error_count} error" + ("s" if error_count != 1 else "") + ")", style="status.warn")

    console.print(line)


def print_cve_phase(cpe_count: int) -> None:
    console.print()
    console.print(f"  [dim]correlating {cpe_count} CPE value" + ("s" if cpe_count != 1 else "") + " with NVD...[/dim]")


def print_cve_match(cpe: str, count: int) -> None:
    n = count
    console.print(
        f"  [status.err]![/status.err]  [dim]{cpe}[/dim]  "
        f"[status.err]{n} CVE" + ("" if n == 1 else "s") + "[/status.err]"
    )


def print_cve_error(cpe: str) -> None:
    console.print(f"  [status.err]✗[/status.err]  [dim]CVE lookup failed:[/dim] {cpe}")


def print_info(msg: str) -> None:
    console.print(f"  [dim]→[/dim]  [dim]{msg}[/dim]")


def print_summary(
    target: str,
    total: int,
    counts: dict[str, int],
    cve_count: int,
    misconfig_count: int,
    output_path: str,
) -> None:
    """Print the final summary panel."""
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)
    low = counts.get("low", 0)
    info = counts.get("info", 0)
    crit_high = crit + high

    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="label", justify="right")
    grid.add_column()

    # Severity breakdown inline
    sev_text = Text(str(total) + "  ")
    sev_breakdown = [
        (crit,   "crit", "sev.critical"),
        (high,   "high", "sev.high"),
        (medium, "med",  "sev.medium"),
        (low,    "low",  "sev.low"),
        (info,   "info", "sev.info"),
    ]
    for count, label, style in sev_breakdown:
        if count:
            sev_text.append(f"{count} {label}  ", style=style)

    cve_text = Text(str(cve_count) if cve_count else "none", style="sev.high" if cve_count else "sev.none")
    misc_text = Text(str(misconfig_count) if misconfig_count else "none", style="status.warn" if misconfig_count else "sev.none")
    report_text = Text(output_path, style="dim")

    grid.add_row("findings", sev_text)
    grid.add_row("CVEs", cve_text)
    grid.add_row("misconfigs", misc_text)
    grid.add_row("report", report_text)

    border = "red" if crit_high > 0 else "green"
    icon = "⚠" if crit_high > 0 else "✓"
    status = "Issues Found" if crit_high > 0 else "Scan Complete"

    console.print()
    console.print(
        Panel(
            grid,
            title=f"[bold white] {icon}  {status} [/bold white]",
            border_style=border,
            padding=(1, 3),
            box=box.ROUNDED,
        )
    )
    console.print()


def print_error(msg: str, hint: str = "") -> None:
    """Print an error with optional fix hint to stderr."""
    err_console = Console(stderr=True, theme=_THEME, highlight=False)
    err_console.print(f"\n  [status.err]✗[/status.err]  {msg}")
    if hint:
        err_console.print(f"     [dim]→ {hint}[/dim]")


def print_warning(msg: str) -> None:
    console.print(f"  [status.warn]⚠[/status.warn]  {msg}")


def print_interrupted() -> None:
    console.print("\n  [dim]scan interrupted[/dim]")


def print_fleet_summary(rows: list[dict[str, object]]) -> None:
    """Print a one-row-per-target overview at the end of a multi-target scan.

    Each row is {"target", "counts" (dict), "highest" (str|None), "report" (str)}.
    """
    table = Table(
        title="[bold white]Fleet Scan Summary[/bold white]",
        box=box.ROUNDED,
        border_style="cyan",
        padding=(0, 1),
        title_justify="left",
    )
    table.add_column("Target", style="bold")
    table.add_column("Highest", justify="center")
    table.add_column("C", justify="right", style="sev.critical")
    table.add_column("H", justify="right", style="sev.high")
    table.add_column("M", justify="right", style="sev.medium")
    table.add_column("L", justify="right", style="sev.low")
    table.add_column("Report", style="dim")

    _highest_style = {
        "critical": "sev.critical", "high": "sev.high", "medium": "sev.medium",
        "low": "sev.low", "info": "sev.info",
    }
    for row in rows:
        counts = row.get("counts", {}) or {}
        assert isinstance(counts, dict)
        highest = row.get("highest")
        highest_text = Text(str(highest) if highest else "—", style=_highest_style.get(str(highest), "sev.none"))

        def _cell(key: str) -> str:
            n = counts.get(key, 0)
            return str(n) if n else "·"

        table.add_row(
            str(row.get("target", "")),
            highest_text,
            _cell("critical"), _cell("high"), _cell("medium"), _cell("low"),
            str(row.get("report", "")),
        )

    console.print()
    console.print(table)
    console.print()
