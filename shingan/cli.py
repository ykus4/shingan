"""shingan CLI — scan IPA files from the terminal / CI/CD."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

from shingan.core.analyzer import analyze
from shingan.core.diff import compare
from shingan.core.models import Severity
from shingan.core.report import to_json, to_sarif, to_html
from shingan.core.storage import ScanStore

console = Console(stderr=True)
store = ScanStore()

SEVERITY_COLOR = {
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
}

SEVERITY_ORDER = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}


@click.group()
def cli():
    """shingan — iOS IPA 解析耐性チェッカー"""


@cli.command()
@click.argument("ipa", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
    show_default=True,
)
@click.option(
    "--out",
    type=click.Path(),
    default=None,
    help="Output file path (stdout if omitted)",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["high", "medium", "low", "none"]),
    default="none",
    show_default=True,
    help="Exit 1 if any finding at this severity or above",
)
@click.option(
    "--save/--no-save",
    default=True,
    show_default=True,
    help="Persist scan result to local store",
)
@click.option("--baseline", default=None, help="Scan ID to diff against")
def scan(
    ipa: str, fmt: str, out: str | None, fail_on: str, save: bool, baseline: str | None
):
    """Scan an IPA file for reverse-engineering vulnerabilities."""
    ipa_path = Path(ipa)
    console.print(f"[cyan]shingan[/cyan] scanning [bold]{ipa_path.name}[/bold] …")

    try:
        result = analyze(ipa_path)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(2)

    if save:
        saved_path = store.save(result)
        console.print(f"[dim]Saved → {saved_path}[/dim]")

    # Diff
    diff = None
    if baseline:
        try:
            base_result = store.load(baseline)
            diff = compare(base_result, result)
            console.print(
                f"[dim]Diff vs baseline {baseline[:8]}: "
                f"[green]+{len(diff.new)} new[/green]  "
                f"[red]-{len(diff.fixed)} fixed[/red]  "
                f"{len(diff.persisted)} persisted[/dim]"
            )
        except FileNotFoundError:
            console.print(
                f"[yellow]Warning:[/yellow] baseline scan {baseline} not found, skipping diff"
            )

    # Output
    output_text = _render(result, fmt, diff=diff)

    if out:
        Path(out).write_text(output_text, encoding="utf-8")
        console.print(f"[dim]Report → {out}[/dim]")
    elif fmt != "text":
        click.echo(output_text)

    # Summary table (always to stderr)
    if fmt == "text":
        _print_table(result)

    # Fail-on gate
    if fail_on != "none":
        threshold = Severity(fail_on)
        threshold_order = SEVERITY_ORDER[threshold]
        violations = [
            f for f in result.findings if SEVERITY_ORDER[f.severity] <= threshold_order
        ]
        if violations:
            console.print(
                f"\n[red]FAIL[/red] — {len(violations)} finding(s) at severity "
                f"[bold]{fail_on}[/bold] or above"
            )
            sys.exit(1)
        else:
            console.print(
                f"\n[green]PASS[/green] — no findings at severity [bold]{fail_on}[/bold] or above"
            )


@cli.command("list")
@click.option("--app-id", default=None, help="Filter by bundle ID")
def list_scans(app_id: str | None):
    """List stored scan results."""
    scans = store.list_scans(app_id=app_id)
    if not scans:
        console.print("[dim]No scans found.[/dim]")
        return
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Scan ID", style="dim", width=10)
    table.add_column("App ID")
    table.add_column("Version")
    table.add_column("H", style="red", justify="right")
    table.add_column("M", style="yellow", justify="right")
    table.add_column("L", style="green", justify="right")
    table.add_column("Scanned At", style="dim")
    for s in scans:
        summary = s.get("summary", {})
        table.add_row(
            s["scan_id"][:8],
            s.get("app_id", ""),
            f"{s.get('app_version', '')} ({s.get('build', '')})",
            str(summary.get("high", 0)),
            str(summary.get("medium", 0)),
            str(summary.get("low", 0)),
            (s.get("scanned_at") or "")[:19].replace("T", " "),
        )
    console.print(table)


@cli.command()
@click.argument("scan_id")
@click.argument("baseline_id")
def diff(scan_id: str, baseline_id: str):
    """Show diff between two stored scans."""
    try:
        current = store.load(scan_id)
        baseline = store.load(baseline_id)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    d = compare(baseline, current)

    if d.new:
        console.print(f"\n[green bold]NEW ({len(d.new)})[/green bold]")
        for f in d.new:
            console.print(
                f"  [{SEVERITY_COLOR[f.severity.value]}]{f.severity.value.upper()}[/{SEVERITY_COLOR[f.severity.value]}]  {f.rule_id}  {f.title}"
            )

    if d.fixed:
        console.print(f"\n[red bold]FIXED ({len(d.fixed)})[/red bold]")
        for f in d.fixed:
            console.print(
                f"  [{SEVERITY_COLOR[f.severity.value]}]{f.severity.value.upper()}[/{SEVERITY_COLOR[f.severity.value]}]  {f.rule_id}  {f.title}"
            )

    console.print(f"\n[dim]{len(d.persisted)} finding(s) persisted from baseline[/dim]")


@cli.command()
@click.argument("scan_id")
@click.option(
    "--format", "fmt", type=click.Choice(["json", "sarif", "html"]), default="json"
)
@click.option("--out", type=click.Path(), required=True)
def export(scan_id: str, fmt: str, out: str):
    """Export a stored scan result."""
    try:
        result = store.load(scan_id)
    except FileNotFoundError:
        console.print(f"[red]Scan not found:[/red] {scan_id}")
        sys.exit(1)
    text = _render(result, fmt)
    Path(out).write_text(text, encoding="utf-8")
    console.print(f"[dim]Exported → {out}[/dim]")


@cli.command()
def serve():
    """Start the web UI."""
    import uvicorn

    console.print("[cyan]shingan[/cyan] web UI → [bold]http://localhost:8000[/bold]")
    uvicorn.run("shingan.api.main:app", host="0.0.0.0", port=8000, reload=False)


# ── helpers ───────────────────────────────────────────────────────────────────


def _render(result, fmt: str, diff=None) -> str:
    if fmt == "json":
        return to_json(result)
    if fmt == "sarif":
        return to_sarif(result)
    if fmt == "html":
        return to_html(
            result,
            diff_new=diff.new_fingerprints if diff else None,
            diff_fixed=diff.fixed_fingerprints if diff else None,
        )
    return ""


def _print_table(result):
    summary = result.to_dict()["summary"]
    console.print(
        f"\n[bold]{result.ipa_name}[/bold]  "
        f"{result.app_id} {result.app_version} ({result.build})"
    )
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
    table.add_column("Severity", width=8)
    table.add_column("Rule ID", width=18)
    table.add_column("Title")
    for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER[x.severity]):
        color = SEVERITY_COLOR[f.severity.value]
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.rule_id,
            f.title,
        )
    console.print(table)
    console.print(
        f"[bold red]{summary['high']} high[/bold red]  "
        f"[bold yellow]{summary['medium']} medium[/bold yellow]  "
        f"[bold green]{summary['low']} low[/bold low]  "
        f"[cyan]{summary['info']} info[/cyan]"
    )
