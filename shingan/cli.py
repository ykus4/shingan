"""shingan CLI — scan IPA/APK files from the terminal / CI/CD."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import click
from rich import box
from rich.console import Console
from rich.table import Table

from shingan.core.analyzer import analyze
from shingan.core.constants import (
    DEFAULT_SERVE_HOST,
    DEFAULT_SERVE_PORT,
    HTTP_TIMEOUT,
)
from shingan.core.diff import DiffResult, compare
from shingan.core.models import SEVERITY_ORDER, ScanResult, Severity
from shingan.core.report import to_html, to_json, to_pdf, to_sarif, to_text
from shingan.core.storage import ScanStore
from shingan.core.version import get_version

console = Console(stderr=True)

#: Severity values accepted by --fail-on, most severe first.
_FAIL_ON_CHOICES = [s.value for s in SEVERITY_ORDER] + ["none"]

_DEFAULT_SERVER_URL = f"http://{DEFAULT_SERVE_HOST}:{DEFAULT_SERVE_PORT}"

# Exit codes
EXIT_FINDINGS = 1  # --fail-on threshold met
EXIT_ERROR = 2  # scan could not be completed


def get_store() -> ScanStore:
    """Open the scan store.

    Constructed on demand rather than at import time: instantiating it at module
    level created ``~/.shingan/shingan.db`` as a side effect of merely importing
    the CLI, which made the module impossible to import in tests without
    touching the user's home directory.
    """
    return ScanStore()


def _fail(message: str, code: int = EXIT_ERROR) -> NoReturn:
    console.print(f"[red]Error:[/red] {message}")
    sys.exit(code)


@click.group()
@click.version_option(version=get_version(), prog_name="shingan")
def cli() -> None:
    """shingan — iOS/Android 解析耐性チェッカー"""


@cli.command()
@click.argument(
    "artifact",
    # .app and .xcarchive inputs are directories, which ingest() accepts; the
    # previous dir_okay=False rejected them before analysis could start.
    type=click.Path(exists=True, dir_okay=True, file_okay=True, path_type=Path),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
    show_default=True,
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file path (stdout if omitted)",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(_FAIL_ON_CHOICES),
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
@click.option(
    "--lang",
    type=click.Choice(["en", "ja"]),
    default="en",
    show_default=True,
    help="Report language (HTML only)",
)
@click.option(
    "--rules-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Custom YAML rules directory (default: ~/.shingan/rules)",
)
@click.option(
    "--dynamic/--no-dynamic",
    default=False,
    help="Also run dynamic checks against a live device (requires frida + running app)",
)
@click.option(
    "--device",
    "device_udid",
    default=None,
    metavar="UDID",
    help="Target device UDID for dynamic analysis (default: first USB device)",
)
@click.option(
    "--dynamic-timeout",
    default=30,
    show_default=True,
    type=int,
    help="Per-check timeout for dynamic analysis (seconds)",
)
def scan(
    artifact: Path,
    fmt: str,
    out: Path | None,
    fail_on: str,
    save: bool,
    baseline: str | None,
    lang: str,
    rules_dir: Path | None,
    dynamic: bool,
    device_udid: str | None,
    dynamic_timeout: int,
) -> None:
    """Scan an IPA or APK file for reverse-engineering vulnerabilities."""
    console.print(f"[cyan]shingan[/cyan] scanning [bold]{artifact.name}[/bold] …")

    try:
        result = analyze(
            artifact,
            custom_rules_dir=rules_dir,
            dynamic=dynamic,
            device_udid=device_udid,
            dynamic_timeout=dynamic_timeout,
        )
    except (FileNotFoundError, ValueError, ImportError) as exc:
        _fail(str(exc))

    store = get_store()
    if save:
        db_path = store.save(result)
        console.print(f"[dim]Saved scan {result.scan_id[:8]} → {db_path}[/dim]")

    diff = _load_diff(store, baseline, result)
    output_text = _render(result, fmt, diff=diff, lang=lang)

    if out:
        out.write_text(output_text, encoding="utf-8")
        console.print(f"[dim]Report → {out}[/dim]")
    elif fmt != "text":
        click.echo(output_text)

    # Summary table always goes to stderr so it never pollutes piped output.
    if fmt == "text":
        _print_table(result)

    _apply_fail_gate(result, fail_on)


def _load_diff(
    store: ScanStore, baseline: str | None, result: ScanResult
) -> DiffResult | None:
    if not baseline:
        return None
    try:
        base_result = store.load(baseline)
    except FileNotFoundError:
        console.print(
            f"[yellow]Warning:[/yellow] baseline scan {baseline} not found, skipping diff"
        )
        return None
    diff = compare(base_result, result)
    console.print(
        f"[dim]Diff vs baseline {baseline[:8]}: "
        f"[green]+{len(diff.new)} new[/green]  "
        f"[red]-{len(diff.fixed)} fixed[/red]  "
        f"{len(diff.persisted)} persisted[/dim]"
    )
    return diff


def _apply_fail_gate(result: ScanResult, fail_on: str) -> None:
    if fail_on == "none":
        return
    threshold = Severity(fail_on)
    violations = [f for f in result.findings if f.severity.at_least(threshold)]
    if violations:
        console.print(
            f"\n[red]FAIL[/red] — {len(violations)} finding(s) at severity "
            f"[bold]{fail_on}[/bold] or above"
        )
        sys.exit(EXIT_FINDINGS)
    console.print(
        f"\n[green]PASS[/green] — no findings at severity [bold]{fail_on}[/bold] or above"
    )


@cli.command("list")
@click.option("--app-id", default=None, help="Filter by bundle ID")
def list_scans(app_id: str | None) -> None:
    """List stored scan results."""
    scans = get_store().list_scans(app_id=app_id)
    if not scans:
        console.print("[dim]No scans found.[/dim]")
        return
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Scan ID", style="dim", width=10)
    table.add_column("App ID")
    table.add_column("Version")
    table.add_column("C", style="bright_red", justify="right")
    table.add_column("H", style="red", justify="right")
    table.add_column("M", style="yellow", justify="right")
    table.add_column("L", style="green", justify="right")
    table.add_column("Scanned At", style="dim")
    for s in scans:
        summary = s.get("summary", {})
        table.add_row(
            (s.get("scan_id") or "")[:8],
            s.get("app_id", ""),
            f"{s.get('app_version', '')} ({s.get('build', '')})",
            str(summary.get(Severity.CRITICAL.value, 0)),
            str(summary.get(Severity.HIGH.value, 0)),
            str(summary.get(Severity.MEDIUM.value, 0)),
            str(summary.get(Severity.LOW.value, 0)),
            (s.get("scanned_at") or "")[:19].replace("T", " "),
        )
    console.print(table)


@cli.command()
@click.argument("scan_id")
@click.argument("baseline_id")
def diff(scan_id: str, baseline_id: str) -> None:
    """Show diff between two stored scans."""
    store = get_store()
    try:
        current = store.load(scan_id)
        baseline = store.load(baseline_id)
    except FileNotFoundError as exc:
        _fail(str(exc), EXIT_FINDINGS)

    result = compare(baseline, current)

    for label, style, findings in (
        ("NEW", "green bold", result.new),
        ("FIXED", "red bold", result.fixed),
    ):
        if not findings:
            continue
        console.print(f"\n[{style}]{label} ({len(findings)})[/{style}]")
        for f in sorted(findings, key=lambda x: x.severity.rank):
            console.print(f"  {_severity_tag(f.severity)}  {f.rule_id}  {f.title}")

    console.print(
        f"\n[dim]{len(result.persisted)} finding(s) persisted from baseline[/dim]"
    )


@cli.command()
@click.argument("scan_id")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif", "html", "pdf"]),
    default="json",
    show_default=True,
)
@click.option("--out", type=click.Path(path_type=Path), required=True)
@click.option(
    "--lang",
    type=click.Choice(["en", "ja"]),
    default="en",
    show_default=True,
    help="Report language (HTML/PDF only)",
)
def export(scan_id: str, fmt: str, out: Path, lang: str) -> None:
    """Export a stored scan result."""
    try:
        result = get_store().load(scan_id)
    except FileNotFoundError:
        _fail(f"Scan not found: {scan_id}", EXIT_FINDINGS)

    if fmt == "pdf":
        try:
            out.write_bytes(to_pdf(result, lang=lang))
        except RuntimeError as exc:
            _fail(str(exc), EXIT_FINDINGS)
    else:
        out.write_text(_render(result, fmt, lang=lang), encoding="utf-8")
    console.print(f"[dim]Exported → {out}[/dim]")


@cli.command("devices")
def list_devices_cmd() -> None:
    """List available devices and simulators for dynamic analysis."""
    from shingan.core.dynamic.device import list_devices

    # list_devices() already aggregates frida, xcrun and adb and is documented
    # never to raise, so the previous try/except + xcrun fallback here could
    # not trigger and duplicated work list_devices() already does.
    devices = list_devices()

    if not devices:
        console.print(
            "[dim]No devices found.[/dim]\n\n"
            "[bold]iOS:[/bold] Connect a device via USB or boot a simulator.\n"
            "[bold]Android:[/bold] Connect a device via USB or start an emulator, "
            "then push frida-server:\n"
            "  [dim]adb push frida-server /data/local/tmp/[/dim]\n"
            "  [dim]adb shell 'chmod 755 /data/local/tmp/frida-server && "
            "/data/local/tmp/frida-server &'[/dim]\n\n"
            "Frida must be installed: [cyan]pip install 'shingan[dynamic]'[/cyan]"
        )
        return

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Serial / UDID", style="dim", width=40)
    table.add_column("Name")
    table.add_column("Type", width=10)
    table.add_column("OS")
    for d in devices:
        table.add_row(d.udid, d.name, d.kind, d.os_version)
    console.print(table)


@cli.command()
@click.option(
    "--host",
    default=DEFAULT_SERVE_HOST,
    show_default=True,
    help="Bind address. Defaults to loopback because the API is unauthenticated "
    "unless SHINGAN_API_KEY is set.",
)
@click.option(
    "--port", default=DEFAULT_SERVE_PORT, show_default=True, type=int, help="Bind port"
)
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (dev)")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the web UI."""
    import uvicorn

    console.print(f"[cyan]shingan[/cyan] web UI → [bold]http://{host}:{port}[/bold]")
    uvicorn.run("shingan.web.main:app", host=host, port=port, reload=reload)


# ── Suppression commands ──────────────────────────────────────────────────────

_url_option = click.option(
    "--url",
    default=_DEFAULT_SERVER_URL,
    show_default=True,
    help="shingan server URL",
)


@cli.group()
def suppress() -> None:
    """Manage suppression rules (requires `shingan serve` to be running)."""


def _api_request(
    url: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
) -> object:
    """Call the shingan server API, exiting with a helpful message on failure.

    Shared by the three suppress subcommands, which each had their own copy of
    this request/error-handling block.
    """
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    # S310: the URL is the operator-supplied --url for their own shingan
    # server (loopback by default), not attacker-controlled input.
    request = urllib.request.Request(  # noqa: S310
        f"{url.rstrip('/')}{path}", data=data, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310
            body = resp.read()
    except urllib.error.HTTPError as exc:
        _fail(f"HTTP {exc.code}: {exc.read().decode(errors='replace')}", EXIT_FINDINGS)
    except urllib.error.URLError as exc:
        _fail(
            f"{exc.reason}\n[dim]Is `shingan serve` running at {url}?[/dim]",
            EXIT_FINDINGS,
        )
    return json.loads(body) if body else None


def _api_dict(url: str, path: str, **kwargs: object) -> dict:
    """API call that must return a JSON object."""
    data = _api_request(url, path, **kwargs)  # type: ignore[arg-type]
    if not isinstance(data, dict):
        _fail(
            f"Unexpected response from {path}: expected an object, got {type(data).__name__}"
        )
    return data


def _api_list(url: str, path: str, **kwargs: object) -> list:
    """API call that must return a JSON array."""
    data = _api_request(url, path, **kwargs)  # type: ignore[arg-type]
    if data is None:
        return []
    if not isinstance(data, list):
        _fail(
            f"Unexpected response from {path}: expected an array, got {type(data).__name__}"
        )
    return data


@suppress.command("add")
@click.argument("rule_id")
@click.option(
    "--evidence-prefix",
    default="",
    help="Narrow suppression to a specific evidence prefix",
)
@click.option("--reason", default="", help="Reason for suppression")
@_url_option
def suppress_add(rule_id: str, evidence_prefix: str, reason: str, url: str) -> None:
    """Add a suppression rule via the running web server."""
    data = _api_dict(
        url,
        "/api/suppressions",
        method="POST",
        payload={
            "rule_id": rule_id,
            "evidence_prefix": evidence_prefix,
            "reason": reason,
        },
    )
    console.print(f"[green]Suppression added:[/green] {data['rule_id']}")


@suppress.command("list")
@_url_option
def suppress_list(url: str) -> None:
    """List all active suppression rules."""
    items = _api_list(url, "/api/suppressions")
    if not items:
        console.print("[dim]No suppressions.[/dim]")
        return
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Rule ID")
    table.add_column("Evidence Prefix")
    table.add_column("Reason")
    for s in items:
        table.add_row(s["rule_id"], s.get("evidence_prefix", ""), s.get("reason", ""))
    console.print(table)


@suppress.command("remove")
@click.argument("rule_id")
@click.option("--evidence-prefix", default="", help="Evidence prefix to match")
@_url_option
def suppress_remove(rule_id: str, evidence_prefix: str, url: str) -> None:
    """Remove a suppression rule."""
    params = {"rule_id": rule_id}
    if evidence_prefix:
        params["evidence_prefix"] = evidence_prefix
    query = urllib.parse.urlencode(params)
    data = _api_dict(url, f"/api/suppressions?{query}", method="DELETE")
    console.print(f"[green]Removed:[/green] {data['removed']} suppression(s)")


# ── helpers ───────────────────────────────────────────────────────────────────


def _severity_tag(severity: Severity) -> str:
    """Rich-markup severity label, coloured from the single mapping in models."""
    return f"[{severity.color}]{severity.value.upper()}[/{severity.color}]"


def _render(
    result: ScanResult,
    fmt: str,
    diff: DiffResult | None = None,
    lang: str = "en",
) -> str:
    if fmt == "json":
        return to_json(result)
    if fmt == "sarif":
        return to_sarif(result)
    if fmt == "html":
        return to_html(
            result,
            diff_new=diff.new_fingerprints if diff else None,
            diff_fixed=diff.fixed_fingerprints if diff else None,
            lang=lang,
        )
    return to_text(result)


def _summary_cells(summary: dict) -> Iterator[str]:
    for severity in SEVERITY_ORDER:
        count = summary.get(severity.value, 0)
        if severity is Severity.INFO or count:
            yield f"[{severity.color}]{count} {severity.value}[/{severity.color}]"


def _print_table(result: ScanResult) -> None:
    summary = result.to_dict()["summary"]
    console.print(
        f"\n[bold]{result.artifact_name}[/bold]  "
        f"{result.app_id} {result.app_version} ({result.build})"
    )
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
    table.add_column("Severity", width=9)
    table.add_column("Rule ID", width=18)
    table.add_column("Title")
    for f in sorted(result.findings, key=lambda x: x.severity.rank):
        table.add_row(_severity_tag(f.severity), f.rule_id, f.title)
    console.print(table)
    console.print("  ".join(_summary_cells(summary)))
