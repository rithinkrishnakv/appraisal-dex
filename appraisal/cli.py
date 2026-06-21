#!/usr/bin/env python3
"""
APPRAISAL: DEX — CLI Entry Point
Clean progress UI. No debug noise. Real-time module status.
"""

# ── Silence ALL noisy loggers before any other import ─────────────────────────
import logging
import warnings
warnings.filterwarnings("ignore")

_SILENCE = [
    "androguard", "androguard.core", "androguard.core.analysis",
    "androguard.core.analysis.analysis", "androguard.core.apk",
    "androguard.core.dex", "androguard.core.axml", "androguard.misc",
    "pyaxmlparser", "asn1crypto", "oscrypto",
]
for _n in _SILENCE:
    _l = logging.getLogger(_n)
    _l.setLevel(logging.CRITICAL)
    _l.handlers = []
    _l.propagate = False

# Silence loguru (androguard uses it instead of stdlib logging)
try:
    from loguru import logger as _loguru_logger
    import sys as _sys
    _loguru_logger.remove()
    _loguru_logger.add(_sys.stderr, level="CRITICAL")
except Exception:
    pass

# Also silence root if nothing else catches it
logging.getLogger().setLevel(logging.WARNING)

import sys
import os
import time
import json
from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.columns import Columns
from rich import box

from appraisal import __version__
from appraisal.engine.orchestrator import Orchestrator, ALL_MODULES
from appraisal.report.renderer import (
    print_banner, print_target_info, print_summary_table,
    print_results, save_json_report, save_html_report,
    export_pocs, print_module_errors, console,
)

# ─────────────────────────────────────────────────────────────────────────────
#  Progress renderer
# ─────────────────────────────────────────────────────────────────────────────

def _make_progress_table(steps: List[dict]) -> Table:
    """Build a clean live progress table from the step list."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1),
                  show_edge=False, expand=False)
    table.add_column("icon",  width=3,  no_wrap=True)
    table.add_column("label", width=34, no_wrap=True)
    table.add_column("state", width=16, no_wrap=True)

    ICONS = {
        "pending": "[dim]○[/dim]",
        "running": "[bold yellow]◈[/bold yellow]",
        "ok":      "[bold green]✓[/bold green]",
        "skip":    "[dim]–[/dim]",
        "error":   "[bold red]✗[/bold red]",
    }
    STATE_STYLES = {
        "pending": "[dim]waiting[/dim]",
        "running": "[bold yellow]running...[/bold yellow]",
        "ok":      "",
        "skip":    "[dim]skipped[/dim]",
        "error":   "[bold red]error[/bold red]",
    }

    for step in steps:
        status   = step.get("status", "pending")
        name     = step.get("name", "")
        findings = step.get("findings", None)
        elapsed  = step.get("elapsed", None)
        skill    = step.get("skill", "")

        icon  = ICONS.get(status, "○")
        state = STATE_STYLES.get(status, "")

        if status == "ok" and findings is not None:
            count_style = "[bold red]" if findings > 0 else "[dim]"
            count_end   = "[/bold red]" if findings > 0 else "[/dim]"
            fin_str = f"{count_style}{findings} finding{'s' if findings != 1 else ''}  "
            fin_str += f"[dim]{elapsed:.1f}s[/dim]{count_end}" if elapsed else f"{count_end}"
            state = fin_str

        label = f"[dim cyan][{skill}][/dim cyan] {name}" if skill else name
        table.add_row(icon, label, state)

    return table


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(__version__, prog_name="appraisal-dex")
def cli():
    """
    \b
    ╔══════════════════════════════════════════════════════════╗
    ║  APPRAISAL: DEX — S-Rank Android Vulnerability Scanner  ║
    ╚══════════════════════════════════════════════════════════╝

    The binary thought its secrets were safe.
    """
    pass


@cli.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("-o", "--output",         default=None,   help="Output directory for reports")
@click.option("--json",  "emit_json",   is_flag=True,   help="Save JSON report")
@click.option("--html",  "emit_html",   is_flag=True,   help="Save HTML report")
@click.option("--pocs",  "emit_pocs",   is_flag=True,   help="Export all PoC files")
@click.option("--no-poc","no_poc",      is_flag=True,   help="Hide PoC code in terminal output")
@click.option("--min-rank",             default="F",    help="Minimum rank to display [F/D/C/B/A/S/SS/SSS]", show_default=True)
@click.option("--skip",                 multiple=True,  help="Skip a module by name (repeatable)")
@click.option("--debug", "debug_mode",  is_flag=True,   help="Show androguard debug output (very verbose)")
@click.option("--quiet", "-q",          is_flag=True,   help="Suppress terminal findings (output files only)")
@click.option("--no-banner",            is_flag=True,   help="Skip the banner")
def scan(
    apk_path:   str,
    output:     Optional[str],
    emit_json:  bool,
    emit_html:  bool,
    emit_pocs:  bool,
    no_poc:     bool,
    min_rank:   str,
    skip:       tuple,
    debug_mode: bool,
    quiet:      bool,
    no_banner:  bool,
):
    """
    Appraise an APK file and expose all vulnerabilities.

    \b
    Examples:
      appraisal-dex scan target.apk
      appraisal-dex scan target.apk --html --json --pocs -o ./report
      appraisal-dex scan target.apk --min-rank S --no-poc
      appraisal-dex scan target.apk --skip "Taint Walk"
    """
    # In debug mode, let androguard logs through
    if debug_mode:
        for _n in _SILENCE:
            logging.getLogger(_n).setLevel(logging.DEBUG)

    if not no_banner:
        print_banner()

    apk = Path(apk_path)
    if apk.suffix.lower() not in (".apk", ".xapk", ".apks"):
        console.print(f"[red]✗ Not an APK file: {apk_path}[/red]")
        sys.exit(1)

    # ── Determine output dir ──────────────────────────────────────────────────
    if output:
        out_dir = Path(output)
    else:
        safe_pkg = "scan_" + apk.stem[:30]
        out_dir  = Path("appraisal_output") / safe_pkg
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Build step list for live progress ─────────────────────────────────────
    skip_lower = [s.lower() for s in skip]
    steps = []
    steps.append({"name": "Ingesting binary & parsing DEX", "skill": "ENGINE",
                  "status": "running", "findings": None})
    for mod_cls in ALL_MODULES:
        m    = mod_cls()
        name = m.SKILL_NAME
        st   = "skip" if name.lower() in skip_lower else "pending"
        steps.append({"name": name, "skill": m.SKILL_TYPE.value,
                      "status": st, "findings": None})

    # ── Live progress display ─────────────────────────────────────────────────
    console.print(f"[bold red]▸[/bold red] Target: [cyan]{apk_path}[/cyan]")
    console.print(f"[dim]  Size: {apk.stat().st_size/1024/1024:.1f} MB  |  "
                  f"Modules: {len(ALL_MODULES)}  |  "
                  f"Output: {out_dir}[/dim]")
    console.print()

    orchestrator  = Orchestrator(verbose=debug_mode, skip_modules=list(skip))
    result        = None
    current_module = {"name": None}

    def on_status(msg: str):
        # Map status messages to step updates
        for step in steps:
            if step["name"] in msg or step["skill"] in msg:
                if "✓" in msg or "finding" in msg.lower():
                    step["status"] = "ok"
                    try:
                        # Extract finding count from "✓ Name — N finding(s) [Xs]"
                        parts = msg.split("—")
                        if len(parts) > 1:
                            num = int(parts[1].strip().split()[0])
                            step["findings"] = num
                    except Exception:
                        step["findings"] = 0
                    try:
                        elapsed_str = msg.split("[")[-1].rstrip("]").replace("s", "")
                        step["elapsed"] = float(elapsed_str)
                    except Exception:
                        pass
                elif "✗" in msg or "ERROR" in msg:
                    step["status"] = "error"
                elif "SKIP" in msg:
                    step["status"] = "skip"
                elif "..." in msg:
                    step["status"] = "running"

    orchestrator.set_status_callback(on_status)

    with Live(console=console, refresh_per_second=8, transient=False) as live:
        def update_live():
            # Ingest step is always first
            panel = Panel(
                _make_progress_table(steps),
                title="[bold red]APPRAISAL IN PROGRESS[/bold red]",
                border_style="red",
                padding=(0, 1),
            )
            live.update(panel)

        # Monkey-patch status callback to also refresh display
        _orig_cb = orchestrator._status_cb
        def live_status(msg: str):
            on_status(msg)
            # Mark ingest step done once we see "Target locked"
            if "Target locked" in msg:
                steps[0]["status"] = "ok"
                steps[0]["findings"] = None
                steps[0]["elapsed"] = None
            # Mark current module running
            for step in steps[1:]:
                if step["name"] in msg and "..." in msg:
                    step["status"] = "running"
            update_live()

        orchestrator.set_status_callback(live_status)
        update_live()

        try:
            result = orchestrator.run(apk_path)
        except FileNotFoundError as e:
            console.print(f"\n[red]✗ {e}[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"\n[red]✗ Fatal error: {e}[/red]")
            if debug_mode:
                import traceback
                traceback.print_exc()
            else:
                console.print("[dim]  Run with --debug for full traceback[/dim]")
            sys.exit(1)

        # Mark any still-pending as done (edge case)
        for step in steps:
            if step["status"] == "running":
                step["status"] = "ok"
        update_live()

    # ── Results ───────────────────────────────────────────────────────────────
    console.print()
    if not quiet:
        print_target_info(result)
        print_summary_table(result)
        print_module_errors(orchestrator.module_errors)
        print_results(result, show_poc=not no_poc, min_rank=min_rank)

    # ── File output ───────────────────────────────────────────────────────────
    saved_files = []
    if emit_json:
        p = save_json_report(result, str(out_dir / "report.json"))
        saved_files.append(("JSON Report", p))
    if emit_html:
        p = save_html_report(result, str(out_dir / "report.html"))
        saved_files.append(("HTML Report", p))
    if emit_pocs:
        for p in export_pocs(result, str(out_dir)):
            saved_files.append(("PoC", p))

    if saved_files:
        console.print()
        console.print("[bold green]Output saved:[/bold green]")
        for label, path in saved_files:
            console.print(f"  [green]✓[/green] {label}: [cyan]{path}[/cyan]")
        console.print()

    # ── Exit code ─────────────────────────────────────────────────────────────
    highest = result.highest_rank
    if highest and highest.label in ("SSS", "SS", "S", "A"):
        sys.exit(2)
    elif highest and highest.label in ("B", "C"):
        sys.exit(1)
    sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
#  diff command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("apk_v1", type=click.Path(exists=True))
@click.argument("apk_v2", type=click.Path(exists=True))
@click.option("--html", "emit_html", is_flag=True, help="Save HTML diff report")
@click.option("-o", "--output", default=None, help="Output directory")
def diff(apk_v1: str, apk_v2: str, emit_html: bool, output: Optional[str]):
    """Compare two APK versions — regression check for new vulnerabilities."""
    print_banner()
    console.print(f"[bold red]▸[/bold red] Diffing [cyan]{apk_v1}[/cyan] vs [cyan]{apk_v2}[/cyan]\n")

    orch1, orch2 = Orchestrator(), Orchestrator()
    with console.status("[bold red]Appraising v1...[/bold red]", spinner="dots"):
        r1 = orch1.run(apk_v1)
    with console.status("[bold red]Appraising v2...[/bold red]", spinner="dots"):
        r2 = orch2.run(apk_v2)

    ids1 = {f.id: f for f in r1.findings}
    ids2 = {f.id: f for f in r2.findings}

    new_findings   = [f for fid, f in ids2.items() if fid not in ids1]
    fixed_findings = [f for fid, f in ids1.items() if fid not in ids2]

    console.print(f"\n[bold red]◈ DIFF RESULTS[/bold red]")
    console.print(f"  [red]+{len(new_findings)} NEW vulnerabilities[/red] introduced in v2")
    console.print(f"  [green]-{len(fixed_findings)} vulnerabilities FIXED[/green] in v2")
    console.print(f"  [dim]{len(ids2) - len(new_findings)} findings unchanged[/dim]\n")

    if new_findings:
        console.print("[bold red]NEW FINDINGS:[/bold red]")
        for f in sorted(new_findings, key=lambda x: -x.cvss_score):
            console.print(f"  [{f.rank.label}] {f.title}  [dim]CVSS {f.cvss_score:.1f}[/dim]")

    if fixed_findings:
        console.print("\n[bold green]FIXED:[/bold green]")
        for f in fixed_findings:
            console.print(f"  [green]✓[/green] [{f.rank.label}] {f.title}")

    if output:
        out = Path(output)
        out.mkdir(parents=True, exist_ok=True)
        save_json_report(r1, str(out / "v1_report.json"))
        save_json_report(r2, str(out / "v2_report.json"))
        diff_data = {
            "v1": {"apk": apk_v1, "findings": len(r1.findings)},
            "v2": {"apk": apk_v2, "findings": len(r2.findings)},
            "new_findings":   [f.to_dict() for f in new_findings],
            "fixed_findings": [f.to_dict() for f in fixed_findings],
        }
        (out / "diff.json").write_text(json.dumps(diff_data, indent=2))
        console.print(f"\n[green]✓[/green] Diff saved to: [cyan]{output}[/cyan]")


# ─────────────────────────────────────────────────────────────────────────────
#  list-modules
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("list-modules")
def list_modules():
    """List all available skill modules."""
    print_banner()
    table = Table(
        title="AVAILABLE SKILL MODULES",
        box=box.DOUBLE_EDGE, border_style="red",
        title_style="bold red", show_lines=True,
    )
    table.add_column("Type",        style="bold cyan", width=10)
    table.add_column("Module",      style="bold white", width=30)
    table.add_column("Description", style="dim",        width=60)

    for mod_cls in ALL_MODULES:
        m = mod_cls()
        table.add_row(f"[{m.SKILL_TYPE.value}]", m.SKILL_NAME, m.DESCRIPTION)

    console.print(table)
    console.print(f"\n  [dim]Total: {len(ALL_MODULES)} modules[/dim]")
    console.print(f"  [dim]Skip with: --skip \"Module Name\"[/dim]\n")


# ─────────────────────────────────────────────────────────────────────────────
#  info command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("apk_path", type=click.Path(exists=True))
def info(apk_path: str):
    """Display APK metadata without running the full scan."""
    from appraisal.engine.loader import load_apk
    print_banner()
    with console.status("[bold red]Parsing APK...[/bold red]", spinner="dots"):
        ctx = load_apk(apk_path)

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key",   style="dim cyan", width=25)
    table.add_column("Value", style="white")

    rows = [
        ("Package Name",     ctx.package_name),
        ("App Name",         ctx.app_name),
        ("Version",          f"{ctx.version_name} (code: {ctx.version_code})"),
        ("SDK",              f"min={ctx.min_sdk}  target={ctx.target_sdk}"),
        ("SHA-256",          ctx.sha256[:32] + "..."),
        ("MD5",              ctx.md5),
        ("Size",             f"{ctx.size_bytes/1024/1024:.2f} MB"),
        ("Permissions",      str(len(ctx.permissions))),
        ("Components",       str(len(ctx.components))),
        ("Exported",         str(len([c for c in ctx.components if c.exported]))),
        ("Native Libs",      str(len(ctx.native_lib_names)) if ctx.has_native_libs else "None"),
        ("Files in APK",     str(len(ctx.file_list))),
        ("Has NSC",          "Yes" if ctx.has_network_security_config else "No"),
        ("App Classes",      f"{len(ctx.app_classes):,} (framework-stripped)"),
        ("String Pool",      f"{len(ctx.strings_pool):,} strings"),
    ]
    for k, v in rows:
        table.add_row(k, v)
    console.print(table)

    if ctx.permissions:
        console.print("\n[bold cyan]Permissions:[/bold cyan]")
        for p in sorted(ctx.permissions):
            console.print(f"  [dim]•[/dim] {p}")

    exported = [c for c in ctx.components if c.exported]
    if exported:
        console.print("\n[bold cyan]Exported Components:[/bold cyan]")
        for c in exported:
            perm = f" [dim]({c.permission})[/dim]" if c.permission else " [red](no permission)[/red]"
            console.print(f"  [dim]{c.component_type:10}[/dim] {c.name}{perm}")
    console.print()


def main():
    cli()


if __name__ == "__main__":
    main()
