#!/usr/bin/env python3
"""
APPRAISAL: DEX
Using My S-Rank Appraisal Skill to Expose Vulnerabilities in Android Binaries

CLI Entry Point — every flag, every mode, every output format.
"""

import sys
import os
import time
from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

from appraisal import __version__
from appraisal.engine.orchestrator import Orchestrator, ALL_MODULES
from appraisal.report.renderer import (
    print_banner, print_target_info, print_summary_table,
    print_results, save_json_report, save_html_report,
    export_pocs, print_module_errors, console,
)

# ─────────────────────────────────────────────────────────────────────────────
#  CLI Definition
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


# ─────────────────────────────────────────────────────────────────────────────
#  scan command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("-o", "--output",         default=None,        help="Output directory for reports (default: ./appraisal_output/<pkg>)")
@click.option("--json",   "emit_json",  is_flag=True,        help="Save JSON report")
@click.option("--html",   "emit_html",  is_flag=True,        help="Save HTML report")
@click.option("--pocs",   "emit_pocs",  is_flag=True,        help="Export all PoC files")
@click.option("--no-poc", "no_poc",     is_flag=True,        help="Hide PoC code in terminal output")
@click.option("--min-rank",             default="F",         help="Minimum rank to display [F/D/C/B/A/S/SS/SSS]", show_default=True)
@click.option("--skip",                 multiple=True,       help="Skip a module by name (repeatable)")
@click.option("--verbose", "-v",        is_flag=True,        help="Show full error tracebacks")
@click.option("--quiet",   "-q",        is_flag=True,        help="Suppress terminal finding output (output files only)")
@click.option("--no-banner",            is_flag=True,        help="Skip the banner")
def scan(
    apk_path:   str,
    output:     Optional[str],
    emit_json:  bool,
    emit_html:  bool,
    emit_pocs:  bool,
    no_poc:     bool,
    min_rank:   str,
    skip:       tuple,
    verbose:    bool,
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
      appraisal-dex scan target.apk --skip "Taint Walk" --skip "Supply Chain Scanner"
    """
    if not no_banner:
        print_banner()

    # ── Validate APK ──────────────────────────────────────────────────────────
    apk = Path(apk_path)
    if not apk.suffix.lower() == ".apk":
        console.print(f"[red]✗ Not an APK file: {apk_path}[/red]")
        sys.exit(1)

    # ── Initialise orchestrator ───────────────────────────────────────────────
    orchestrator = Orchestrator(
        verbose=verbose,
        skip_modules=list(skip),
    )

    status_lines: List[str] = []

    def on_status(msg: str):
        status_lines.append(msg)
        if verbose:
            console.print(f"  [dim]{msg}[/dim]")

    orchestrator.set_status_callback(on_status)

    # ── Run scan ──────────────────────────────────────────────────────────────
    console.print(f"[bold red]▸[/bold red] Target: [cyan]{apk_path}[/cyan]")
    console.print()

    with console.status("[bold red]Initializing appraisal...[/bold red]", spinner="dots"):
        try:
            result = orchestrator.run(apk_path)
        except FileNotFoundError as e:
            console.print(f"[red]✗ {e}[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]✗ Fatal error during appraisal: {e}[/red]")
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # ── Determine output dir ──────────────────────────────────────────────────
    if output:
        out_dir = Path(output)
    else:
        safe_pkg = result.package_name.replace(".", "_")
        out_dir  = Path("appraisal_output") / safe_pkg
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Terminal output ───────────────────────────────────────────────────────
    if not quiet:
        print_target_info(result)
        print_summary_table(result)
        print_module_errors(orchestrator.module_errors)
        print_results(result, show_poc=not no_poc, min_rank=min_rank)

    # ── Module timing summary (verbose) ──────────────────────────────────────
    if verbose:
        console.print("\n[dim cyan]Module Timings:[/dim cyan]")
        for name, elapsed in sorted(orchestrator.module_timings.items(), key=lambda x: -x[1]):
            console.print(f"  [dim]{name}: {elapsed:.2f}s[/dim]")
        console.print()

    # ── File output ───────────────────────────────────────────────────────────
    saved_files = []

    if emit_json:
        json_path = save_json_report(result, str(out_dir / "report.json"))
        saved_files.append(("JSON Report", json_path))

    if emit_html:
        html_path = save_html_report(result, str(out_dir / "report.html"))
        saved_files.append(("HTML Report", html_path))

    if emit_pocs:
        exported = export_pocs(result, str(out_dir))
        for p in exported:
            saved_files.append(("PoC", p))

    # Always save JSON by default if any output requested
    if not emit_json and (emit_html or emit_pocs):
        json_path = save_json_report(result, str(out_dir / "report.json"))
        saved_files.append(("JSON Report", json_path))

    if saved_files:
        console.print()
        console.print(f"[bold green]Output saved:[/bold green]")
        for label, path in saved_files:
            console.print(f"  [green]✓[/green] {label}: [cyan]{path}[/cyan]")
        console.print()

    # ── Exit code based on highest rank ───────────────────────────────────────
    highest = result.highest_rank
    if highest and highest.label in ("SSS", "SS", "S", "A"):
        sys.exit(2)   # Critical/High findings
    elif highest and highest.label in ("B", "C"):
        sys.exit(1)   # Medium/Low findings
    else:
        sys.exit(0)   # Clean or informational only


# ─────────────────────────────────────────────────────────────────────────────
#  diff command — compare two APKs
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("apk_v1", type=click.Path(exists=True))
@click.argument("apk_v2", type=click.Path(exists=True))
@click.option("--html", "emit_html", is_flag=True, help="Save HTML diff report")
@click.option("-o", "--output", default=None, help="Output directory")
def diff(apk_v1: str, apk_v2: str, emit_html: bool, output: Optional[str]):
    """
    Compare two APK versions — regression check for new vulnerabilities.

    \b
    Examples:
      appraisal-dex diff app_v1.2.apk app_v1.3.apk
      appraisal-dex diff old.apk new.apk --html -o ./diff_report
    """
    print_banner()
    console.print(f"[bold red]▸[/bold red] Diffing: [cyan]{apk_v1}[/cyan] vs [cyan]{apk_v2}[/cyan]")
    console.print()

    orch1 = Orchestrator()
    orch2 = Orchestrator()

    with console.status("[bold red]Appraising v1...[/bold red]", spinner="dots"):
        result1 = orch1.run(apk_v1)

    with console.status("[bold red]Appraising v2...[/bold red]", spinner="dots"):
        result2 = orch2.run(apk_v2)

    # Compare findings
    ids1 = {f.id: f for f in result1.findings}
    ids2 = {f.id: f for f in result2.findings}

    new_findings    = [f for fid, f in ids2.items() if fid not in ids1]
    fixed_findings  = [f for fid, f in ids1.items() if fid not in ids2]
    common_findings = [f for fid, f in ids2.items() if fid in ids1]

    console.print(f"\n[bold red]◈ DIFF RESULTS[/bold red]")
    console.print(f"  [red]+{len(new_findings)} NEW vulnerabilities[/red] introduced in v2")
    console.print(f"  [green]-{len(fixed_findings)} vulnerabilities FIXED[/green] from v1")
    console.print(f"  [dim]{len(common_findings)} findings unchanged[/dim]\n")

    if new_findings:
        console.print("[bold red]NEW FINDINGS (introduced in v2):[/bold red]")
        for f in sorted(new_findings, key=lambda x: -x.cvss_score):
            rank  = f.rank
            icon  = "⚔" if rank.label in ("S","SS","SSS") else "▲"
            console.print(f"  [{rank.label}] {icon} {f.title} (CVSS: {f.cvss_score:.1f})")

    if fixed_findings:
        console.print("\n[bold green]FIXED FINDINGS (resolved in v2):[/bold green]")
        for f in fixed_findings:
            console.print(f"  [green]✓[/green] [{f.rank.label}] {f.title}")

    if output:
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)
        # Save both reports
        save_json_report(result1, str(out_dir / "v1_report.json"))
        save_json_report(result2, str(out_dir / "v2_report.json"))

        # Save diff summary
        diff_data = {
            "v1": {"apk": apk_v1, "findings": len(result1.findings)},
            "v2": {"apk": apk_v2, "findings": len(result2.findings)},
            "new_findings":   [f.to_dict() for f in new_findings],
            "fixed_findings": [f.to_dict() for f in fixed_findings],
        }
        import json
        (out_dir / "diff.json").write_text(json.dumps(diff_data, indent=2))
        console.print(f"\n[green]✓[/green] Diff saved to: [cyan]{out_dir}[/cyan]")


# ─────────────────────────────────────────────────────────────────────────────
#  list-modules command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("list-modules")
def list_modules():
    """List all available skill modules."""
    print_banner()
    from rich.table import Table
    from rich import box

    table = Table(
        title="AVAILABLE SKILL MODULES",
        box=box.DOUBLE_EDGE,
        border_style="red",
        title_style="bold red",
        show_lines=True,
    )
    table.add_column("Skill Type", style="bold cyan", width=12)
    table.add_column("Module Name", style="bold white", width=30)
    table.add_column("Description", style="dim", width=60)

    for module_cls in ALL_MODULES:
        m = module_cls()
        table.add_row(
            f"[{m.SKILL_TYPE.value}]",
            m.SKILL_NAME,
            m.DESCRIPTION,
        )

    console.print(table)
    console.print()
    console.print(f"  [dim]Total modules: {len(ALL_MODULES)}[/dim]")
    console.print(f"  [dim]Use --skip \"Module Name\" to exclude any module from a scan.[/dim]")
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
#  info command — APK metadata without full scan
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("apk_path", type=click.Path(exists=True))
def info(apk_path: str):
    """
    Display APK metadata without running the full scan.

    \b
    Examples:
      appraisal-dex info target.apk
    """
    from appraisal.engine.loader import load_apk
    from rich.table import Table
    from rich import box

    print_banner()

    with console.status("[bold red]Parsing APK...[/bold red]", spinner="dots"):
        ctx = load_apk(apk_path)

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key",   style="dim cyan", width=25)
    table.add_column("Value", style="white")

    table.add_row("Package Name",     ctx.package_name)
    table.add_row("App Name",         ctx.app_name)
    table.add_row("Version Name",     ctx.version_name)
    table.add_row("Version Code",     ctx.version_code)
    table.add_row("Min SDK",          str(ctx.min_sdk))
    table.add_row("Target SDK",       str(ctx.target_sdk))
    table.add_row("SHA-256",          ctx.sha256)
    table.add_row("MD5",              ctx.md5)
    table.add_row("File Size",        f"{ctx.size_bytes:,} bytes ({ctx.size_bytes/1024/1024:.2f} MB)")
    table.add_row("Permissions",      str(len(ctx.permissions)))
    table.add_row("Components",       str(len(ctx.components)))
    exported = [c for c in ctx.components if c.exported]
    table.add_row("Exported Comps",   str(len(exported)))
    table.add_row("Native Libs",      str(len(ctx.native_lib_names)) if ctx.has_native_libs else "None")
    table.add_row("Files in APK",     str(len(ctx.file_list)))
    table.add_row("Has NSC",          "Yes" if ctx.has_network_security_config else "No")
    table.add_row("String Pool Size", f"{len(ctx.strings_pool):,} strings")

    console.print(table)

    if ctx.permissions:
        console.print("\n[bold cyan]Permissions:[/bold cyan]")
        for p in sorted(ctx.permissions):
            console.print(f"  [dim]•[/dim] {p}")

    if exported:
        console.print("\n[bold cyan]Exported Components:[/bold cyan]")
        for c in exported:
            perm = f" [dim](perm: {c.permission})[/dim]" if c.permission else " [red](no permission)[/red]"
            console.print(f"  [dim]{c.component_type:10}[/dim] {c.name}{perm}")
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    cli()


if __name__ == "__main__":
    main()
