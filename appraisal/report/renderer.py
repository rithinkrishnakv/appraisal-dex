"""
SKILL: Report Forge [DIVINE]
Renders the AppraisalResult into:
  1. Rich terminal output (Appraisal Cards)
  2. JSON machine-readable report
  3. Full HTML report with PoC artifacts
"""

import json
import os
import time
from pathlib import Path
from typing import Optional, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.syntax import Syntax
from rich import box

from appraisal.models import AppraisalResult, Finding, Rank

console = Console()

# ── Rank colour map for Rich ──────────────────────────────────────────────────
RANK_STYLES = {
    "F":   "dim white",
    "D":   "cyan",
    "C":   "green",
    "B":   "yellow",
    "A":   "orange1",
    "S":   "bold red",
    "SS":  "bold magenta",
    "SSS": "bold white on red",
}

RANK_ICONS = {
    "F":   "○",
    "D":   "◇",
    "C":   "◆",
    "B":   "▲",
    "A":   "★",
    "S":   "⚔",
    "SS":  "⚡",
    "SSS": "☠",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Terminal Output
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    console.print()
    console.print(Panel.fit(
        Text.from_markup(
            "[bold red]APPRAISAL: DEX[/bold red]\n"
            "[dim]Using My S-Rank Appraisal Skill to Expose Vulnerabilities in Android Binaries[/dim]\n"
            "[dim cyan]v1.0.0 — The binary thought its secrets were safe.[/dim cyan]"
        ),
        border_style="red",
        padding=(1, 4),
    ))
    console.print()


def print_target_info(result: AppraisalResult):
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key",   style="dim cyan", width=20)
    table.add_column("Value", style="white")

    table.add_row("Package",      result.package_name)
    table.add_row("App Name",     result.app_name)
    table.add_row("Version",      f"{result.version_name} (code: {result.version_code})")
    table.add_row("SDK",          f"min={result.min_sdk}  target={result.target_sdk}")
    table.add_row("Scan Time",    f"{result.scan_duration:.1f}s")
    table.add_row("Timestamp",    result.timestamp)
    table.add_row("Total Findings", str(len(result.findings)))

    console.print(Panel(table, title="[bold red]TARGET LOCKED[/bold red]", border_style="red"))
    console.print()


def print_summary_table(result: AppraisalResult):
    stats = result.stats
    highest = result.highest_rank

    table = Table(
        title="APPRAISAL SUMMARY",
        box=box.DOUBLE_EDGE,
        border_style="red",
        title_style="bold red",
        show_lines=True,
    )

    table.add_column("Rank",        style="bold",  width=8,  justify="center")
    table.add_column("Class",       width=14)
    table.add_column("Count",       width=8,  justify="center")
    table.add_column("Status",      width=30)

    rank_order = [Rank.SSS, Rank.SS, Rank.S, Rank.A, Rank.B, Rank.C, Rank.D, Rank.F]
    for rank in rank_order:
        count = stats.get(rank.label, 0)
        style = RANK_STYLES.get(rank.label, "white")
        icon  = RANK_ICONS.get(rank.label, "?")
        bar   = "█" * min(count, 20) if count > 0 else "·"
        table.add_row(
            f"[{style}]{icon} {rank.label}[/{style}]",
            f"[{style}]{rank.description}[/{style}]",
            f"[bold {style}]{count}[/bold {style}]" if count > 0 else "[dim]0[/dim]",
            f"[{style}]{bar}[/{style}]",
        )

    console.print(table)

    if highest:
        style = RANK_STYLES.get(highest.label, "white")
        icon  = RANK_ICONS.get(highest.label, "?")
        console.print()
        console.print(Panel.fit(
            Text.from_markup(
                f"[{style}]{icon} HIGHEST RANK: {highest.label} — {highest.description}[/{style}]"
            ),
            border_style=style.split()[-1] if "on" not in style else "red",
        ))
    console.print()


def print_finding(finding: Finding, index: int, total: int, show_poc: bool = True):
    rank   = finding.rank
    style  = RANK_STYLES.get(rank.label, "white")
    icon   = RANK_ICONS.get(rank.label, "?")

    # ── Header card ───────────────────────────────────────────────────────────
    header = Text()
    header.append(f"\n  {icon} [{rank.label}] ", style=f"bold {style.split()[0]}")
    header.append(finding.title + "\n", style="bold white")
    header.append(f"  ID: {finding.id}   ", style="dim")
    header.append(f"Category: {finding.category}   ", style="dim cyan")
    header.append(f"CVSS: {finding.cvss_score:.1f}  ", style=f"bold {style.split()[0]}")
    header.append(f"Vector: {finding.cvss.vector_string()}\n", style="dim")

    console.print(Panel(
        header,
        border_style=style.split()[0] if " " not in style else "red",
        padding=(0, 1),
    ))

    # ── Description ───────────────────────────────────────────────────────────
    console.print(f"  [bold cyan]Description[/bold cyan]")
    for line in finding.description.split("\n"):
        if line.strip():
            console.print(f"  {line.strip()}")
    console.print()

    # ── Technical Detail ──────────────────────────────────────────────────────
    if finding.technical_detail:
        console.print(f"  [bold cyan]Technical Detail[/bold cyan]")
        for line in finding.technical_detail.split("\n"):
            if line.strip():
                console.print(f"  [dim]{line.strip()}[/dim]")
        console.print()

    # ── Evidence ──────────────────────────────────────────────────────────────
    if finding.evidence:
        console.print(f"  [bold cyan]Evidence[/bold cyan]")
        for ev in finding.evidence[:5]:
            console.print(f"  [yellow]▸[/yellow] {ev}")
        console.print()

    # ── Affected Components ───────────────────────────────────────────────────
    if finding.affected_components:
        console.print(f"  [bold cyan]Affected[/bold cyan]")
        for comp in finding.affected_components[:5]:
            console.print(f"  [dim]→[/dim] {comp}")
        console.print()

    # ── Remediation ───────────────────────────────────────────────────────────
    if finding.remediation:
        console.print(f"  [bold green]Remediation[/bold green]")
        for line in finding.remediation.split("\n"):
            if line.strip():
                console.print(f"  [green]{line.strip()}[/green]")
        console.print()

    # ── PoCs ─────────────────────────────────────────────────────────────────
    if show_poc and finding.pocs:
        for poc in finding.pocs:
            lang = _poc_language(poc.type)
            console.print(f"  [bold red]PoC: {poc.title}[/bold red]")
            console.print(f"  [dim]{poc.description}[/dim]")
            if poc.code:
                syntax = Syntax(
                    poc.code[:2000],
                    lang,
                    theme="monokai",
                    line_numbers=False,
                    word_wrap=True,
                )
                console.print(Panel(syntax, border_style="red", padding=(0, 1)))
        console.print()

    console.print(Rule(style="dim"))


def _poc_language(poc_type: str) -> str:
    return {
        "adb_command":    "bash",
        "html_page":      "html",
        "frida_script":   "javascript",
        "curl_command":   "bash",
        "python_script":  "python",
    }.get(poc_type, "text")


def print_results(result: AppraisalResult, show_poc: bool = True, min_rank: str = "F"):
    """Print all findings to terminal in appraisal card format."""
    rank_order_map = {r.label: i for i, r in enumerate(
        [Rank.SSS, Rank.SS, Rank.S, Rank.A, Rank.B, Rank.C, Rank.D, Rank.F]
    )}
    min_idx = rank_order_map.get(min_rank.upper(), 7)

    filtered = [
        f for f in result.findings
        if rank_order_map.get(f.rank.label, 7) <= min_idx
    ]

    console.print()
    console.print(Rule("[bold red]APPRAISAL RESULTS[/bold red]", style="red"))
    console.print()

    if not filtered:
        console.print("  [dim]No findings at or above the specified rank threshold.[/dim]")
        return

    for i, finding in enumerate(filtered, 1):
        print_finding(finding, i, len(filtered), show_poc=show_poc)

    console.print()
    console.print(Rule("[bold red]END OF APPRAISAL[/bold red]", style="red"))
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
#  JSON Report
# ─────────────────────────────────────────────────────────────────────────────

def save_json_report(result: AppraisalResult, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.to_json(), encoding="utf-8")
    return str(path)


# ─────────────────────────────────────────────────────────────────────────────
#  HTML Report
# ─────────────────────────────────────────────────────────────────────────────

def save_html_report(result: AppraisalResult, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = _render_html(result)
    path.write_text(html, encoding="utf-8")
    return str(path)


def _render_html(result: AppraisalResult) -> str:
    findings_html = ""
    for f in result.findings:
        findings_html += _render_finding_card(f)

    stats = result.stats
    stat_badges = ""
    rank_order = [Rank.SSS, Rank.SS, Rank.S, Rank.A, Rank.B, Rank.C, Rank.D, Rank.F]
    for rank in rank_order:
        count = stats.get(rank.label, 0)
        if count > 0:
            stat_badges += f'<span class="badge rank-{rank.label}">{rank.label}: {count}</span>\n'

    highest = result.highest_rank
    highest_html = (
        f'<div class="highest-rank rank-{highest.label}">'
        f'{RANK_ICONS.get(highest.label, "?")} HIGHEST RANK: {highest.label} — {highest.description}'
        f'</div>'
    ) if highest else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Appraisal: DEX — {result.app_name}</title>
  <style>
    :root {{
      --bg:         #0d1117;
      --bg2:        #161b22;
      --bg3:        #21262d;
      --border:     #30363d;
      --text:       #c9d1d9;
      --text-dim:   #8b949e;
      --accent:     #e94560;
      --cyan:       #58a6ff;
      --green:      #3fb950;
      --yellow:     #d29922;
      --orange:     #f78166;
      --purple:     #bc8cff;
      --red:        #ff4444;
      --white:      #ffffff;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      font-size: 14px;
      line-height: 1.6;
    }}
    /* Header */
    .header {{
      background: linear-gradient(135deg, #0d1117 0%, #1a0a0a 50%, #0d1117 100%);
      border-bottom: 2px solid var(--accent);
      padding: 2rem 3rem;
      position: sticky; top: 0; z-index: 100;
    }}
    .header h1 {{ color: var(--accent); font-size: 2rem; letter-spacing: 0.1em; }}
    .header .subtitle {{ color: var(--text-dim); font-size: 0.9rem; margin-top: 0.25rem; }}
    /* Layout */
    .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem 3rem; }}
    /* Target Info */
    .target-card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-left: 4px solid var(--accent);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
    }}
    .target-field .label {{ color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; }}
    .target-field .value {{ color: var(--white); font-family: monospace; margin-top: 0.2rem; }}
    /* Summary */
    .summary {{ margin-bottom: 2rem; }}
    .summary h2 {{ color: var(--accent); margin-bottom: 1rem; font-size: 1.2rem; letter-spacing: 0.05em; }}
    .badges {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }}
    .badge {{
      padding: 0.4rem 1rem;
      border-radius: 20px;
      font-weight: bold;
      font-size: 0.85rem;
      font-family: monospace;
    }}
    .highest-rank {{
      padding: 1rem 1.5rem;
      border-radius: 8px;
      font-weight: bold;
      font-size: 1.1rem;
      margin-bottom: 1rem;
    }}
    /* Rank colours */
    .rank-F   {{ background: #2a2a2a; color: #808080; border: 1px solid #404040; }}
    .rank-D   {{ background: #0a2a3a; color: #58a6ff; border: 1px solid #1a4a6a; }}
    .rank-C   {{ background: #0a2a1a; color: #3fb950; border: 1px solid #1a4a2a; }}
    .rank-B   {{ background: #2a2500; color: #d29922; border: 1px solid #4a4500; }}
    .rank-A   {{ background: #2a1500; color: #f78166; border: 1px solid #5a3000; }}
    .rank-S   {{ background: #2a0a0a; color: #ff4444; border: 1px solid #6a1a1a; }}
    .rank-SS  {{ background: #2a002a; color: #bc8cff; border: 1px solid #5a005a; }}
    .rank-SSS {{ background: #3a0a0a; color: #ffffff; border: 2px solid #ff4444; box-shadow: 0 0 20px rgba(255,68,68,0.3); }}
    /* Finding Card */
    .finding-card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1.5rem;
      overflow: hidden;
    }}
    .finding-header {{
      padding: 1rem 1.5rem;
      display: flex;
      align-items: center;
      gap: 1rem;
      border-bottom: 1px solid var(--border);
    }}
    .rank-badge {{
      width: 50px; height: 50px;
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-weight: bold; font-size: 1.2rem;
      flex-shrink: 0;
    }}
    .finding-title {{ color: var(--white); font-weight: bold; font-size: 1rem; }}
    .finding-meta {{ color: var(--text-dim); font-size: 0.8rem; margin-top: 0.3rem; font-family: monospace; }}
    .finding-body {{ padding: 1.5rem; }}
    .section {{ margin-bottom: 1.2rem; }}
    .section-title {{
      color: var(--cyan);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 0.5rem;
      font-weight: bold;
    }}
    .section p {{ color: var(--text); line-height: 1.6; }}
    .evidence-item {{
      background: var(--bg3);
      border-left: 3px solid var(--yellow);
      padding: 0.4rem 0.8rem;
      margin: 0.3rem 0;
      font-family: monospace;
      font-size: 0.85rem;
      color: var(--yellow);
      border-radius: 0 4px 4px 0;
    }}
    .remediation {{
      background: #0a2a1a;
      border: 1px solid #1a4a2a;
      border-radius: 6px;
      padding: 1rem;
      color: var(--green);
      line-height: 1.6;
    }}
    /* PoC */
    .poc-card {{
      background: #0a0a0a;
      border: 1px solid #ff444440;
      border-radius: 6px;
      margin-top: 0.8rem;
      overflow: hidden;
    }}
    .poc-header {{
      background: #1a0a0a;
      padding: 0.6rem 1rem;
      color: var(--accent);
      font-weight: bold;
      font-size: 0.85rem;
      border-bottom: 1px solid #ff444430;
      display: flex; justify-content: space-between; align-items: center;
    }}
    .poc-type {{
      background: #2a0a0a;
      color: var(--text-dim);
      padding: 0.2rem 0.6rem;
      border-radius: 10px;
      font-size: 0.75rem;
      font-family: monospace;
    }}
    .poc-desc {{ padding: 0.6rem 1rem; color: var(--text-dim); font-size: 0.85rem; }}
    pre.poc-code {{
      padding: 1rem;
      overflow-x: auto;
      font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
      font-size: 0.82rem;
      line-height: 1.5;
      color: #a8ffd6;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .copy-btn {{
      background: var(--accent);
      border: none;
      color: white;
      padding: 0.2rem 0.8rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.75rem;
    }}
    .copy-btn:hover {{ background: #c93050; }}
    /* Tags */
    .tags {{ display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.8rem; }}
    .tag {{
      background: var(--bg3);
      color: var(--text-dim);
      padding: 0.2rem 0.6rem;
      border-radius: 10px;
      font-size: 0.75rem;
      font-family: monospace;
    }}
    /* CVSS score pill */
    .cvss-pill {{
      padding: 0.2rem 0.8rem;
      border-radius: 10px;
      font-weight: bold;
      font-family: monospace;
      font-size: 0.85rem;
    }}
    /* Collapsible */
    details {{ cursor: pointer; }}
    details summary {{ list-style: none; }}
    details summary::-webkit-details-marker {{ display: none; }}
    .toggle-btn {{
      background: var(--bg3);
      border: 1px solid var(--border);
      color: var(--text-dim);
      padding: 0.3rem 1rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.8rem;
      margin-top: 0.5rem;
    }}
    /* Scroll to top */
    .scroll-top {{
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      background: var(--accent);
      color: white;
      border: none;
      width: 44px; height: 44px;
      border-radius: 50%;
      cursor: pointer;
      font-size: 1.2rem;
      box-shadow: 0 4px 12px rgba(233,69,96,0.4);
    }}
    /* Filter bar */
    .filter-bar {{
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      margin-bottom: 1.5rem;
      align-items: center;
    }}
    .filter-btn {{
      padding: 0.4rem 1rem;
      border-radius: 20px;
      border: 1px solid var(--border);
      background: var(--bg2);
      color: var(--text-dim);
      cursor: pointer;
      font-size: 0.82rem;
    }}
    .filter-btn.active {{ border-color: var(--accent); color: var(--accent); }}
    .filter-label {{ color: var(--text-dim); font-size: 0.82rem; }}
    /* Chain highlight */
    .chain-card {{ border-color: #ff4444; box-shadow: 0 0 12px rgba(255,68,68,0.2); }}
  </style>
</head>
<body>
  <div class="header">
    <h1>⚔ APPRAISAL: DEX</h1>
    <div class="subtitle">Using My S-Rank Appraisal Skill to Expose Vulnerabilities in Android Binaries</div>
  </div>

  <div class="container">

    <!-- Target Info -->
    <div class="target-card">
      <div class="target-field">
        <div class="label">Package</div>
        <div class="value">{result.package_name}</div>
      </div>
      <div class="target-field">
        <div class="label">App Name</div>
        <div class="value">{result.app_name}</div>
      </div>
      <div class="target-field">
        <div class="label">Version</div>
        <div class="value">{result.version_name} ({result.version_code})</div>
      </div>
      <div class="target-field">
        <div class="label">SDK Range</div>
        <div class="value">min={result.min_sdk} / target={result.target_sdk}</div>
      </div>
      <div class="target-field">
        <div class="label">Findings</div>
        <div class="value">{len(result.findings)} total</div>
      </div>
      <div class="target-field">
        <div class="label">Scan Duration</div>
        <div class="value">{result.scan_duration:.1f}s</div>
      </div>
      <div class="target-field">
        <div class="label">Timestamp</div>
        <div class="value">{result.timestamp}</div>
      </div>
    </div>

    <!-- Summary -->
    <div class="summary">
      <h2>⊞ APPRAISAL SUMMARY</h2>
      <div class="badges">{stat_badges}</div>
      {highest_html}
    </div>

    <!-- Filter Bar -->
    <div class="filter-bar">
      <span class="filter-label">Filter:</span>
      <button class="filter-btn active" onclick="filterRank('ALL')">All</button>
      <button class="filter-btn" onclick="filterRank('SSS')">SSS</button>
      <button class="filter-btn" onclick="filterRank('SS')">SS</button>
      <button class="filter-btn" onclick="filterRank('S')">S</button>
      <button class="filter-btn" onclick="filterRank('A')">A</button>
      <button class="filter-btn" onclick="filterRank('B')">B</button>
      <button class="filter-btn" onclick="filterRank('C')">C</button>
      <button class="filter-btn" onclick="filterRank('D')">D</button>
      <button class="filter-btn" onclick="filterRank('CHAIN')">⚡ Chains</button>
    </div>

    <!-- Findings -->
    <div id="findings-container">
      {findings_html}
    </div>

  </div>

  <button class="scroll-top" onclick="window.scrollTo(0,0)" title="Back to top">↑</button>

  <script>
    function filterRank(rank) {{
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      document.querySelectorAll('.finding-card').forEach(card => {{
        if (rank === 'ALL') {{
          card.style.display = '';
        }} else if (rank === 'CHAIN') {{
          card.style.display = card.classList.contains('chain-card') ? '' : 'none';
        }} else {{
          card.style.display = card.dataset.rank === rank ? '' : 'none';
        }}
      }});
    }}

    function copyCode(btn) {{
      const pre = btn.closest('.poc-card').querySelector('pre');
      navigator.clipboard.writeText(pre.textContent).then(() => {{
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 1500);
      }});
    }}
  </script>
</body>
</html>"""


def _render_finding_card(f: Finding) -> str:
    rank     = f.rank
    style_cls = f"rank-{rank.label}"
    icon      = RANK_ICONS.get(rank.label, "?")
    is_chain  = "chain" in f.tags

    # Evidence
    evidence_html = "".join(
        f'<div class="evidence-item">{_esc(e)}</div>'
        for e in f.evidence[:5]
    )

    # Remediation
    rem_html = f'<div class="remediation">{_esc(f.remediation)}</div>' if f.remediation else ""

    # PoCs
    pocs_html = ""
    for poc in f.pocs:
        pocs_html += f"""
        <div class="poc-card">
          <div class="poc-header">
            <span>⚔ {_esc(poc.title)}</span>
            <span style="display:flex;gap:0.5rem;align-items:center;">
              <span class="poc-type">{poc.type}</span>
              <button class="copy-btn" onclick="copyCode(this)">Copy</button>
            </span>
          </div>
          <div class="poc-desc">{_esc(poc.description)}</div>
          <pre class="poc-code">{_esc(poc.code[:3000])}</pre>
        </div>"""

    # Tags
    tags_html = "".join(f'<span class="tag">{_esc(t)}</span>' for t in f.tags[:8])

    chain_cls = " chain-card" if is_chain else ""

    return f"""
    <div class="finding-card{chain_cls}" data-rank="{rank.label}" id="{f.id}">
      <div class="finding-header">
        <div class="rank-badge {style_cls}">{icon}<br><small>{rank.label}</small></div>
        <div style="flex:1;">
          <div class="finding-title">{_esc(f.title)}</div>
          <div class="finding-meta">
            {f.id} &nbsp;|&nbsp; {_esc(f.category)} &nbsp;|&nbsp;
            CVSS: <strong>{f.cvss_score:.1f}</strong> &nbsp;|&nbsp;
            <span style="font-size:0.75rem;color:var(--text-dim);">{f.cvss.vector_string()}</span>
          </div>
          <div class="tags">{tags_html}</div>
        </div>
      </div>
      <div class="finding-body">
        <div class="section">
          <div class="section-title">Description</div>
          <p>{_esc(f.description)}</p>
        </div>
        {"<div class='section'><div class='section-title'>Technical Detail</div><p style='font-family:monospace;font-size:0.85rem;white-space:pre-wrap;color:var(--text-dim);'>" + _esc(f.technical_detail) + "</p></div>" if f.technical_detail else ""}
        {"<div class='section'><div class='section-title'>Evidence</div>" + evidence_html + "</div>" if evidence_html else ""}
        {"<div class='section'><div class='section-title'>Affected Components</div>" + "".join(f'<div class="evidence-item" style="border-color:var(--cyan);color:var(--cyan);">{_esc(c)}</div>' for c in f.affected_components[:5]) + "</div>" if f.affected_components else ""}
        {"<div class='section'><div class='section-title'>Remediation</div>" + rem_html + "</div>" if rem_html else ""}
        {"<div class='section'><div class='section-title'>Proof of Concept</div>" + pocs_html + "</div>" if pocs_html else ""}
      </div>
    </div>"""


def _esc(text: str) -> str:
    """HTML-escape a string."""
    if not text:
        return ""
    return (
        str(text)
        .replace("&",  "&amp;")
        .replace("<",  "&lt;")
        .replace(">",  "&gt;")
        .replace('"',  "&quot;")
        .replace("\n", "<br>")
    )


# ─────────────────────────────────────────────────────────────────────────────
#  PoC File Exporter
# ─────────────────────────────────────────────────────────────────────────────

def export_pocs(result: AppraisalResult, output_dir: str) -> List[str]:
    """Export every PoC as a standalone file ready to run."""
    out = Path(output_dir) / "pocs"
    out.mkdir(parents=True, exist_ok=True)

    extensions = {
        "adb_command":   ".sh",
        "html_page":     ".html",
        "frida_script":  ".js",
        "curl_command":  ".sh",
        "python_script": ".py",
    }

    exported: List[str] = []
    for finding in result.findings:
        for i, poc in enumerate(finding.pocs):
            ext  = extensions.get(poc.type, ".txt")
            name = f"{finding.id}_{i+1}{ext}".replace("/", "_").replace(":", "_")
            fpath = out / name
            content = poc.code
            if ext == ".sh":
                content = "#!/bin/bash\n# Appraisal: DEX — " + poc.title + "\n\n" + content
            fpath.write_text(content, encoding="utf-8")
            if ext in (".sh", ".py"):
                os.chmod(str(fpath), 0o755)
            exported.append(str(fpath))

    return exported


def print_module_errors(errors):
    if not errors:
        return
    console.print()
    console.print(Rule("[yellow]MODULE WARNINGS[/yellow]", style="yellow"))
    for err in errors:
        console.print(f"  [yellow]⚠[/yellow] [{err.module_name}] {err.original}")
    console.print()
