"""redcell CLI — `redcell ingest | stats | symbols | scan | gen | verify | play`."""

import typer
from rich.console import Console
from rich.table import Table

import json
from pathlib import Path

from redcell.ingest import Store, ingest as run_ingest
from redcell.scan import scan as run_scan
from redcell.generator import generate as run_generate

app = typer.Typer(help="Turn real vulnerabilities into playable CTF challenges.")
console = Console()

DEFAULT_DB = ".redcell/index.db"


@app.command()
def ingest(src: str, db: str = DEFAULT_DB):
    """Ingest a repo (local path or git URL) into a queryable index."""
    console.print(f"[bold]Ingesting[/bold] {src} -> {db}")
    report = run_ingest(src, db)

    table = Table(title="Ingestion report", show_header=False)
    for key, val in report.to_dict().items():
        if key == "errors":
            continue
        table.add_row(key, str(val))
    console.print(table)

    if report.errors:
        console.print(f"[yellow]{len(report.errors)} error(s); first few:[/yellow]")
        for e in report.errors[:5]:
            console.print(f"  - {e}")
    console.print(f"[green]Done in {report.elapsed_s}s[/green]")


@app.command()
def stats(db: str = DEFAULT_DB):
    """Show counts for an existing index."""
    store = Store(db)
    table = Table(title=f"Index stats ({db})", show_header=False)
    for key, val in store.stats().items():
        table.add_row(key, str(val))
    store.close()
    console.print(table)


@app.command()
def symbols(name: str, db: str = DEFAULT_DB):
    """Look up a symbol by name (and who calls it)."""
    store = Store(db)
    defs = store.find_symbol(name)
    callers = store.find_callers(name)
    store.close()

    console.print(f"[bold]Definitions of[/bold] {name}: {len(defs)}")
    for r in defs:
        console.print(f"  {r['kind']} {r['qualname']}{r['signature']}  "
                      f"[dim]{r['file_path']}:{r['start_line']}[/dim]")
    console.print(f"[bold]Callers of[/bold] {name}: {len(callers)}")
    for r in callers:
        console.print(f"  {r['caller']}  [dim]{r['file_path']}:{r['line']}[/dim]")


# --- later-stage stubs ---------------------------------------------------
@app.command()
def scan(src: str, db: str = DEFAULT_DB, out: str = "findings.json",
         no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM, use heuristic only")):
    """Scan a repo (local path or git URL) for vulnerabilities -> findings.json."""
    console.print(f"[bold]Scanning[/bold] {src}")
    report = run_scan(src, db_path=db, out_path=out, use_llm=not no_llm)

    summary = Table(title="Scan summary", show_header=False)
    for k in ("files_parsed", "candidates", "findings", "engine",
              "llm_calls", "cost_usd", "elapsed_s"):
        summary.add_row(k, str(getattr(report, k)))
    console.print(summary)

    if report.findings_list:
        console.print(f"\n[bold]Findings ({report.findings})[/bold]")
        for i, f in enumerate(report.findings_list, 1):
            flow = "cross-file" if f.cross_file else "same-file"
            console.print(
                f"\n[bold cyan]{i}.[/bold cyan] [bold]{f.threat}[/bold] "
                f"[dim](score {f.score:.2f}, {flow}, {f.confirmed_by})[/dim]"
            )
            console.print(f"   [bold]where:[/bold] {f.file}:{f.line}  ([dim]{f.sink_label}[/dim])")
            console.print(f"   [bold]source:[/bold] {f.source_kind} in {f.source_file}")
            if f.cross_file and f.path:
                console.print(f"   [bold]flow:[/bold]  {' <- '.join(f.path)}")
            console.print(f"   [bold]why:[/bold]   {f.why}")
    else:
        console.print("[yellow]No findings.[/yellow]")

    console.print(f"[green]Wrote {out} ({report.engine} engine, "
                  f"${report.cost_usd})[/green]")


@app.command()
def gen(findings: str = "findings.json", index: int = 0,
        out: str = "challenges", no_llm: bool = typer.Option(False, "--no-llm")):
    """Generate a playable CTF challenge from a finding in findings.json."""
    data = json.loads(Path(findings).read_text(encoding="utf-8"))
    items = data.get("findings", data) if isinstance(data, dict) else data
    if not items:
        console.print("[red]No findings to generate from.[/red]")
        raise typer.Exit(1)
    if index >= len(items):
        console.print(f"[red]index {index} out of range (have {len(items)}).[/red]")
        raise typer.Exit(1)

    finding = items[index]
    console.print(f"[bold]Generating challenge[/bold] from finding #{index}: "
                  f"{finding.get('threat')} @ {finding.get('file')}:{finding.get('line')}")
    ch = run_generate(finding, out_dir=out, use_llm=not no_llm)

    console.print(f"\n[green]Created challenge:[/green] {ch.directory}")
    console.print(f"  title:  {ch.story_title}")
    console.print(f"  threat: {ch.threat}")
    console.print(f"  flag:   {ch.flag}  [dim](synthetic)[/dim]")
    console.print("  files:  challenge.md, meta.json, app/main.py, exploit.py")
    console.print(f"\n[bold]Play it:[/bold]")
    console.print(f"  cd {ch.directory} && pip install -r app/requirements.txt && python app/main.py")
    console.print(f"  python {ch.directory}/exploit.py http://127.0.0.1:{ch.port}")


@app.command()
def verify(challenge_id: str):
    """Have the agent attempt to solve a challenge. (stub)"""
    typer.echo(f"[stub] verifying challenge {challenge_id}")


@app.command()
def play(challenge_id: str):
    """Launch a challenge for a human to solve. (stub)"""
    typer.echo(f"[stub] launching challenge {challenge_id}")


if __name__ == "__main__":
    app()
