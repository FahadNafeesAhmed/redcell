"""redcell CLI — `redcell ingest | stats | symbols | scan | gen | verify | play`."""

import typer
from rich.console import Console
from rich.table import Table

from redcell.ingest import Store, ingest as run_ingest
from redcell.scan import scan as run_scan

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
        t = Table(title=f"Findings ({report.findings})")
        t.add_column("score", justify="right")
        t.add_column("threat")
        t.add_column("location")
        t.add_column("flow")
        t.add_column("why", overflow="fold", max_width=44)
        for f in report.findings_list:
            flow = "cross-file" if f.cross_file else "same-file"
            t.add_row(f"{f.score:.2f}", f.threat, f"{f.file}:{f.line}", flow, f.why)
        console.print(t)
    else:
        console.print("[yellow]No findings.[/yellow]")

    console.print(f"[green]Wrote {out} ({report.engine} engine, "
                  f"${report.cost_usd})[/green]")


@app.command()
def gen(finding_id: str):
    """Generate a CTF challenge from a finding. (stub)"""
    typer.echo(f"[stub] generating challenge for finding {finding_id}")


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
