"""redcell CLI — `redcell ingest | stats | symbols | scan | gen | verify | play`."""

import typer
from rich.console import Console
from rich.table import Table

from redcell.ingest import Store, ingest as run_ingest

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
def scan(path: str):
    """Scan an ingested repo for vulnerabilities. (stub)"""
    typer.echo(f"[stub] scanning {path}")


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
