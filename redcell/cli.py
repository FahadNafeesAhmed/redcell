"""redcell CLI — `redcell scan | gen | verify | play`."""

import typer

app = typer.Typer(help="Turn real vulnerabilities into playable CTF challenges.")


@app.command()
def scan(path: str):
    """Scan a repo for AI-specific vulnerabilities."""
    typer.echo(f"[stub] scanning {path}")


@app.command()
def gen(finding_id: str):
    """Generate a CTF challenge from a finding."""
    typer.echo(f"[stub] generating challenge for finding {finding_id}")


@app.command()
def verify(challenge_id: str):
    """Have the agent attempt to solve a challenge."""
    typer.echo(f"[stub] verifying challenge {challenge_id}")


@app.command()
def play(challenge_id: str):
    """Launch a challenge for a human to solve."""
    typer.echo(f"[stub] launching challenge {challenge_id}")


if __name__ == "__main__":
    app()
