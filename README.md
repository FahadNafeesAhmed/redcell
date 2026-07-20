# redcell 🔴

**Turn your real vulnerabilities into CTF challenges your team can play.**

🌐 **Landing page:** https://fahadnafeesahmed.github.io/redcell/ (served from [`docs/`](docs/index.html))

`redcell` scans a target repo for AI-specific security flaws (starting with prompt
injection), then auto-generates a hands-on CTF challenge — story, a runnable
vulnerable app, and a working exploit — runs it in a sandbox, and has an LLM agent
**autonomously solve it to prove the vuln is real.**

```
scan repo  →  find vuln  →  generate CTF  →  sandbox  →  agent solves it  →  score
```

> ⚠️ Training use only. Only scan repos you own or are authorized to test.
> Generated exploits run only inside the sandbox against synthetic secrets.

## Status
🚧 Early WIP — hackathon build. See [PLAN.md](PLAN.md) for the 3-day roadmap.

## Quickstart (planned)
```bash
pip install -e .
cp .env.example .env      # add your OPENAI_API_KEY
redcell scan ./fixtures/demo-app
redcell gen  <finding-id>
redcell verify <challenge-id>
```

## Layout
```
redcell/        # the package (scanner, generator, sandbox, verifier, cli, llm)
fixtures/       # demo-app (target we scan) + golden (hand-built reference challenge)
challenges/     # generated challenges land here (gitignored)
```

## Stack
Python · OpenAI GPT · Docker (sandbox) · Typer (CLI)

## License
MIT
