# redcell

**Turn risky code paths into safe, playable security training challenges.**

Redcell is an offline-first developer-security prototype. It reads a Python
repository, finds paths from untrusted input to dangerous operations, generates
a self-contained CTF challenge, runs it on localhost, and verifies that the
synthetic vulnerability can be solved.

```text
repo -> ingest -> source-to-sink scan -> findings.json -> generate CTF
     -> localhost sandbox -> verify synthetic flag
```

> Training use only. Scan only repositories you own or are authorized to test.
> Generated challenges use synthetic `FLAG{...}` secrets and run locally.

## Why Redcell

Security reports are easy to ignore. Redcell turns a finding such as
`untrusted HTTP input -> LLM call` into a small, safe exercise that lets a team
see the risk and practice how to defend against it.

The scanner currently looks for source-to-sink paths involving:

- Prompt injection / risky LLM calls
- SQL injection
- Command injection
- Code execution
- Unsafe deserialization
- Server-side request forgery (SSRF)

## Quickstart

Requires Python 3.10 or later.

```powershell
git clone https://github.com/FahadNafeesAhmed/redcell.git
cd redcell
py -m pip install -e ".[dev]"
py -m redcell.cli demo tests/vuln_repo --no-llm
```

The demo is fully offline and should finish with:

```text
SOLVED  agent captured FLAG{...} == expected flag.
Vulnerability proven exploitable.
```

Run the automated tests:

```powershell
py -m pytest -q
```

## Commands

```powershell
# Index a local repository or a Git URL.
py -m redcell.cli ingest <repo-or-url>

# Inspect indexed symbols and their callers.
py -m redcell.cli symbols <function-name>

# Scan without remote-model calls.
py -m redcell.cli scan <repo-or-url> --no-llm

# Generate a challenge from the first finding.
py -m redcell.cli gen --no-llm

# Launch a generated challenge for a human player; stop with Ctrl+C.
py -m redcell.cli play challenges/<challenge-id>

# Launch and verify a generated challenge offline.
py -m redcell.cli verify challenges/<challenge-id> --no-llm
```

## Architecture

```text
1. INGEST
   Python AST -> functions, imports, calls -> SQLite call graph

2. SCAN
   untrusted source -> backward call-graph walk -> dangerous sink

3. GENERATE
   finding -> challenge.md + vulnerable Flask app + exploit.py + meta.json

4. SANDBOX
   generated app -> temporary localhost port + synthetic flag

5. VERIFY
   deterministic payloads -> exact-flag verdict
```

Stages exchange simple on-disk contracts: `findings.json` and each generated
challenge's `meta.json`. This makes the pipeline easy to test, inspect, and run
without a server or external API.

## Offline by default; optional LLM mode

Redcell is deliberately reliable without an API key. Its default mode uses
deterministic source-to-sink heuristics, fixed safe challenge templates, and
built-in verification payloads.

An optional OpenAI or Gemini-compatible model can add a second opinion during
candidate confirmation, write a richer challenge briefing, and attempt an
adaptive verification. Remote-model failures fall back to the deterministic
pipeline instead of stopping a training run.

To opt in, copy `.env.example` to `.env`, choose a provider, add its key, and
set a model name. Keep `.env` private; it is ignored by Git.

## Current scope and limitations

- Python parsing is implemented; JavaScript and TypeScript are future work.
- The analysis proves call-graph reachability, not full variable-level taint
  flow, so findings are candidates for human review.
- Generated challenges reproduce a vulnerability class with a synthetic flag;
  they never copy real application secrets.
- The sandbox is a local subprocess designed for a Windows-friendly demo, not
  production-grade container isolation.

## Project layout

```text
redcell/          package: ingest, scan, generator, sandbox, verifier, CLI
tests/            unit and end-to-end tests with a local vulnerable app
fixtures/         example inputs and reference material
challenges/       generated runtime output (ignored by Git)
docs/             GitHub Pages landing page
```

## Vision

Redcell can grow into an AI Agent Security Twin: a tool that maps untrusted
content, LLM context, tools, permissions, and outbound actions, then generates
safe regression tests before an agent is deployed with access to real systems.

## License

MIT
