# AI Security Twin — 3-Day Hackathon Plan

> Auto-generate a hands-on CTF challenge from a target repo: **scan → generate → sandbox → verify → score.**
> Judges reward one *working* end-to-end loop + a killer demo story. NOT breadth.

## The Winning Bet (scope decision)
Build **ONE vertical slice** perfectly: **Prompt Injection** (Threat #1).
- Scan a repo → find `user_input → LLM prompt` with no sanitization.
- Auto-generate a playable CTF: `challenge.md` + a runnable vulnerable app + `exploit.py`.
- Run it in Docker. An LLM "player" agent solves it automatically = **self-verification** (the wow moment).
- Show a human solving it, then patching, then re-running = "issue closed."

Everything else in the proposal (10 threats, web UI, multi-provider) is **stretch, not core.**
If the loop works on one threat, cloning to a 2nd (insecure code / hardcoded secret) is 1-2 hrs of templates — do that ONLY if Day 1+2 finish early.

## What makes it *win* (not just work)
1. **The self-verifying agent.** A GPT agent autonomously exploiting the generated challenge on stage is the memorable moment. Prioritize it.
2. **Speed on stage.** `twin scan ./demo-app` → challenge in <60s. Pre-warm/caches ready. Have a fallback recording.
3. **A clean narrative.** "We turn your real vulnerabilities into training your team can play." One sentence, one live demo.
4. **Real target.** Scan an actual public vulnerable LLM app (not a toy), so it's not obviously staged.

---

## Architecture (thin)
```
twin/
  scanner.py     # GPT call: repo -> JSON findings [{threat, file, line, snippet, why}]
  generator.py   # GPT call: finding -> {challenge.md, app files, exploit.py}
  sandbox.py     # write generated files, docker build+run, expose port
  verifier.py    # GPT agent: given running app + challenge, attempt exploit, capture flag
  cli.py         # `twin scan`, `twin gen`, `twin play`, `twin verify`  (Typer)
  llm.py         # thin OpenAI client wrapper (model, retries, JSON mode)
challenges/      # generated output goes here (gitignored)
fixtures/
  golden/        # HAND-BUILT reference challenge (built Day 1) = spec + test oracle
  demo-app/      # the vulnerable target repo we scan live
```
Backend: **OpenAI GPT** via the `openai` SDK ($100 credits). Use a strong model (e.g. `gpt-4o` / latest `gpt-4.1`/`gpt-5` available on the account) for generation + the verifier agent; a cheaper model (`gpt-4o-mini`) for the bulk scan pass to save credits. Use JSON mode / structured outputs for the scanner. Keep `llm.py` as the ONLY file that imports `openai`, so swapping models/providers later is one edit.

---

## Day-by-Day

### DAY 1 — Prove the output shape (build the target by hand)
Goal: a working CTF that YOU wrote by hand, plus scanner emitting findings.
- [ ] Repo scaffold: python package, `pyproject.toml`, `.env.example` (`OPENAI_API_KEY`), `.gitignore`.
- [ ] `fixtures/demo-app/` — small Flask app with a **real prompt-injection hole** (user input concatenated into an LLM system prompt that guards a secret "flag").
- [ ] `fixtures/golden/` — hand-write the ideal `challenge.md` + `exploit.py` + Dockerfile for that app. **This is your quality bar and your test oracle.**
- [ ] `llm.py` — OpenAI wrapper (load key, one `complete_json()` helper).
- [ ] `scanner.py` — feed repo files to GPT, get back JSON findings. Validate it finds the golden hole.
- [ ] `cli.py` — `twin scan <path>` prints findings table.
- **End of day: `twin scan fixtures/demo-app` correctly flags the injection.** ✅

### DAY 2 — Close the loop (generate + sandbox + verify)
Goal: generation produces a golden-quality challenge; agent solves it.
- [ ] `generator.py` — finding → challenge files. Few-shot prompt using the golden example as the template.
- [ ] `sandbox.py` — write files to `challenges/<id>/`, `docker build`, `docker run`, return URL. (Fallback: run locally with `python` + venv if Docker is flaky on Windows — test EARLY.)
- [ ] `verifier.py` — GPT agent loop: sees challenge + live endpoint, sends crafted prompts, extracts flag, reports pass/fail. This is the demo centerpiece.
- [ ] `twin gen <finding>` and `twin verify <id>` wired.
- **End of day: `scan → gen → verify` runs unattended and the agent captures the flag.** ✅

### DAY 3 — Make it demo-proof + polish
Goal: it never breaks on stage and looks great.
- [ ] `twin play <id>` — prints the challenge nicely, serves the app, shows the flag-check.
- [ ] Terminal polish: rich/colored output, progress spinners, a final "SOLVED ✓ — here's the fix" panel.
- [ ] Record a full backup demo video (in case wifi/API dies).
- [ ] Write the 90-second pitch + slides: problem → gap → live demo → "clone to any threat."
- [ ] STRETCH (only if ahead): 2nd threat template (hardcoded secret / SQLi), or a minimal web view.
- [ ] Dry-run the demo end-to-end 3x. Time it.

---

## Risks & pre-empts (Windows-specific)
- **Docker on Windows flaky/slow** → decide Day 2 morning: Docker Desktop vs. a local subprocess sandbox. Have the subprocess fallback coded.
- **API latency on stage** → cache the golden-path scan+gen result; `--demo` flag replays cached artifacts instantly if live call stalls.
- **LLM nondeterminism breaks the exploit** → pin the demo repo + seed prompts; the verifier retries 3x; keep the recorded fallback.
- **Time sink: perfect scanner** → don't. Scanner only needs to reliably find the ONE demo vuln class. Generalize later.

## Ethics / safety (say this in the pitch — judges like it)
- Only scans repos you own/authorize. Generated exploits run **only inside the sandbox**, carry a "training only" banner, use synthetic secrets/flags, never real data.

## First code task (when you say go)
Scaffold Day 1: package skeleton + `fixtures/demo-app` + `fixtures/golden` + `llm.py` + `scanner.py` + `cli.py scan`.
