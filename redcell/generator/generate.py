"""Generator orchestrator: Finding -> challenge folder on disk."""

from __future__ import annotations

import hashlib
import json
import secrets
import sys
from pathlib import Path

from ..llm import get_llm
from .models import Challenge
from .story import enrich
from .templates import build_for


def _new_flag() -> str:
    return "FLAG{" + secrets.token_hex(8) + "}"


def _challenge_id(finding: dict) -> str:
    threat = finding.get("threat", "vuln")
    seed = f"{finding.get('file','')}:{finding.get('line','')}"
    short = hashlib.sha1(seed.encode()).hexdigest()[:6]
    return f"{threat}_{short}"


def _render_challenge_md(ch: Challenge, spec: dict, story: str) -> str:
    hints = "\n".join(f"{i}. {h}" for i, h in enumerate(spec["hints"], 1))
    src = ch.source_finding
    src_line = (f"- Modelled on a real finding: `{src.get('file')}:{src.get('line')}` "
                f"({src.get('threat')})\n" if src else "")
    return f"""# {ch.story_title}

**Category:** {ch.threat.replace('_', ' ').title()}  |  **Difficulty:** intro

## Briefing
{story}

## Objective
{spec['objective']}

## How to run
```bash
cd {ch.id}
pip install -r app/requirements.txt
python app/main.py          # starts on http://127.0.0.1:{ch.port}
```

## Your goal
Capture the flag in the form `FLAG{{...}}`.

## Hints
{hints}

## Reference exploit
`exploit.py` contains a working solution:
```bash
python exploit.py http://127.0.0.1:{ch.port}
```

{src_line}> [!] Training only. Runs a deliberately vulnerable app with a synthetic flag
> in an isolated sandbox. Do not deploy.
"""


def generate(finding: dict, out_dir: str = "challenges", use_llm: bool = True) -> Challenge:
    """Turn one finding (dict from findings.json) into a challenge folder."""
    threat = finding.get("threat", "code_execution")
    spec = build_for(threat)
    flag = _new_flag()
    cid = _challenge_id(finding)
    directory = str(Path(out_dir) / cid)

    llm = get_llm() if use_llm else None
    title, story = enrich(threat, finding.get("file", "unknown"),
                          spec["title"], spec["objective"], llm)

    ch = Challenge(
        id=cid, threat=threat, flag=flag, directory=directory,
        port=spec["port"],
        start_cmd=[sys.executable, "app/main.py"],
        solve_check=spec["solve_check"],
        files=dict(spec["files"]),
        story_title=title,
        source_finding={k: finding.get(k) for k in ("file", "line", "threat", "why")},
    )

    # write files
    base = Path(directory)
    base.mkdir(parents=True, exist_ok=True)
    for rel, content in ch.files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    (base / "challenge.md").write_text(
        _render_challenge_md(ch, spec, story), encoding="utf-8")
    (base / "meta.json").write_text(
        json.dumps(ch.meta(), indent=2), encoding="utf-8")

    return ch
