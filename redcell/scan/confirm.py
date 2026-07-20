"""Stage 4 — confirm & explain a candidate.

With an LLM: send the connected code slices and ask if it's really exploitable.
Without an LLM: deterministic heuristic so the pipeline still completes offline.
"""

from __future__ import annotations

from pathlib import Path

from ..llm import LLM, MODEL_STRONG
from .candidates import Candidate

CONFIRM_THRESHOLD = 0.5

_PROMPT = """You are a security analyst. Below is a data-flow path where untrusted
input ({source_kind}) may reach a dangerous sink ({sink_label}) — potential {threat}.

Code along the path (sink first):
{slices}

Decide if this is genuinely exploitable. Respond as JSON:
{{"exploitable": true|false, "confidence": 0.0-1.0, "severity": "low|medium|high|critical",
  "why": "one or two sentences"}}"""


def _gather_slices(cand: Candidate, root: Path) -> str:
    from .candidates import _scope_source  # reuse reader
    from ..ingest.store import Store  # noqa: F401 (typing only)

    parts = []
    for hop in cand.path:
        try:
            text = (root / hop.file).read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        # trim very long files
        snippet = text if len(text) < 4000 else text[:4000]
        parts.append(f"# ===== {hop.func} @ {hop.file} =====\n{snippet}")
    return "\n\n".join(parts)


def confirm(cand: Candidate, root: str | Path, llm: LLM | None) -> dict:
    """Return {exploitable, confidence, why, confirmed_by}."""
    root = Path(root)

    def heuristic(reason: str) -> dict:
        # A candidate already has a concrete source-to-sink reachability path.
        conf = 0.8 if not cand.cross_file else 0.65
        return {
            "exploitable": True,
            "confidence": conf,
            "why": (f"Untrusted {cand.source_kind} input reaches {cand.sink_label} "
                    f"via {len(cand.path)} hop(s); no sanitization detected "
                    f"({reason})."),
            "confirmed_by": "heuristic" if llm is None else "heuristic_fallback",
        }

    if llm is None:
        return heuristic("heuristic, no LLM configured")

    prompt = _PROMPT.format(
        source_kind=cand.source_kind, sink_label=cand.sink_label,
        threat=cand.threat, slices=_gather_slices(cand, root),
    )
    try:
        res = llm.complete_json(prompt, model=MODEL_STRONG)
    except Exception:
        return heuristic("LLM confirmation unavailable; deterministic fallback")
    if not res:
        return heuristic("LLM returned no valid JSON; deterministic fallback")
    return {
        "exploitable": bool(res.get("exploitable", False)),
        "confidence": float(res.get("confidence", 0.0) or 0.0),
        "why": str(res.get("why", "")) or "(no explanation returned)",
        "confirmed_by": "llm",
    }
