"""Optional LLM enrichment of the challenge narrative.

The vulnerable code always comes from the deterministic templates (reliable).
The LLM, if available, only rewrites the *story* so each challenge feels
tailored to the scanned repo. Falls back to the template default with no key.
"""

from __future__ import annotations

from ..llm import MODEL_STRONG, LLM

_PROMPT = """Write a short, fun CTF challenge briefing (2-4 sentences) for a training
exercise about a {threat} vulnerability. It was found in the file {file}.
Give it an engaging security-training tone. Respond as JSON:
{{"title": "a short catchy challenge name", "story": "the briefing text"}}"""


def enrich(threat: str, source_file: str, default_title: str,
           objective: str, llm: LLM | None) -> tuple[str, str]:
    """Return (title, story). Uses the LLM if given, else a sensible default."""
    default_story = (f"A {threat.replace('_', ' ')} vulnerability was discovered in "
                     f"`{source_file}`. {objective}")
    if llm is None:
        return default_title, default_story
    try:
        res = llm.complete_json(
            _PROMPT.format(threat=threat, file=source_file), model=MODEL_STRONG)
        title = str(res.get("title") or default_title)[:60]
        story = str(res.get("story") or default_story)
        return title, story
    except Exception:
        return default_title, default_story
