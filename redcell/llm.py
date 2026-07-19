"""Thin OpenAI wrapper — the ONLY file that imports `openai`.

Degrades gracefully: if there's no OPENAI_API_KEY (or the SDK isn't installed),
`get_llm()` returns None and callers fall back to a deterministic heuristic, so
the pipeline always completes offline.
"""

from __future__ import annotations

import json
import os

# Load .env if python-dotenv is available (optional).
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

MODEL_STRONG = os.getenv("REDCELL_MODEL_STRONG", "gpt-4o")
MODEL_CHEAP = os.getenv("REDCELL_MODEL_CHEAP", "gpt-4o-mini")

# Rough USD per 1M tokens, for the live cost meter (override as needed).
_PRICES = {
    "gpt-4o": (2.50, 10.0),
    "gpt-4o-mini": (0.15, 0.60),
}


class LLM:
    def __init__(self, client) -> None:
        self._client = client
        self.calls = 0
        self.cost_usd = 0.0

    def _account(self, model: str, usage) -> None:
        self.calls += 1
        pin, pout = _PRICES.get(model, (0.0, 0.0))
        try:
            self.cost_usd += (usage.prompt_tokens * pin + usage.completion_tokens * pout) / 1e6
        except Exception:
            pass

    def complete_json(self, prompt: str, *, model: str) -> dict:
        """Ask the model for a JSON object. Returns {} on parse failure."""
        resp = self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "Respond ONLY with a valid JSON object."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )
        self._account(model, getattr(resp, "usage", None))
        try:
            return json.loads(resp.choices[0].message.content)
        except Exception:
            return {}


def get_llm() -> LLM | None:
    """Return an LLM if a key + SDK are available, else None."""
    if not os.getenv("OPENAI_API_KEY"):
        return None
    try:
        from openai import OpenAI
    except Exception:
        return None
    try:
        return LLM(OpenAI())
    except Exception:
        return None
