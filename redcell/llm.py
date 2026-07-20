"""Optional LLM provider adapter.

The core Redcell pipeline is offline-first. If no supported provider is
configured, ``get_llm()`` returns ``None`` and callers use deterministic
heuristics and payloads instead. The OpenAI SDK is the only external SDK used
here; Gemini is supported through its OpenAI-compatible endpoint.
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

# These defaults are used only when a provider key is deliberately configured.
MODEL_STRONG = os.getenv("REDCELL_MODEL_STRONG", "gpt-5.3-codex")
MODEL_CHEAP = os.getenv("REDCELL_MODEL_CHEAP", "gpt-5.6-luna")
GEMINI_OPENAI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"

# Rough USD per 1M tokens, for the live cost meter (override as needed).
_PRICES = {
    "gpt-5.3-codex": (1.75, 14.0),
    "gpt-5.6-luna": (1.0, 6.0),
    "gemini-2.5-flash-lite": (0.10, 0.40),
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

    def chat(self, messages: list, *, model: str, tools: list | None = None):
        """Raw multi-turn chat with optional tool-use. Returns the message object."""
        kwargs = {"model": model, "messages": messages, "temperature": 0}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        resp = self._client.chat.completions.create(**kwargs)
        self._account(model, getattr(resp, "usage", None))
        return resp.choices[0].message

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
    """Return the configured LLM provider, or None for offline mode.

    Set REDCELL_LLM_PROVIDER to ``openai`` or ``gemini`` to opt in. Any other
    value, including ``offline``, deliberately disables remote model calls.
    """
    provider = os.getenv("REDCELL_LLM_PROVIDER", "offline").strip().lower()
    if provider == "gemini":
        api_key = os.getenv("GEMINI_API_KEY")
        client_kwargs = {"api_key": api_key, "base_url": GEMINI_OPENAI_BASE_URL}
    elif provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        client_kwargs = {"api_key": api_key}
    else:
        return None

    if not api_key:
        return None
    try:
        from openai import OpenAI
    except Exception:
        return None
    try:
        return LLM(OpenAI(**client_kwargs))
    except Exception:
        return None
