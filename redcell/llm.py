"""Thin OpenAI wrapper — the ONLY file that imports `openai`.

Keeps model choice and JSON handling in one place so the rest of the codebase
never touches the SDK directly. Swapping models/providers = editing this file.
"""

# TODO(day1): load OPENAI_API_KEY via python-dotenv, expose:
#   complete_json(prompt, *, model, schema=None) -> dict
#   complete_text(prompt, *, model) -> str
# with retries + timeout. Use JSON mode / structured outputs for the scanner.


def complete_json(prompt: str, *, model: str) -> dict:
    """Return a parsed JSON object from the model. (stub)"""
    raise NotImplementedError


def complete_text(prompt: str, *, model: str) -> str:
    """Return raw text from the model. (stub)"""
    raise NotImplementedError
