"""Stage 2 — the source & sink dictionaries.

SOURCES: where untrusted input enters (matched by regex over a function body).
SINKS:   dangerous operations (matched against call-graph callee names).

Pure pattern data + tiny matchers. No AI, no cost.
"""

from __future__ import annotations

import re

# --- SOURCES: untrusted input entering the program ----------------------
# Matched against a function's source text.
SOURCE_PATTERNS: list[tuple[str, str]] = [
    # Flask / FastAPI / generic request objects
    (r"request\.(json|args|form|values|data|files|cookies|headers|get_json|stream)",
     "http_request"),
    # Django / DRF request attributes
    (r"request\.(GET|POST|PUT|DELETE|body|query_params|FILES|COOKIES|META)",
     "http_request"),
    # aiohttp request methods and route/query parameters
    (r"request\.(post|read|text|json|multipart|match_info|query|rel_url)",
     "http_request"),
    (r"\bflask\.request\b", "http_request"),
    # Route/view decorators (params are untrusted)
    (r"@(app|router|blueprint|bp|api)\.(route|get|post|put|delete|patch|websocket)",
     "http_endpoint"),
    # Raw stdlib http.server / WSGI style input
    (r"\bparse_qs\b", "http_request"),
    (r"\bself\.(path|rfile)\b", "http_request"),
    (r"\benviron\[['\"](QUERY_STRING|PATH_INFO|wsgi\.input)", "http_request"),
    # Other untrusted entry points
    (r"\binput\s*\(", "stdin"),
    (r"\bsys\.argv\b", "cli_args"),
    (r"\bos\.environ\b", "environment"),
]

_SOURCE_RE = [(re.compile(p), kind) for p, kind in SOURCE_PATTERNS]

# --- SINKS: dangerous operations, keyed by threat -----------------------
# Matched against callee_full (dotted) or the short callee name.
SINK_PATTERNS: list[tuple[str, str, str]] = [
    # (substring to look for in callee_full, threat, human label)
    ("chat.completions.create", "prompt_injection", "OpenAI chat completion"),
    ("completions.create", "prompt_injection", "OpenAI completion"),
    ("responses.create", "prompt_injection", "OpenAI responses API"),
    ("messages.create", "prompt_injection", "Anthropic messages API"),
    ("generate_content", "prompt_injection", "Gemini generate content"),
    ("generateContent", "prompt_injection", "Gemini generate content"),
    ("ChatCompletion", "prompt_injection", "OpenAI ChatCompletion"),
    (".invoke", "prompt_injection", "LangChain invoke"),
    ("llm.", "prompt_injection", "LLM call"),
    (".execute", "sql_injection", "SQL execute"),
    (".executescript", "sql_injection", "SQL executescript"),
    (".raw", "sql_injection", "raw SQL query"),
    ("os.system", "command_injection", "os.system"),
    ("subprocess.run", "command_injection", "subprocess.run"),
    ("subprocess.call", "command_injection", "subprocess.call"),
    ("subprocess.Popen", "command_injection", "subprocess.Popen"),
    ("os.popen", "command_injection", "os.popen"),
    ("eval", "code_execution", "eval"),
    ("exec", "code_execution", "exec"),
    ("pickle.loads", "deserialization", "pickle.loads"),
    ("yaml.load", "deserialization", "yaml.load"),
    ("requests.get", "ssrf", "requests.get"),
    ("requests.post", "ssrf", "requests.post"),
    ("urlopen", "ssrf", "urllib urlopen"),
]


def match_source(text: str) -> str | None:
    """Return the source kind if the text contains an input source, else None."""
    for rx, kind in _SOURCE_RE:
        if rx.search(text):
            return kind
    return None


def match_sink(callee: str, callee_full: str) -> tuple[str, str] | None:
    """Return (threat, label) if this call is a sink, else None."""
    hay = callee_full or callee or ""
    for needle, threat, label in SINK_PATTERNS:
        # exact short-name match for bare builtins like eval/exec, else substring
        if needle in ("eval", "exec"):
            if callee == needle:
                return threat, label
        elif needle in hay:
            return threat, label
    return None
