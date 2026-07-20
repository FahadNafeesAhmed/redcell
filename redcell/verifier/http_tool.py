"""The single tool the agent is allowed to use: an HTTP request to the target."""

from __future__ import annotations

import re

import requests

FLAG_RE = re.compile(r"FLAG\{[^}]+\}")


def execute_http(base_url: str, method: str, path: str,
                 body: dict | None = None, timeout: float = 10.0) -> dict:
    """Send one HTTP request to the sandboxed app. Returns {status, body}."""
    if not path.startswith("/"):
        path = "/" + path
    url = base_url + path
    try:
        if (method or "GET").upper() == "POST":
            r = requests.post(url, json=body or {}, timeout=timeout)
        else:
            r = requests.get(url, timeout=timeout)
        return {"status": r.status_code, "body": r.text[:2000]}
    except Exception as exc:
        return {"status": 0, "body": f"request error: {exc}"}


def find_flag(text: str) -> str | None:
    m = FLAG_RE.search(text or "")
    return m.group(0) if m else None


# OpenAI tool schema for the agent
HTTP_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "http_request",
        "description": "Send an HTTP request to the target application and get the response.",
        "parameters": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST"]},
                "path": {"type": "string",
                         "description": "URL path, may include a query string, e.g. /user?name=alice"},
                "body": {"type": "object",
                         "description": "JSON body for POST requests"},
            },
            "required": ["method", "path"],
        },
    },
}
