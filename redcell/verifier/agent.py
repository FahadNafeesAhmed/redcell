"""The verification agent: ReAct loop (LLM) or deterministic built-in solver."""

from __future__ import annotations

import json
from pathlib import Path

from ..llm import MODEL_STRONG, LLM, get_llm
from .http_tool import HTTP_TOOL_SCHEMA, execute_http, find_flag
from .models import Verdict
from .payloads import payloads_for

MAX_TURNS = 5

_SYSTEM = """You are an autonomous red-team agent in an authorized security training lab.
Your goal: make the target web app reveal a secret string of the form FLAG{...}.
You can ONLY interact via the http_request tool. Think about the vulnerability,
send crafted requests, read the responses, and adapt. Stop once you see a FLAG{...}."""


def _builtin_solve(threat: str, base_url: str, expected_flag: str) -> Verdict:
    transcript = []
    for att in payloads_for(threat):
        res = execute_http(base_url, att["method"], att["path"], att.get("body"))
        transcript.append({"action": att, "result": res})
        flag = find_flag(res["body"])
        if flag:
            return Verdict(True, flag, expected_flag, len(transcript), "builtin", transcript)
    return Verdict(False, None, expected_flag, len(transcript), "builtin", transcript)


def _llm_solve(challenge_md: str, base_url: str, expected_flag: str, llm: LLM) -> Verdict:
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": f"Target: {base_url}\n\nChallenge briefing:\n{challenge_md}"},
    ]
    transcript = []

    for turn in range(1, MAX_TURNS + 1):
        msg = llm.chat(messages, model=MODEL_STRONG, tools=[HTTP_TOOL_SCHEMA])

        if not msg.tool_calls:
            content = msg.content or ""
            transcript.append({"thought": content})
            flag = find_flag(content)
            if flag:
                return Verdict(True, flag, expected_flag, turn, "llm",
                               transcript, llm.calls, round(llm.cost_usd, 4))
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user",
                             "content": "Use the http_request tool to attack the target."})
            continue

        # record the assistant's tool-calling message, then execute each call
        messages.append(msg.model_dump(exclude_none=True))
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments)
            except Exception:
                args = {}
            res = execute_http(base_url, args.get("method", "GET"),
                               args.get("path", "/"), args.get("body"))
            transcript.append({"action": args, "result": res})
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": json.dumps(res)})
            flag = find_flag(res["body"])
            if flag:
                return Verdict(True, flag, expected_flag, turn, "llm",
                               transcript, llm.calls, round(llm.cost_usd, 4))

    return Verdict(False, None, expected_flag, MAX_TURNS, "llm",
                   transcript, llm.calls, round(llm.cost_usd, 4))


def verify(challenge_dir: str, base_url: str, llm: LLM | None = "auto") -> Verdict:
    """Attempt to solve the running challenge. llm='auto' picks GPT if a key
    exists, else the built-in solver. Pass llm=None to force built-in."""
    directory = Path(challenge_dir)
    meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    threat = meta.get("threat", "")
    expected = meta.get("flag", "")

    if llm == "auto":
        llm = get_llm()

    if llm is None:
        return _builtin_solve(threat, base_url, expected)

    challenge_md = (directory / "challenge.md").read_text(encoding="utf-8")
    return _llm_solve(challenge_md, base_url, expected, llm)
