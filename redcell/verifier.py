"""Verifier — the demo centerpiece.

A GPT agent that sees the running challenge + its description, crafts exploit
attempts (prompt-injection payloads), extracts the flag, and reports pass/fail.
If the agent captures the flag, the generated challenge is proven solvable.
"""

# TODO(day2): agent loop -> send payloads to sandbox url, detect flag, retry x3.


def verify(challenge_id: str, base_url: str) -> dict:
    """Attempt to solve the challenge; return {solved, flag, transcript}. (stub)"""
    raise NotImplementedError
