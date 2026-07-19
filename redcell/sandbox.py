"""Sandbox — run a generated challenge in isolation.

Writes challenge files, builds/runs the vulnerable app, returns a URL.
Primary: Docker. Fallback: local subprocess venv (decided Day 2 morning on
Windows). Everything here is training-only and uses synthetic secrets.
"""

# TODO(day2): docker build + run (or subprocess fallback), health-check, return url.


def launch(challenge_id: str) -> str:
    """Start the challenge app; return the base URL. (stub)"""
    raise NotImplementedError


def teardown(challenge_id: str) -> None:
    """Stop and clean up the challenge. (stub)"""
    raise NotImplementedError
