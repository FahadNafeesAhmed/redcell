"""Integration tests: generate a challenge, run it in a sandbox, let the
built-in (offline) agent solve it, and confirm it captures the real flag."""

import pytest

from redcell import sandbox as sbx
from redcell.generator import generate
from redcell.verifier import verify
from redcell.verifier.http_tool import find_flag

FINDINGS = {
    "prompt_injection": {"threat": "prompt_injection", "file": "app/llm.py", "line": 6},
    "sql_injection": {"threat": "sql_injection", "file": "app/db.py", "line": 12},
    "code_execution": {"threat": "code_execution", "file": "app/calc.py", "line": 3},
}


@pytest.mark.parametrize("threat", list(FINDINGS))
def test_agent_solves_generated_challenge(threat, tmp_path):
    ch = generate(FINDINGS[threat], out_dir=str(tmp_path), use_llm=False)
    run = sbx.launch(ch.directory)
    try:
        verdict = verify(ch.directory, run.base_url, llm=None)  # force built-in solver
        assert verdict.engine == "builtin"
        assert verdict.solved is True
        assert verdict.flag_found == run.flag == ch.flag
    finally:
        run.stop()


def test_find_flag_helper():
    assert find_flag("the secret is FLAG{abc123}") == "FLAG{abc123}"
    assert find_flag("nothing here") is None


def test_verdict_not_solved_on_wrong_target(tmp_path):
    """If the app never leaks a flag, the agent must report NOT solved."""
    ch = generate(FINDINGS["prompt_injection"], out_dir=str(tmp_path), use_llm=False)
    # point the verifier at a dead port -> no flag possible
    verdict = verify(ch.directory, "http://127.0.0.1:1", llm=None)
    assert verdict.solved is False
    assert verdict.flag_found is None


def test_verdict_not_solved_on_honeypot_flag(monkeypatch):
    """If the app returns a fake/honeypot flag, the agent must report NOT solved unless expected_flag matches."""
    from redcell.verifier import agent
    monkeypatch.setattr(agent, "payloads_for", lambda threat: [{"method": "GET", "path": "/test"}])
    monkeypatch.setattr(agent, "execute_http", lambda base_url, method, path, body=None: {"status": 200, "body": "FLAG{honeypot}"})

    verdict = agent._builtin_solve("prompt_injection", "http://fake.target", expected_flag="FLAG{real_secret}")
    assert verdict.solved is False
    assert verdict.flag_found == "FLAG{honeypot}"


def test_verifier_falls_back_when_optional_llm_fails(tmp_path):
    class FailingLLM:
        calls = 0
        cost_usd = 0.0

        def chat(self, *args, **kwargs):
            raise RuntimeError("provider unavailable")

    ch = generate(FINDINGS["prompt_injection"], out_dir=str(tmp_path), use_llm=False)
    run = sbx.launch(ch.directory)
    try:
        verdict = verify(ch.directory, run.base_url, llm=FailingLLM())
        assert verdict.engine == "builtin_fallback"
        assert verdict.solved is True
        assert verdict.flag_found == ch.flag
    finally:
        run.stop()
