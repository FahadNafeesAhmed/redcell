"""redcell verifier — autonomously solve a generated challenge to prove it real.

A ReAct-style agent: given the running challenge + an http_request tool, it
sends attack payloads, observes responses, and adapts until it captures the
flag. With an LLM it's GPT-driven; without one, a deterministic built-in solver
runs the same loop so the pipeline is fully testable offline.
"""

from .agent import verify
from .models import Verdict

__all__ = ["verify", "Verdict"]
