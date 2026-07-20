"""Verdict — the result of a verification attempt."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Verdict:
    solved: bool
    flag_found: str | None
    expected_flag: str
    turns: int
    engine: str  # "llm" | "builtin"
    transcript: list = field(default_factory=list)
    llm_calls: int = 0
    cost_usd: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)
