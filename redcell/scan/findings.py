"""Stage 5 — the Finding data model + ranking/dedupe."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Base severity by threat class (0-1), scaled by LLM/heuristic confidence.
SEVERITY = {
    "prompt_injection": 0.9,
    "command_injection": 1.0,
    "code_execution": 1.0,
    "sql_injection": 0.9,
    "deserialization": 0.85,
    "ssrf": 0.7,
}


@dataclass
class Finding:
    threat: str
    file: str
    line: int
    source_kind: str
    source_file: str
    sink_label: str
    why: str
    confidence: float
    confirmed_by: str  # "llm" | "heuristic"
    cross_file: bool
    path: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return round(SEVERITY.get(self.threat, 0.5) * self.confidence, 3)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = self.score
        return d


def rank_and_dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop duplicate (threat, file, line) findings; sort by score desc."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.threat, f.file, f.line)
        if key not in best or f.score > best[key].score:
            best[key] = f
    return sorted(best.values(), key=lambda f: f.score, reverse=True)
