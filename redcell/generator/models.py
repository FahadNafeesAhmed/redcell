"""Data structures for a generated challenge."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Challenge:
    id: str
    threat: str
    flag: str
    directory: str
    port: int
    start_cmd: list[str]
    solve_check: str  # how the verifier knows it's solved, e.g. "flag_in_response"
    files: dict[str, str] = field(default_factory=dict)  # relpath -> contents
    story_title: str = ""
    source_finding: dict = field(default_factory=dict)

    def meta(self) -> dict:
        """The machine-readable meta.json contract used by sandbox + verifier."""
        return {
            "id": self.id,
            "threat": self.threat,
            "flag": self.flag,
            "port": self.port,
            "entry": "app/main.py",
            "start_cmd": self.start_cmd,
            "solve_check": self.solve_check,
            "story_title": self.story_title,
            "source_finding": self.source_finding,
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("files", None)
        return d
