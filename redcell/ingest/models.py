"""Data structures produced by parsing. Plain dataclasses — no runtime deps."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Symbol:
    """A function, method, or class definition."""

    kind: str  # "function" | "method" | "class"
    name: str
    qualname: str  # dotted path within the file, e.g. "Calculator.compute"
    file: str
    start_line: int
    end_line: int
    signature: str = ""


@dataclass
class ImportEdge:
    """One imported name (module dependency edge)."""

    file: str
    module: str  # e.g. "pkg.math_utils"
    name: str  # imported symbol / alias
    line: int


@dataclass
class CallEdge:
    """A call site: who calls what, and where."""

    caller: str  # enclosing function qualname, or "<module>"
    callee: str  # last name, e.g. "compute"
    callee_full: str  # dotted, e.g. "c.compute"
    file: str
    line: int


@dataclass
class ParsedFile:
    """Everything extracted from a single source file."""

    symbols: list[Symbol] = field(default_factory=list)
    imports: list[ImportEdge] = field(default_factory=list)
    calls: list[CallEdge] = field(default_factory=list)
