"""Stage 3 — candidate finder (backward taint over the call graph).

For every sink call, walk UP the call graph (who calls this function?) until we
hit a function whose body contains an input source. That source -> ... -> sink
chain is a candidate vulnerability. This is the cross-file reachability that
free Semgrep can't do; here the call graph gathers the context and (later) the
LLM reasons about exploitability.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ..ingest.store import Store
from .sources_sinks import match_sink, match_source

MAX_DEPTH = 8  # max hops up the call graph
DECORATOR_LOOKBACK = 3  # lines above a def to include (catches @app.route)


@dataclass
class Hop:
    func: str
    file: str


@dataclass
class Candidate:
    threat: str
    sink_label: str
    sink_file: str
    sink_line: int
    source_kind: str
    source_file: str
    path: list[Hop] = field(default_factory=list)  # sink-first .. source-last

    @property
    def cross_file(self) -> bool:
        return self.sink_file != self.source_file

    def path_str(self) -> str:
        return " <- ".join(f"{h.func}@{h.file}" for h in self.path)


def _read(root: Path, rel: str) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _scope_source(store: Store, root: Path, file: str, func: str) -> str:
    """Source text of `func` in `file`. Module scope => whole file."""
    text = _read(root, file)
    if not text:
        return ""
    if func == "<module>":
        return text
    span = store.get_symbol_span(file, func)
    if not span:
        return text  # fallback: scan whole file
    start, end = span
    lines = text.splitlines()
    lo = max(0, start - 1 - DECORATOR_LOOKBACK)
    return "\n".join(lines[lo:end])


def _simple(qualname: str) -> str:
    return qualname.split(".")[-1]


def find_candidates(store: Store, root: str | Path) -> list[Candidate]:
    root = Path(root)
    calls = store.all_calls()

    # cache scope text lookups
    @lru_cache(maxsize=None)
    def scope(file: str, func: str) -> str:
        return _scope_source(store, root, file, func)

    candidates: list[Candidate] = []
    seen: set[tuple] = set()

    for c in calls:
        hit = match_sink(c["callee"], c["callee_full"])
        if not hit:
            continue
        threat, label = hit
        sink_file, sink_func, sink_line = c["file_path"], c["caller"], c["line"]

        # Backward BFS up the call graph looking for a source.
        visited: set[tuple[str, str]] = set()
        dq: deque[tuple[str, str, list[Hop]]] = deque()
        dq.append((sink_file, sink_func, [Hop(sink_func, sink_file)]))

        while dq:
            file, func, path = dq.popleft()
            if (file, func) in visited or len(path) > MAX_DEPTH:
                continue
            visited.add((file, func))

            src_kind = match_source(scope(file, func))
            if src_kind:
                key = (threat, sink_file, sink_line, file)
                if key not in seen:
                    seen.add(key)
                    candidates.append(Candidate(
                        threat=threat, sink_label=label,
                        sink_file=sink_file, sink_line=sink_line,
                        source_kind=src_kind, source_file=file, path=path,
                    ))
                break  # nearest source is enough

            if func == "<module>":
                continue
            for r in store.find_callers(_simple(func)):
                nxt = (r["file_path"], r["caller"])
                if nxt not in visited:
                    dq.append((r["file_path"], r["caller"],
                               path + [Hop(r["caller"], r["file_path"])]))

    return candidates
