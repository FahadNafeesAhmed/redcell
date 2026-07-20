"""Scan orchestrator: ingest -> candidates -> confirm -> rank -> findings.json."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..ingest import ingest as run_ingest
from ..ingest.store import Store
from ..llm import get_llm
from .candidates import find_candidates
from .confirm import CONFIRM_THRESHOLD, confirm
from .findings import Finding, rank_and_dedupe


@dataclass
class ScanReport:
    src: str
    root: str = ""
    db_path: str = ""
    out_path: str = ""
    files_parsed: int = 0
    candidates: int = 0
    findings: int = 0
    engine: str = "heuristic"  # "llm" | "heuristic"
    llm_calls: int = 0
    cost_usd: float = 0.0
    elapsed_s: float = 0.0
    findings_list: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "findings_list"}
        d["findings"] = [f.to_dict() for f in self.findings_list]
        return d


def scan(src: str, db_path: str = ".redcell/index.db",
         out_path: str = "findings.json", use_llm: bool = True) -> ScanReport:
    import time

    started = time.perf_counter()

    # Stage 1: ingest (clones URL if needed)
    ing = run_ingest(src, db_path)
    report = ScanReport(src=src, root=ing.root, db_path=db_path,
                        out_path=out_path, files_parsed=ing.files_parsed)

    store = Store(db_path)

    # Stages 2-3: candidates
    cands = find_candidates(store, ing.root)
    report.candidates = len(cands)

    # Stage 4: confirm engine
    llm = get_llm() if use_llm else None
    report.engine = "llm" if llm else "heuristic"

    findings: list[Finding] = []
    for c in cands:
        res = confirm(c, ing.root, llm)
        if res["exploitable"] and res["confidence"] >= CONFIRM_THRESHOLD:
            findings.append(Finding(
                threat=c.threat, file=c.sink_file, line=c.sink_line,
                source_kind=c.source_kind, source_file=c.source_file,
                sink_label=c.sink_label, why=res["why"],
                confidence=round(res["confidence"], 3),
                confirmed_by=res["confirmed_by"], cross_file=c.cross_file,
                path=[f"{h.func}@{h.file}" for h in c.path],
            ))

    # Stage 5: rank + dedupe
    findings = rank_and_dedupe(findings)
    report.findings_list = findings
    report.findings = len(findings)

    if llm:
        report.llm_calls = llm.calls
        report.cost_usd = round(llm.cost_usd, 4)

    store.close()

    report.elapsed_s = round(time.perf_counter() - started, 3)

    # write findings.json
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return report
