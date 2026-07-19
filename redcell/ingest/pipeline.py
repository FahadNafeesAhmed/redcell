"""Ingestion orchestrator: acquire -> filter -> parse -> store."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .acquire import resolve_repo
from .filters import PARSEABLE, detect_lang, iter_source_files
from .parser import parse_python
from .store import Store


@dataclass
class IngestReport:
    root: str = ""
    sha: str | None = None
    db_path: str = ""
    files_seen: int = 0  # known-language source files found
    files_parsed: int = 0  # successfully parsed
    files_skipped_lang: int = 0  # known ext but no parser yet (js/ts)
    parse_errors: int = 0  # SyntaxError / read failures
    symbols: int = 0
    imports: int = 0
    calls: int = 0
    loc: int = 0
    elapsed_s: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()


def ingest(src: str, db_path: str = ".redcell/index.db") -> IngestReport:
    """Ingest a repo (local path or git URL) into a SQLite index.

    Idempotent-ish: creates a fresh DB file. Returns an IngestReport with
    counts used by tests and the CLI.
    """
    started = time.perf_counter()
    root, sha = resolve_repo(src)

    report = IngestReport(root=str(root), sha=sha, db_path=db_path)

    store = Store(db_path)
    store.init_schema()
    repo_id = store.add_repo(str(root), sha)

    for path in iter_source_files(root):
        lang = detect_lang(path)
        report.files_seen += 1
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:  # unreadable file
            report.parse_errors += 1
            report.errors.append(f"read {path}: {exc}")
            continue

        rel = str(path.relative_to(root)).replace("\\", "/")
        loc = source.count("\n") + 1
        file_sha = _sha1(source)
        report.loc += loc

        if lang not in PARSEABLE:
            report.files_skipped_lang += 1
            store.add_file(repo_id, rel, lang, loc, file_sha, parsed=False)
            continue

        try:
            parsed = parse_python(rel, source)
        except SyntaxError as exc:
            report.parse_errors += 1
            report.errors.append(f"parse {rel}: {exc}")
            store.add_file(repo_id, rel, lang, loc, file_sha, parsed=False)
            continue

        file_id = store.add_file(repo_id, rel, lang, loc, file_sha, parsed=True)
        store.add_symbols(file_id, parsed.symbols)
        store.add_imports(file_id, parsed.imports)
        store.add_calls(file_id, parsed.calls)

        report.files_parsed += 1
        report.symbols += len(parsed.symbols)
        report.imports += len(parsed.imports)
        report.calls += len(parsed.calls)

    store.commit()
    store.close()
    report.elapsed_s = round(time.perf_counter() - started, 3)
    return report
