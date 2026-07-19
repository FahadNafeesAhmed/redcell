"""SQLite store — the queryable model of an ingested repo.

One file, portable, no server. Holds files, symbols, imports and the call
graph. This is what the scanner/generator later query instead of re-reading
source or hitting the LLM.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import CallEdge, ImportEdge, Symbol

_SCHEMA = """
CREATE TABLE IF NOT EXISTS repos (
    id INTEGER PRIMARY KEY,
    root TEXT NOT NULL,
    sha TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    repo_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    lang TEXT,
    loc INTEGER,
    sha TEXT,
    parsed INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL,
    kind TEXT, name TEXT, qualname TEXT,
    start_line INTEGER, end_line INTEGER, signature TEXT
);
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL,
    module TEXT, name TEXT, line INTEGER
);
CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL,
    caller TEXT, callee TEXT, callee_full TEXT, line INTEGER
);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_qual ON symbols(qualname);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee);
CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller);
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row

    def init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # --- writes ----------------------------------------------------------
    def add_repo(self, root: str, sha: str | None) -> int:
        cur = self.conn.execute(
            "INSERT INTO repos(root, sha, created_at) VALUES (?,?,?)",
            (root, sha, datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid

    def add_file(self, repo_id: int, path: str, lang: str | None,
                 loc: int, sha: str, parsed: bool) -> int:
        cur = self.conn.execute(
            "INSERT INTO files(repo_id, path, lang, loc, sha, parsed) VALUES (?,?,?,?,?,?)",
            (repo_id, path, lang, loc, sha, int(parsed)),
        )
        return cur.lastrowid

    def add_symbols(self, file_id: int, symbols: list[Symbol]) -> None:
        self.conn.executemany(
            "INSERT INTO symbols(file_id, kind, name, qualname, start_line, end_line, signature)"
            " VALUES (?,?,?,?,?,?,?)",
            [(file_id, s.kind, s.name, s.qualname, s.start_line, s.end_line, s.signature)
             for s in symbols],
        )

    def add_imports(self, file_id: int, imports: list[ImportEdge]) -> None:
        self.conn.executemany(
            "INSERT INTO imports(file_id, module, name, line) VALUES (?,?,?,?)",
            [(file_id, i.module, i.name, i.line) for i in imports],
        )

    def add_calls(self, file_id: int, calls: list[CallEdge]) -> None:
        self.conn.executemany(
            "INSERT INTO calls(file_id, caller, callee, callee_full, line) VALUES (?,?,?,?,?)",
            [(file_id, c.caller, c.callee, c.callee_full, c.line) for c in calls],
        )

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- reads / queries -------------------------------------------------
    def _count(self, table: str) -> int:
        return self.conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]

    def stats(self) -> dict:
        return {
            "repos": self._count("repos"),
            "files": self._count("files"),
            "files_parsed": self.conn.execute(
                "SELECT COUNT(*) AS n FROM files WHERE parsed=1").fetchone()["n"],
            "symbols": self._count("symbols"),
            "imports": self._count("imports"),
            "calls": self._count("calls"),
            "loc": self.conn.execute(
                "SELECT COALESCE(SUM(loc),0) AS n FROM files").fetchone()["n"],
        }

    def find_symbol(self, name: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT s.*, f.path AS file_path FROM symbols s JOIN files f ON f.id=s.file_id"
            " WHERE s.name=? ORDER BY f.path, s.start_line",
            (name,),
        ).fetchall()

    def find_callers(self, callee: str) -> list[sqlite3.Row]:
        """Who calls `callee`? Core call-graph query for taint traversal."""
        return self.conn.execute(
            "SELECT DISTINCT c.caller, f.path AS file_path, c.line"
            " FROM calls c JOIN files f ON f.id=c.file_id WHERE c.callee=?"
            " ORDER BY f.path, c.line",
            (callee,),
        ).fetchall()
