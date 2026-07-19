"""redcell ingestion engine.

Turns an arbitrary repo into a queryable model (SQLite):
    acquire -> filter -> parse (AST) -> store (symbols + imports + call graph)

Public API:
    ingest(src, db_path) -> IngestReport
    Store(db_path)       -> query the built index
"""

from .pipeline import ingest, IngestReport
from .store import Store

__all__ = ["ingest", "IngestReport", "Store"]
