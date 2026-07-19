from redcell.ingest.models import CallEdge, ImportEdge, Symbol
from redcell.ingest.store import Store


def _seed():
    store = Store(":memory:")
    store.init_schema()
    repo_id = store.add_repo("/tmp/x", "deadbeef")
    fid = store.add_file(repo_id, "a.py", "python", 10, "sha", parsed=True)
    store.add_symbols(fid, [Symbol("function", "add", "add", "a.py", 1, 2, "(a, b)")])
    store.add_imports(fid, [ImportEdge("a.py", "os", "path", 1)])
    store.add_calls(fid, [CallEdge("mul", "add", "add", "a.py", 5)])
    store.commit()
    return store


def test_roundtrip_stats():
    store = _seed()
    s = store.stats()
    assert s["repos"] == 1
    assert s["files"] == 1
    assert s["files_parsed"] == 1
    assert s["symbols"] == 1
    assert s["imports"] == 1
    assert s["calls"] == 1
    store.close()


def test_find_symbol():
    store = _seed()
    rows = store.find_symbol("add")
    assert len(rows) == 1
    assert rows[0]["qualname"] == "add"
    assert rows[0]["file_path"] == "a.py"
    store.close()


def test_find_callers():
    store = _seed()
    rows = store.find_callers("add")
    assert len(rows) == 1
    assert rows[0]["caller"] == "mul"
    store.close()
