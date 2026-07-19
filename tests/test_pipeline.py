from redcell.ingest import Store, ingest


def test_end_to_end_counts(sample_repo, tmp_path):
    db = tmp_path / "index.db"
    report = ingest(str(sample_repo), str(db))

    # 3 python files found (venv/ ignored), all parse cleanly.
    assert report.files_seen == 3
    assert report.files_parsed == 3
    assert report.parse_errors == 0

    # add, mul, Calculator, compute, main
    assert report.symbols == 5
    # from pkg.math_utils import add, mul
    assert report.imports == 2
    # mul->add; compute->mul,add; main->Calculator,compute,print
    assert report.calls == 6


def test_db_is_queryable_after_ingest(sample_repo, tmp_path):
    db = tmp_path / "index.db"
    ingest(str(sample_repo), str(db))

    store = Store(str(db))
    stats = store.stats()
    assert stats["symbols"] == 5
    assert stats["calls"] == 6

    # Call-graph query: who calls add()?  -> mul (math_utils) and compute (service)
    callers = {r["caller"] for r in store.find_callers("add")}
    assert callers == {"mul", "Calculator.compute"}
    store.close()


def test_venv_excluded(sample_repo, tmp_path):
    db = tmp_path / "index.db"
    ingest(str(sample_repo), str(db))
    store = Store(str(db))
    assert store.find_symbol("ignored") == []  # the venv/ function
    store.close()
