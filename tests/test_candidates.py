from pathlib import Path

from redcell.ingest import Store, ingest
from redcell.scan.candidates import find_candidates

VULN_REPO = Path(__file__).parent / "vuln_repo"


def _build(tmp_path):
    db = tmp_path / "index.db"
    ingest(str(VULN_REPO), str(db))
    return Store(str(db))


def test_finds_cross_file_prompt_injection(tmp_path):
    store = _build(tmp_path)
    cands = find_candidates(store, VULN_REPO)
    store.close()

    pi = [c for c in cands if c.threat == "prompt_injection"]
    assert pi, "should find the prompt-injection flow"
    c = pi[0]
    assert c.cross_file is True
    assert c.source_kind == "http_request"
    # path should span from the llm sink back to the route handler
    files = {h.file for h in c.path}
    assert "app/llm.py" in files
    assert "app/routes.py" in files


def test_finds_same_file_sqli(tmp_path):
    store = _build(tmp_path)
    cands = find_candidates(store, VULN_REPO)
    store.close()

    sqli = [c for c in cands if c.threat == "sql_injection"]
    assert sqli, "should find the same-file SQL injection"
    assert sqli[0].cross_file is False
