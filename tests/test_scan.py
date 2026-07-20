import json
from pathlib import Path

from redcell.scan import scan
from redcell.scan.candidates import Candidate, Hop
from redcell.scan.confirm import confirm

VULN_REPO = Path(__file__).parent / "vuln_repo"


def test_scan_end_to_end_heuristic(tmp_path):
    db = tmp_path / "index.db"
    out = tmp_path / "findings.json"
    # force heuristic engine (deterministic, no network)
    report = scan(str(VULN_REPO), db_path=str(db), out_path=str(out), use_llm=False)

    assert report.engine == "heuristic"
    assert report.candidates >= 2
    assert report.findings >= 2

    threats = {f.threat for f in report.findings_list}
    assert "prompt_injection" in threats
    assert "sql_injection" in threats

    # findings.json written and well-formed
    data = json.loads(out.read_text())
    assert data["engine"] == "heuristic"
    assert len(data["findings"]) == report.findings
    # findings are sorted by score desc
    scores = [f["score"] for f in data["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_safe_code_not_flagged(tmp_path):
    db = tmp_path / "index.db"
    out = tmp_path / "findings.json"
    report = scan(str(VULN_REPO), db_path=str(db), out_path=str(out), use_llm=False)
    # safe.py has neither source nor sink
    assert all("safe.py" not in f.file for f in report.findings_list)


def test_confirmation_falls_back_when_optional_llm_fails(tmp_path):
    class FailingLLM:
        def complete_json(self, *args, **kwargs):
            raise RuntimeError("rate limited")

    cand = Candidate(
        threat="prompt_injection", sink_label="OpenAI chat completion",
        sink_file="app/llm.py", sink_line=6, source_kind="http_request",
        source_file="app/routes.py", path=[Hop("build_prompt", "app/llm.py")],
    )
    result = confirm(cand, tmp_path, FailingLLM())
    assert result["exploitable"] is True
    assert result["confirmed_by"] == "heuristic_fallback"
