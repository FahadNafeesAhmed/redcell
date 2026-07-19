from pathlib import Path

from redcell.ingest.filters import detect_lang, is_ignored_dir, iter_source_files


def test_detect_lang():
    assert detect_lang(Path("a.py")) == "python"
    assert detect_lang(Path("a.ts")) == "typescript"
    assert detect_lang(Path("a.txt")) is None
    assert detect_lang(Path("Makefile")) is None


def test_ignored_dirs():
    assert is_ignored_dir("venv")
    assert is_ignored_dir("node_modules")
    assert is_ignored_dir(".git")
    assert is_ignored_dir(".hidden")  # hidden dirs skipped
    assert not is_ignored_dir("pkg")


def test_iter_source_files_skips_venv(sample_repo):
    files = {p.name for p in iter_source_files(sample_repo)}
    assert files == {"__init__.py", "math_utils.py", "service.py"}
    # The file under venv/ must never appear.
    assert "should_ignore.py" not in files


def test_iter_source_files_count(sample_repo):
    assert len(list(iter_source_files(sample_repo))) == 3
