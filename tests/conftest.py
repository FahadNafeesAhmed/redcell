from pathlib import Path

import pytest

SAMPLE_REPO = Path(__file__).parent / "sample_repo"


@pytest.fixture
def sample_repo() -> Path:
    return SAMPLE_REPO
