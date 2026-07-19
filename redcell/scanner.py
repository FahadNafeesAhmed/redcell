"""Scanner — repo -> JSON findings.

Feeds repo source to GPT and returns a list of findings:
    {threat, file, line, snippet, why}
MVP target: detect unsanitized user input flowing into an LLM prompt
(prompt injection). Only needs to reliably find the ONE demo vuln class.
"""

# TODO(day1): walk repo, chunk files, prompt GPT (cheap model) for findings,
# validate against fixtures/golden.


def scan(repo_path: str) -> list[dict]:
    """Return a list of vulnerability findings for the repo. (stub)"""
    raise NotImplementedError
