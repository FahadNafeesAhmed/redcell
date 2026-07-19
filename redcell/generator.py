"""Generator — a finding -> a playable CTF challenge.

Turns one finding into: challenge.md (story + goal + hints), the vulnerable
app files, and exploit.py. Few-shot prompted against fixtures/golden so output
matches the hand-built quality bar.
"""

# TODO(day2): prompt GPT (strong model) with the golden example as template,
# write files into challenges/<id>/.


def generate(finding: dict) -> str:
    """Generate a challenge from a finding; return its challenge id/dir. (stub)"""
    raise NotImplementedError
