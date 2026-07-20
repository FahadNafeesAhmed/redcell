"""redcell generator: a Finding -> a playable, self-contained CTF challenge.

Output (per challenge, under challenges/<id>/):
    challenge.md    story + objective + hints
    meta.json       machine-readable: flag, threat, how to run, solve check
    app/main.py     a runnable, genuinely-vulnerable app (synthetic flag, no real data)
    app/requirements.txt
    exploit.py      reference solution that captures the flag

The vulnerable app is a clean reproduction of the finding's vulnerability CLASS
(prompt injection, SQLi, ...), so it runs offline with no API key and no secrets.
"""

from .generate import generate
from .models import Challenge

__all__ = ["generate", "Challenge"]
