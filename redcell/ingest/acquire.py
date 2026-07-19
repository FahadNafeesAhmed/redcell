"""Repo acquisition — resolve a local path or clone a remote URL.

Returns (root_path, commit_sha). Clones are shallow and cached under
`.redcell/cache/` so re-runs are instant.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

CACHE_DIR = Path(".redcell") / "cache"

_URL_RE = re.compile(r"^(https?://|git@|ssh://)")


def looks_like_url(src: str) -> bool:
    return bool(_URL_RE.match(src.strip()))


def _slug(url: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", url.strip())
    return name.strip("_")[:120] or "repo"


def _git_sha(root: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def resolve_repo(src: str, cache_dir: Path = CACHE_DIR) -> tuple[Path, str | None]:
    """Return (root, sha). Clones remote URLs (shallow, cached); local paths
    are used as-is. Raises FileNotFoundError / RuntimeError on failure."""
    if looks_like_url(src):
        cache_dir.mkdir(parents=True, exist_ok=True)
        dest = cache_dir / _slug(src)
        if not dest.exists():
            res = subprocess.run(
                ["git", "clone", "--depth", "1", src, str(dest)],
                capture_output=True, text=True, timeout=600,
            )
            if res.returncode != 0:
                raise RuntimeError(f"git clone failed: {res.stderr.strip()}")
        return dest, _git_sha(dest)

    root = Path(src).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"path does not exist: {root}")
    return root, _git_sha(root)
