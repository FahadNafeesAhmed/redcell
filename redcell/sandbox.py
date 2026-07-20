"""Sandbox — run a generated challenge as an isolated subprocess.

Reads challenges/<id>/meta.json, launches app/main.py with the synthetic FLAG
and a free PORT injected via env, waits until it accepts connections, and hands
back a base URL. Subprocess (not Docker) so it just works on Windows.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_open(port: int) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


@dataclass
class RunningChallenge:
    proc: subprocess.Popen
    base_url: str
    port: int
    flag: str
    directory: str

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()


def launch(challenge_dir: str, timeout: float = 20.0) -> RunningChallenge:
    """Start the challenge app; wait until healthy; return a RunningChallenge."""
    directory = Path(challenge_dir)
    meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    flag = meta["flag"]
    port = _free_port()

    env = {
        **_base_env(),
        "FLAG": flag,
        "PORT": str(port),
    }
    proc = subprocess.Popen(
        [sys.executable, "app/main.py"],
        cwd=str(directory),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("challenge app exited before becoming healthy")
        if _port_open(port):
            break
        time.sleep(0.2)
    else:
        proc.terminate()
        raise TimeoutError(f"challenge app did not open port {port} within {timeout}s")

    return RunningChallenge(proc=proc, base_url=f"http://127.0.0.1:{port}",
                            port=port, flag=flag, directory=str(directory))


def _base_env() -> dict:
    import os

    return dict(os.environ)
