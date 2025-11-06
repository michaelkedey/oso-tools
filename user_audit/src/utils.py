from __future__ import annotations
import subprocess, shlex, os, pwd
from typing import Tuple, Optional

def run_cmd(cmd: str, timeout: int = 5) -> Tuple[int, str, str]:
    """Run shell command, return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def read_file_safe(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return ""

def exists_user(username: str) -> bool:
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False
