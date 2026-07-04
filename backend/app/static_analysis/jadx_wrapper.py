"""JADX decompilation wrapper.

Shells out to `jadx` to recover Java source. The recovered source is used to
harvest string literals (for the entropy-based obfuscation heuristic) and to
give the LLM readable code context. JADX must be on PATH.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

JADX_BIN = os.getenv("JADX_BIN", "jadx")
_TIMEOUT_SECONDS = 240


def is_available() -> bool:
    return shutil.which(JADX_BIN) is not None


def decompile(apk_path: str, out_dir: str | None = None) -> dict[str, Any]:
    """Decompile an APK to Java with JADX. Returns {out_dir, java_files, ...}."""
    if not is_available():
        log.warning("jadx.unavailable")
        return {"ok": False, "error": "jadx not installed", "out_dir": None}

    out_dir = out_dir or tempfile.mkdtemp(prefix="jadx_")
    # --no-res keeps it fast (we only need sources for string harvesting).
    cmd = [JADX_BIN, "--no-res", "-d", out_dir, apk_path]
    try:
        subprocess.run(
            cmd, check=False, capture_output=True, timeout=_TIMEOUT_SECONDS, text=True
        )
    except subprocess.TimeoutExpired:
        log.warning("jadx.timeout", apk=apk_path)
        return {"ok": False, "error": "jadx timed out", "out_dir": out_dir}

    java_files = _count_java(out_dir)
    log.info("jadx.decompiled", java_files=java_files)
    return {"ok": True, "out_dir": out_dir, "java_files": java_files}


def collect_string_literals(source_dir: str, limit: int = 5000) -> list[str]:
    """Harvest quoted string literals from decompiled Java for entropy scoring."""
    import re

    string_re = re.compile(r'"((?:[^"\\]|\\.){2,})"')
    literals: list[str] = []
    for dirpath, _dirs, files in os.walk(source_dir):
        for name in files:
            if not name.endswith(".java"):
                continue
            try:
                with open(os.path.join(dirpath, name), "r", encoding="utf-8",
                          errors="ignore") as fh:
                    for match in string_re.findall(fh.read()):
                        literals.append(match)
                        if len(literals) >= limit:
                            return literals
            except OSError:
                continue
    return literals


def _count_java(root: str) -> int:
    count = 0
    for _dirpath, _dirs, files in os.walk(root):
        count += sum(1 for f in files if f.endswith(".java"))
    return count
