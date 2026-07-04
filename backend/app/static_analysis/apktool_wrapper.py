"""Apktool decompilation wrapper.

Shells out to `apktool d` to decode resources + smali. We use the decoded tree to
gauge structural complexity (smali method/class counts) that feeds the
obfuscation heuristic in `permission_extractor`.

Apktool must be on PATH (see backend Dockerfile). All failures degrade to an
empty result rather than crashing the pipeline.

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

APKTOOL_BIN = os.getenv("APKTOOL_BIN", "apktool")
_TIMEOUT_SECONDS = 180


def is_available() -> bool:
    return shutil.which(APKTOOL_BIN) is not None


def decode(apk_path: str, out_dir: str | None = None) -> dict[str, Any]:
    """Decode an APK with apktool. Returns {out_dir, smali_files, ...}.

    On failure returns {"ok": False, "error": ...} so callers can continue.
    """
    if not is_available():
        log.warning("apktool.unavailable")
        return {"ok": False, "error": "apktool not installed", "out_dir": None}

    out_dir = out_dir or tempfile.mkdtemp(prefix="apktool_")
    cmd = [APKTOOL_BIN, "d", "-f", "-o", out_dir, apk_path]
    try:
        subprocess.run(
            cmd, check=True, capture_output=True, timeout=_TIMEOUT_SECONDS, text=True
        )
    except subprocess.TimeoutExpired:
        log.warning("apktool.timeout", apk=apk_path)
        return {"ok": False, "error": "apktool timed out", "out_dir": out_dir}
    except subprocess.CalledProcessError as exc:
        log.warning("apktool.failed", stderr=exc.stderr[:500] if exc.stderr else "")
        return {"ok": False, "error": "apktool failed", "out_dir": out_dir}

    stats = _tree_stats(out_dir)
    stats.update({"ok": True, "out_dir": out_dir})
    log.info("apktool.decoded", **{k: stats[k] for k in ("smali_files", "smali_classes")})
    return stats


def _tree_stats(root: str) -> dict[str, Any]:
    smali_files = 0
    smali_classes = 0
    total_bytes = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith(".smali"):
                smali_files += 1
                smali_classes += 1
                try:
                    total_bytes += os.path.getsize(os.path.join(dirpath, name))
                except OSError:
                    pass
    return {
        "smali_files": smali_files,
        "smali_classes": smali_classes,
        "smali_total_bytes": total_bytes,
    }
