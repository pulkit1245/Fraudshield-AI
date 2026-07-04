"""SHA-256 hashing utilities.

APKs can be up to 200 MB, so hashing streams in fixed-size chunks and never
loads the whole file into memory.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import hashlib
from typing import BinaryIO

_CHUNK = 1024 * 1024  # 1 MiB


def sha256_stream(fileobj: BinaryIO) -> str:
    """Compute the SHA-256 of a binary stream, restoring the read cursor.

    Returns the lowercase hex digest (64 chars).
    """
    pos = fileobj.tell()
    digest = hashlib.sha256()
    for chunk in iter(lambda: fileobj.read(_CHUNK), b""):
        digest.update(chunk)
    fileobj.seek(pos)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return sha256_stream(fh)
