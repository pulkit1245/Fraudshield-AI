"""Embeddings for the fraud-TTP retrieval step.

Produces 768-dim vectors (matching the pgvector `VECTOR(768)` columns in §4). The
default backend is a deterministic, offline hashing embedding so RAG works with
no external API or model download — good enough for retrieving from the small
curated TTP knowledge base and fully reproducible in CI. A real embedding
provider (e.g. sentence-transformers) can be dropped in behind the same API.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import hashlib
import re

import numpy as np

EMBED_DIM = 768
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    text = (text or "").lower()
    toks = _TOKEN_RE.findall(text)
    # Add char-trigrams for short/OOV robustness.
    trigrams = [text[i:i + 3] for i in range(max(0, len(text) - 2))]
    return toks + trigrams


def _hash_index(token: str) -> tuple[int, float]:
    digest = hashlib.md5(token.encode("utf-8")).digest()
    idx = int.from_bytes(digest[:4], "big") % EMBED_DIM
    sign = 1.0 if digest[4] & 1 else -1.0
    return idx, sign


def embed_text(text: str) -> np.ndarray:
    """Deterministic hashing embedding → L2-normalized 768-dim vector."""
    vec = np.zeros(EMBED_DIM, dtype=np.float64)
    for tok in _tokens(text):
        idx, sign = _hash_index(tok)
        vec[idx] += sign
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


def embed_texts(texts: list[str]) -> np.ndarray:
    if not texts:
        return np.zeros((0, EMBED_DIM), dtype=np.float64)
    return np.vstack([embed_text(t) for t in texts])


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    denom = (np.linalg.norm(a) * np.linalg.norm(b)) + 1e-12
    return float(np.dot(a, b) / denom)
