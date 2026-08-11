"""Regression tests for the VirusTotal secret handling + failure caching.

Background: VT silently returned `not_configured` for every submission because
infra/docker-compose.yml injected an empty VIRUSTOTAL_API_KEY (via
`${VIRUSTOTAL_API_KEY:-}`, which interpolates from the shell / infra/.env — not
from the repo-root .env) that shadowed the real value. These tests pin the
service-side guards that make such a misconfiguration loud and recoverable.
"""
from __future__ import annotations

import pytest

from app.services.virustotal_service import (
    _CACHEABLE,
    _VT_KEY_RE,
    _clean_secret,
)

KEY = "a" * 64


class TestCleanSecret:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            (KEY, KEY),
            (f"{KEY}   ", KEY),
            # The .env footgun: a trailing comment glued onto the value.
            (f"{KEY}        # Member C — hash cross-check", KEY),
            (f"{KEY}\t# note", KEY),
            # Quotes survive some env parsers but not others.
            (f'"{KEY}"', KEY),
            (f"'{KEY}'", KEY),
            # Key never set, only a comment on the line -> treat as unset.
            ("   # Member B — LLM orchestration", ""),
            ("", ""),
            (None, ""),
            # A '#' not preceded by whitespace is part of the secret.
            ("abc#def", "abc#def"),
        ],
    )
    def test_normalises(self, raw, expected):
        assert _clean_secret(raw) == expected

    def test_comment_stripped_key_is_still_valid_shape(self):
        assert _VT_KEY_RE.match(_clean_secret(f"{KEY}   # trailing"))


class TestFailureCaching:
    """Transient failures must not be pinned in Redis for 24h."""

    @pytest.mark.parametrize("status", ["ok", "not_found"])
    def test_real_verdicts_are_cached(self, status):
        assert status in _CACHEABLE

    @pytest.mark.parametrize(
        "status", ["not_configured", "invalid_key", "quota_exceeded", "error"]
    )
    def test_failures_are_not_cached(self, status):
        assert status not in _CACHEABLE
