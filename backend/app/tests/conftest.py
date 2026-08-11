"""Shared pytest fixtures for the backend test suite.

Test isolation from live infrastructure
---------------------------------------
``app.ti_ingestion.fallback_reporter.emit_fallback()`` writes to
``settings.REDIS_URL``, which defaults to ``redis://localhost:6379/0``.
``infra/docker-compose.yml`` publishes Redis on host port 6379, so when the
stack is up, a plain ``pytest`` run on the host connects to the *production*
Redis and pushes events into ``ti:fallback_events`` — the exact list the admin
TI Pipeline dashboard reads.

Two existing tests reach that code path with no network or DB involved:

  * ``test_ti_normalizer.py::test_unknown_tactic_defaults_to_reconnaissance``
    normalizes a STIX object whose tactic is ``totally-unknown-tactic``.
  * ``test_ti_bazaar_otx.py::test_fetcher_skips_when_no_api_key``
    calls the OTX fetcher with ``OTX_API_KEY`` forced empty.

Both emit real fallback events, so the dashboard reports pipeline degradation
that never happened. The autouse fixture below redirects ``emit_fallback`` to
an in-memory list for the duration of every test.

Owner: shared test infrastructure.
"""
from __future__ import annotations

import pytest

# Modules that do `from app.ti_ingestion.fallback_reporter import emit_fallback`.
# The name is bound into each importing module's namespace, so patching only the
# source module would not intercept those call sites — each binding is patched.
_EMIT_FALLBACK_CALL_SITES = (
    "app.ti_ingestion.normalizer",
    "app.ti_ingestion.fetchers.otx",
    "app.ti_ingestion.fetchers.mitre_attack",
    "app.ti_ingestion.fallback_reporter",
)


@pytest.fixture(autouse=True)
def captured_fallbacks(monkeypatch):
    """Prevent tests from writing into the live ``ti:fallback_events`` list.

    Yields the list of captured events so a test can assert on fallback
    behaviour without touching Redis::

        def test_unknown_tactic_reports(captured_fallbacks):
            ...
            assert captured_fallbacks[0]["source"] == "mitre_attack"
    """
    recorded: list[dict] = []

    def _capture(**kwargs) -> None:
        recorded.append(kwargs)

    for module_path in _EMIT_FALLBACK_CALL_SITES:
        try:
            monkeypatch.setattr(f"{module_path}.emit_fallback", _capture)
        except (AttributeError, ImportError):
            # Module absent or no longer imports the symbol — nothing to patch.
            continue

    return recorded
