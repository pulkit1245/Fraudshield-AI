"""Abstract base class for all TI source fetchers.

Every fetcher must implement ``fetch()`` which yields ``dict`` objects
representing raw source records.  The Normalizer converts these dicts into
``NormalizedTTPRecord`` instances.

Design contract
---------------
- ``fetch()`` must **never raise** — it logs errors and continues.  This
  ensures a partial failure in one source does not abort the entire run.
- ``source_name`` must match a value in ``VALID_SOURCES`` from
  ``app.ti_ingestion.models`` so the Normalizer can route correctly.
- ``last_fetch_key`` is the Redis key used to persist the high-water mark
  (ISO 8601 timestamp of the most recently fetched item).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator


class BaseFetcher(ABC):
    """Protocol that every source adapter must implement."""

    source_name: str          # e.g. "mitre_attack", "misp"
    last_fetch_key: str       # Redis key: "ti:last_fetch:{source_name}"

    #: Set to True by a fetcher when it could not retrieve data (network error,
    #: rejected credentials, source disabled). Because ``fetch()`` must never
    #: raise, an empty generator is otherwise ambiguous — the caller cannot tell
    #: "nothing new upstream" from "the fetch failed". The ingestion task reads
    #: this after draining the generator and, when set, leaves the high-water
    #: mark untouched so the next run retries the same window instead of
    #: skipping it forever.
    failed: bool = False

    @abstractmethod
    def fetch(self) -> Iterator[dict]:
        """Yield raw records from the source.

        Each yielded dict must contain at minimum a field the Normalizer
        can use as an ``external_id``.  The exact shape is source-specific;
        the Normalizer handles source-specific parsing.

        This method MUST NOT raise.  Catch all exceptions internally, log
        them with structlog, and yield nothing further if recovery is
        impossible.
        """
        ...
