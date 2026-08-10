"""Threat Intelligence ingestion pipeline package.

Entry points
------------
- ``app.ti_ingestion.fetchers.mitre_attack``  — MITRE ATT&CK for Mobile
- ``app.ti_ingestion.normalizer``             — heterogeneous → NormalizedTTPRecord
- ``app.ti_ingestion.validator``              — 11-rule gate
- ``app.ti_ingestion.deduplicator``           — external_id / name collision check
- ``app.ti_ingestion.upsert``                 — PostgreSQL INSERT ON CONFLICT
"""
