"""Manual smoke check for SandboxManager's *simulate* path.

NOT a pytest test, despite its former name (`backend/test_sandbox.py`). It has no
test functions and no assertions — it prints a result for a human to eyeball.

Why it was moved out of `test_*.py` shape:

    Under its old name pytest collected it, and because every statement sat at
    module level, *collection alone* executed `SandboxManager._run_simulated()`,
    which reaches `_store_log` (`app/dynamic_analysis/sandbox_manager.py:218-227`)
    and calls `storage.upload_artifact(...)`. So merely running the test suite
    fabricated a simulated sandbox run and wrote a log artifact. `storage` is a
    module-level singleton from `file_storage._build_storage()`, which returns
    `S3Storage` whenever STORAGE_KEY and STORAGE_SECRET are both set — so once
    real credentials are populated, that write becomes a live `put_object`
    against the production object store.

Everything is now behind `if __name__ == "__main__":`, so importing this module
does nothing. Running it deliberately still performs a real storage write.

Usage (from the repo root, inside the backend image):

    docker compose -f infra/docker-compose.yml run --rm --no-deps \
        worker-static python scripts/manual_sandbox_check.py

Note this exercises the SIMULATE path only. Simulated findings are fabricated by
design and must never be read as evidence about a sample. It proves the code path
executes; it proves nothing about the sample or about containment.
"""
from __future__ import annotations

import os
import sys

# scripts/ lives one level below the app root, so hop up twice to put the
# directory containing `app/` on the path.
_BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)

from app.dynamic_analysis.sandbox_manager import SandboxManager  # noqa: E402

SAMPLE_SUBMISSION_ID = "12345678-1234-5678-1234-567812345678"

SAMPLE_STATIC_FINDINGS = {
    "api_call_graph": {"sensitive_calls": {"sms": True}},
    "permissions": {"declared": ["android.permission.READ_SMS"]},
}


def main() -> int:
    manager = SandboxManager(mode="simulate")
    print("Testing SandboxManager in simulate mode...")
    try:
        result = manager._run_simulated(SAMPLE_SUBMISSION_ID, SAMPLE_STATIC_FINDINGS)
    except Exception as exc:  # noqa: BLE001 — this is a human-facing smoke check
        print(f"Error: {exc}")
        return 1
    print(f"Result: {result}")
    print("SUCCESS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
