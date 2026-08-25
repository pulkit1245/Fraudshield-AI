"""Test Phase 2 fail-closed behavior for sandbox execution."""
import uuid
import pytest
from unittest.mock import MagicMock

from app.dynamic_analysis.sandbox_manager import SandboxManager


def test_live_failure_propagates(monkeypatch):
    """A failure in live mode must raise, not fall back to simulated."""
    monkeypatch.setattr(SandboxManager, "_store_log", lambda self, sid, blob: "test_log.json")
    manager = SandboxManager(mode="live")
    monkeypatch.setattr(manager, "_run_live", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("emulator dead")))
    
    with pytest.raises(RuntimeError, match="emulator dead"):
        manager.run(uuid.uuid4(), "/tmp/test.apk", static_hint={})


def test_mobsf_failure_propagates(monkeypatch):
    """A failure in mobsf mode must raise, not fall back to live or simulated."""
    monkeypatch.setattr(SandboxManager, "_store_log", lambda self, sid, blob: "test_log.json")
    manager = SandboxManager(mode="mobsf")
    # Mock MobSF client as available
    manager._mobsf = MagicMock()
    manager._mobsf.is_available = True
    manager._mobsf.analyze.side_effect = RuntimeError("mobsf dead")
    
    with pytest.raises(RuntimeError, match="mobsf dead"):
        manager.run(uuid.uuid4(), "/tmp/test.apk", static_hint={})


def test_explicit_simulate_works(monkeypatch):
    """When simulate mode is explicitly requested, it still works."""
    manager = SandboxManager(mode="simulate")
    result = manager.run(uuid.uuid4(), "/tmp/test.apk", static_hint={"foo": "bar"})
    assert result["mode"] == "simulate"

