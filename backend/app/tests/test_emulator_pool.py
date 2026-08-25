"""Tests for the EmulatorPool and its connection modes."""
import pytest
import os
from unittest.mock import patch, MagicMock

from app.dynamic_analysis.emulator_pool import EmulatorPool, EmulatorInstance, is_available

def test_is_available_with_serial(monkeypatch):
    """is_available returns true when ADB is present and SANDBOX_ADB_SERIAL is set."""
    monkeypatch.setenv("SANDBOX_ADB_SERIAL", "emulator-5554")
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/adb" if x == "adb" else None)
    
    assert is_available() is True


def test_warm_up_lazy_evaluates_env_vars(monkeypatch):
    """When SANDBOX_ADB_SERIAL is set in env, it bypasses connect and uses _connect_serial."""
    monkeypatch.setenv("SANDBOX_ADB_SERIAL", "emulator-5554")
    monkeypatch.setattr("app.dynamic_analysis.emulator_pool.is_available", lambda: True)
    
    pool = EmulatorPool(size=1)
    
    with patch.object(pool, "_connect_serial", return_value=True) as mock_connect_serial:
        with patch.object(pool, "_connect_remote") as mock_connect_remote:
            with patch.object(pool, "_boot_local") as mock_boot_local:
                # Force queue to have 1 item so `_started` becomes true
                pool._available.put(EmulatorInstance("emulator-5554", "remote", 0, True))
                
                result = pool.warm_up()
                
                assert result is True
                mock_connect_serial.assert_called_once_with("emulator-5554")
                mock_connect_remote.assert_not_called()
                mock_boot_local.assert_not_called()


def test_connect_serial_success(monkeypatch):
    """_connect_serial correctly instantiates instance and checks boot."""
    pool = EmulatorPool(size=1)
    
    with patch.object(pool, "_wait_for_boot") as mock_wait:
        with patch.object(pool, "_harden_network") as mock_harden:
            result = pool._connect_serial("emulator-5554")
            
            assert result is True
            mock_wait.assert_called_once_with("emulator-5554", remote=True)
            
            # Instance should be in the queue
            assert pool._available.qsize() == 1
            inst = pool._available.get()
            assert inst.serial == "emulator-5554"
            assert inst.remote is True
            mock_harden.assert_called_once_with(inst)

@patch("subprocess.run")
def test_release_cleans_remote_device(mock_run):
    """Ensure that release() runs cleanup even on remote devices, uninstalls 3rd party packages, and clears tmp."""
    mock_out = MagicMock()
    mock_out.stdout = "package:com.malware.test\npackage:org.bad.app\n"
    mock_run.return_value = mock_out

    pool = EmulatorPool(size=1)
    inst = EmulatorInstance("emulator-5554", "remote", 0, True)
    pool.release(inst)

    # 1st call: list packages
    # 2nd call: uninstall com.malware.test
    # 3rd call: uninstall org.bad.app
    # 4th call: rm -rf /data/local/tmp/*
    assert mock_run.call_count == 4
    
    list_cmd = mock_run.call_args_list[0][0][0]
    assert "list" in list_cmd and "-3" in list_cmd

    uninstall1_cmd = mock_run.call_args_list[1][0][0]
    assert "uninstall" in uninstall1_cmd and "com.malware.test" in uninstall1_cmd

    uninstall2_cmd = mock_run.call_args_list[2][0][0]
    assert "uninstall" in uninstall2_cmd and "org.bad.app" in uninstall2_cmd

    rm_cmd = mock_run.call_args_list[3][0][0]
    assert "rm -rf /data/local/tmp/*" in rm_cmd

    # Emulator is put back in pool
    assert pool._available.qsize() == 1

@patch("subprocess.run")
def test_release_cleanup_failure(mock_run):
    """Ensure that if cleanup fails, the emulator is NOT returned to the pool (fail-closed)."""
    mock_run.side_effect = Exception("ADB connection lost")

    pool = EmulatorPool(size=1)
    inst = EmulatorInstance("emulator-5554", "remote", 0, True)
    pool.release(inst)

    # Emulator is NOT put back in pool because it's dirty
    assert pool._available.qsize() == 0
