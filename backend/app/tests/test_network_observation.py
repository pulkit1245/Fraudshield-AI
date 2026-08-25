import pytest
from unittest.mock import patch, MagicMock
from app.dynamic_analysis.network_capture import AdbNetworkObserver, _decode_ip, NetworkObservationError
from app.dynamic_analysis.sandbox_manager import _parse_logcat

def test_proc_net_parsing():
    """Verify hexadecimal IP and port decoding from /proc/net/tcp fixtures."""
    # 0100007F:1092 = 127.0.0.1 : 4242
    # 00000000:0000 = 0.0.0.0 : 0
    # UID = 10123
    tcp_fixture = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:1092 0100007F:1092 01 00000000:00000000 00:00000000 00000000 10123        0 35787 1 0000000000000000 100 0 0 10 0\n"
        "   1: 0100007F:1092 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10123        0 35787 1 0000000000000000 100 0 0 10 0\n"
        "   2: 0100007F:1092 B410A8C0:0050 01 00000000:00000000 00:00000000 00000000 10123        0 35787 1 0000000000000000 100 0 0 10 0\n"
    )
    
    # B410A8C0 -> C0.A8.10.B4 -> 192.168.16.180
    # 0050 -> 80

    observer = AdbNetworkObserver("emulator-5554", "com.test")
    observer.uid = 10123
    observer._success = True
    observer._parse_and_attribute(tcp_fixture, "tcp")
    
    calls = observer.calls
    assert len(calls) == 2  # The second line has 00000000:0000 as rem_address (listening), so it should be skipped.
    
    # Check 127.0.0.1:4242
    assert {"host": "127.0.0.1", "port": 4242, "protocol": "tcp", "sink": False} in [ {k:v for k,v in c.items() if k != "ts"} for c in calls ]
    
    # Check 192.168.16.180:80
    assert {"host": "192.168.16.180", "port": 80, "protocol": "tcp", "sink": False} in [ {k:v for k,v in c.items() if k != "ts"} for c in calls ]

def test_uid_attribution():
    """Verify sockets belonging to other UIDs are discarded."""
    tcp_fixture = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:1092 0100007F:1092 01 00000000:00000000 00:00000000 00000000  9999        0 35787 1 0000000000000000 100 0 0 10 0\n"
        "   1: 0100007F:1092 B410A8C0:0050 01 00000000:00000000 00:00000000 00000000 10123        0 35787 1 0000000000000000 100 0 0 10 0\n"
    )
    
    observer = AdbNetworkObserver("emulator-5554", "com.test")
    observer.uid = 10123
    observer._success = True
    observer._parse_and_attribute(tcp_fixture, "tcp")
    
    calls = observer.calls
    assert len(calls) == 1
    assert calls[0]["host"] == "192.168.16.180"

@patch("subprocess.run")
def test_observer_failure_not_reported_as_empty_success(mock_run):
    """If /proc/net/* fails or ADB fails, observed_network_calls must be None, not []"""
    # 1. Mock _get_uid to return a valid UID so we actually try polling
    observer = AdbNetworkObserver("emulator-5554", "com.test", duration=1)
    
    # 2. Make the subprocess.run fail when trying to read /proc/net/tcp
    import subprocess
    def side_effect(*args, **kwargs):
        if "-U" in args[0]:
            return MagicMock(stdout="package:com.test uid:10123\n")
        raise subprocess.CalledProcessError(1, cmd=args[0], stderr="Permission denied")
    
    mock_run.side_effect = side_effect
    
    with observer:
        import time
        time.sleep(1.5) # let the thread finish
        
    assert observer.calls is None

def test_legacy_logcat_preservation():
    """Verify _parse_logcat() produces exactly the same legacy behavior."""
    logcat_fixture = (
        "10-24 10:14:11.234 10123 10123 I ActivityManager: START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x10200000 cmp=MyApp/.MainActivity} from uid 2000\n"
        "10-24 10:14:12.000 10123 10123 D MyApp: volley connect to https://evil-c2.com:443\n"
        "10-24 10:14:12.500 10123 10123 W System: SYSTEM_ALERT_WINDOW permission granted\n"
    )
    
    flags, network_calls, events = _parse_logcat(logcat_fixture, "com.test")
    
    assert flags["overlay_detected"] is True
    assert flags["sms_access"] is False
    assert flags["accessibility_abuse"] is False
    
    assert len(network_calls) == 1
    assert network_calls[0]["host"] == "evil-c2.com"
    assert network_calls[0]["port"] == 443
    assert network_calls[0]["sink"] is False

    assert len(events) == 2
