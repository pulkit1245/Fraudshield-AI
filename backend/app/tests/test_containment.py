import pytest
from unittest.mock import patch, MagicMock
from app.dynamic_analysis.containment import harden_and_verify, ContainmentError

def _mock_subprocess_run(outputs):
    def side_effect(cmd, **kwargs):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        
        # Determine which command is being mocked
        cmd_str = " ".join(cmd)
        
        if "getprop ro.build.product" in cmd_str:
            mock_result.stdout = "test_device"
        elif "svc data disable" in cmd_str or "svc wifi disable" in cmd_str:
            pass # just mock success
        else:
            # Check which probe is running
            matched_probe = None
            for probe_name in ["ping", "udp", "tcp", "curl", "wget"]:
                if probe_name in cmd_str:
                    matched_probe = probe_name
                    break
                    
            if "ping" in cmd_str:
                mock_result.stdout = outputs.get("icmp", "")
            elif "udp" in cmd_str:
                mock_result.stdout = outputs.get("dns", "")
            elif "tcp" in cmd_str:
                mock_result.stdout = outputs.get("tcp", "")
            elif "curl" in cmd_str or "wget" in cmd_str:
                mock_result.stdout = outputs.get("metadata", "")
                
        return mock_result
    return side_effect

@patch("subprocess.run")
def test_all_probes_blocked_returns_verified(mock_run):
    outputs = {
        "icmp": "100% packet loss",
        "dns": "Connection refused",
        "tcp": "Connection refused",
        "metadata": "HTTP/1.1 404"
    }
    mock_run.side_effect = _mock_subprocess_run(outputs)
    
    report = harden_and_verify("test-serial")
    assert report.verified is True
    assert report.probes["icmp"] == "blocked"
    assert report.probes["tcp"] == "blocked"

@patch("subprocess.run")
def test_one_probe_leaking_raises_error(mock_run):
    outputs = {
        "icmp": "100% packet loss",
        "dns": "Connection refused",
        "tcp": "connected",  # LEAK
        "metadata": "HTTP/1.1 404"
    }
    mock_run.side_effect = _mock_subprocess_run(outputs)
    
    with pytest.raises(ContainmentError, match="network leak detected"):
        harden_and_verify("test-serial")

@patch("subprocess.run")
def test_tcp_inconclusive_but_ping_decisively_blocked_returns_verified(mock_run):
    outputs = {
        "icmp": "100% packet loss",  # Blocked
        "dns": "Connection refused",
        "tcp": "/system/bin/sh: /dev/tcp/1.1.1.1/443: No such file or directory", # Inconclusive
        "metadata": "HTTP/1.1 404"
    }
    mock_run.side_effect = _mock_subprocess_run(outputs)
    
    report = harden_and_verify("test-serial")
    assert report.verified is True
    assert report.probes["tcp"] == "inconclusive"
    assert report.probes["icmp"] == "blocked"

@patch("subprocess.run")
def test_all_probes_inconclusive_raises_error(mock_run):
    outputs = {
        "icmp": "ping: not found",  # Inconclusive
        "dns": "/system/bin/sh: /dev/udp/8.8.8.8/53: No such file or directory",
        "tcp": "/system/bin/sh: /dev/tcp/1.1.1.1/443: No such file or directory",
        "metadata": "curl: not found"
    }
    mock_run.side_effect = _mock_subprocess_run(outputs)
    
    with pytest.raises(ContainmentError, match="unverified: ICMP probe was inconclusive"):
        harden_and_verify("test-serial")
