import os
import re
import subprocess
from dataclasses import dataclass
import structlog

log = structlog.get_logger(__name__)

ADB_BIN = os.getenv("ADB_BIN", "adb")

class ContainmentError(Exception):
    """Raised when sandbox network containment is demonstrably leaking or cannot be verified."""
    pass

@dataclass
class ContainmentReport:
    verified: bool
    method: str
    target: str
    probes: dict[str, str]

def harden_and_verify(serial: str) -> ContainmentReport:
    """
    Disable network routing best-effort and empirically verify the sandbox is contained.
    """
    # 1. Best-effort in-guest hardening
    for args in (["svc", "data", "disable"], ["svc", "wifi", "disable"]):
        subprocess.run(
            [ADB_BIN, "-s", serial, "shell", *args],
            capture_output=True, text=True, timeout=10,
        )
    
    # 2. Empirical probes
    # Target strings for the success regex (which means the network is leaking)
    LEAK_REGEX = re.compile(r"(1 received|bytes from|succeeded|connected|HTTP/)(\s|$)", re.IGNORECASE)
    
    # Shell errors indicating the test itself failed to run (inconclusive)
    INCONCLUSIVE_REGEX = re.compile(r"(not found|No such file|can't open|bad address)", re.IGNORECASE)
    
    probes = {
        "icmp": "ping -c 1 -W 2 8.8.8.8",
        "dns": "echo '' > /dev/udp/8.8.8.8/53 && echo 'succeeded'", # Simple attempt to open UDP socket
        "tcp": "echo '' > /dev/tcp/1.1.1.1/443 && echo 'connected'",
        "metadata": "curl -s -m 2 http://169.254.169.254/ || wget -q -T 2 -O- http://169.254.169.254/ || echo 'HTTP/1.1 404'"
    }
    
    results = {}
    leak_detected = False
    icmp_blocked = False
    
    for name, cmd in probes.items():
        out = subprocess.run(
            [ADB_BIN, "-s", serial, "shell", cmd],
            capture_output=True, text=True, timeout=10
        )
        combined = f"{out.stdout} {out.stderr}".strip()
        
        if LEAK_REGEX.search(combined):
            results[name] = "leaking"
            leak_detected = True
        elif INCONCLUSIVE_REGEX.search(combined):
            results[name] = "inconclusive"
        else:
            results[name] = "blocked"
            if name == "icmp":
                icmp_blocked = True
                
    if leak_detected:
        raise ContainmentError("Sandbox containment failed: network leak detected. " + str(results))
        
    if not icmp_blocked:
        raise ContainmentError("Sandbox containment unverified: ICMP probe was inconclusive, cannot guarantee containment. " + str(results))
        
    # Get target name for report
    out = subprocess.run(
        [ADB_BIN, "-s", serial, "shell", "getprop", "ro.build.product"],
        capture_output=True, text=True, timeout=5
    )
    target = out.stdout.strip() or "unknown"
    
    return ContainmentReport(
        verified=True,
        method="in_guest_svc",
        target=target,
        probes=results
    )
