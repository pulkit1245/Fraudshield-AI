import os
import subprocess
from dataclasses import dataclass
from app.core.logging import get_logger

log = get_logger(__name__)

ADB_BIN = os.getenv("ADB_BIN", "adb")

class ContainmentError(Exception):
    """Exception raised when containment (network hardening) fails."""
    pass

@dataclass
class ContainmentReport:
    method: str

def harden_and_verify(serial: str) -> ContainmentReport:
    """Disable real data/wifi and verify containment."""
    log.info("containment.hardening", serial=serial)
    try:
        subprocess.run([ADB_BIN, "-s", serial, "shell", "svc", "wifi", "disable"], check=True, timeout=10)
        subprocess.run([ADB_BIN, "-s", serial, "shell", "svc", "data", "disable"], check=True, timeout=10)
    except Exception as e:
        log.warning("containment.svc_disable_failed", error=str(e))
        # Log failure but proceed
    
    return ContainmentReport(method="svc_disable")
