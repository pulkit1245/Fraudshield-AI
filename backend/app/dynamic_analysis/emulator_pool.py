"""AVD / Genymotion emulator pool.

Manages a small pool of pre-warmed Android emulators used only to run pre-vetted
research-corpus samples, with ZERO real network egress — every emulator is
configured to route DNS/traffic to an isolated fake-DNS sink (see
`network_capture`). Instances are acquired/released around a single sandbox run.

Requires the Android SDK `emulator` + `adb` on PATH. When they're absent (API
container, CI, judge laptop) `is_available()` is False and the sandbox layer
falls back to replay/simulation mode — a live dynamic run is not judge-safe inside
a hackathon demo window anyway (§ Member C Task 2).

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass

from app.core.logging import get_logger

log = get_logger(__name__)

ADB_BIN = os.getenv("ADB_BIN", "adb")
EMULATOR_BIN = os.getenv("EMULATOR_BIN", "emulator")
POOL_SIZE = int(os.getenv("SANDBOX_POOL_SIZE", "1"))
BOOT_TIMEOUT = 120


@dataclass
class EmulatorInstance:
    serial: str          # e.g. "emulator-5554"
    avd_name: str
    console_port: int


def is_available() -> bool:
    return shutil.which(ADB_BIN) is not None and shutil.which(EMULATOR_BIN) is not None


class EmulatorPool:
    """Thread-safe pool of pre-warmed emulator instances."""

    def __init__(self, avd_name: str | None = None, size: int = POOL_SIZE) -> None:
        self.avd_name = avd_name or os.getenv("SANDBOX_AVD", "fraudshield_avd")
        self.size = size
        self._available: "queue.Queue[EmulatorInstance]" = queue.Queue()
        self._lock = threading.Lock()
        self._started = False

    # ── lifecycle ───────────────────────────────────────────────────────
    def warm_up(self) -> bool:
        """Boot `size` emulators with networking locked down. Returns success."""
        if not is_available():
            log.warning("emulator.unavailable")
            return False
        with self._lock:
            if self._started:
                return True
            for i in range(self.size):
                port = 5554 + i * 2
                inst = self._boot_one(port)
                if inst:
                    self._harden_network(inst)
                    self._available.put(inst)
            self._started = self._available.qsize() > 0
            return self._started

    def _boot_one(self, console_port: int) -> EmulatorInstance | None:
        try:
            subprocess.Popen(
                [EMULATOR_BIN, "-avd", self.avd_name, "-port", str(console_port),
                 "-no-window", "-no-audio", "-no-boot-anim", "-wipe-data",
                 # No real egress: drop the emulated modem's DNS/route to the internet.
                 "-dns-server", "10.0.2.15", "-no-snapshot-save"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            serial = f"emulator-{console_port}"
            self._wait_for_boot(serial)
            log.info("emulator.booted", serial=serial)
            return EmulatorInstance(serial=serial, avd_name=self.avd_name,
                                    console_port=console_port)
        except Exception as exc:  # noqa: BLE001
            log.warning("emulator.boot_failed", port=console_port, error=str(exc))
            return None

    def _wait_for_boot(self, serial: str) -> None:
        deadline = time.time() + BOOT_TIMEOUT
        while time.time() < deadline:
            out = subprocess.run(
                [ADB_BIN, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                capture_output=True, text=True,
            )
            if out.stdout.strip() == "1":
                return
            time.sleep(3)
        raise TimeoutError(f"{serial} did not finish booting")

    def _harden_network(self, inst: EmulatorInstance) -> None:
        """Belt-and-suspenders: disable real data/wifi so only the sink is reachable."""
        for args in (["svc", "data", "disable"], ["svc", "wifi", "disable"]):
            subprocess.run([ADB_BIN, "-s", inst.serial, "shell", *args],
                           capture_output=True, text=True)

    # ── acquire / release ───────────────────────────────────────────────
    def acquire(self, timeout: int = 180) -> EmulatorInstance:
        if not self._started and not self.warm_up():
            raise RuntimeError("No emulator available (SDK not installed)")
        return self._available.get(timeout=timeout)

    def release(self, inst: EmulatorInstance) -> None:
        # Wipe state between samples to prevent cross-contamination.
        subprocess.run([ADB_BIN, "-s", inst.serial, "shell", "pm", "clear-all"],
                       capture_output=True, text=True)
        self._available.put(inst)

    def shutdown(self) -> None:
        while not self._available.empty():
            inst = self._available.get()
            subprocess.run([ADB_BIN, "-s", inst.serial, "emu", "kill"],
                           capture_output=True, text=True)
        self._started = False
