"""AVD / emulator pool with remote-ADB support.

Two modes of operation:
  1. LOCAL  (default): launches the Android emulator binary on this host.
     Requires ADB_BIN + EMULATOR_BIN on PATH (or via env vars).
  2. REMOTE (SANDBOX_ADB_HOST set): connects to an already-running emulator
     via ADB-over-TCP. Used when the Celery worker runs inside Docker and the
     emulator runs on the host Mac — set
       SANDBOX_ADB_HOST=host.docker.internal:5555
     and the worker will `adb connect` to it instead of launching its own VM.

In both modes, network egress is hardened immediately after connection
(wifi+data disabled) so the sample cannot reach real C2 servers.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field

from app.core.logging import get_logger

log = get_logger(__name__)

ADB_BIN       = os.getenv("ADB_BIN",      "adb")
EMULATOR_BIN  = os.getenv("EMULATOR_BIN", "emulator")
POOL_SIZE     = int(os.getenv("SANDBOX_POOL_SIZE", "1"))
BOOT_TIMEOUT  = int(os.getenv("SANDBOX_BOOT_TIMEOUT", "180"))

# When set, skip launching a local emulator and connect to this remote ADB host.
# Example: SANDBOX_ADB_HOST=host.docker.internal:5555
SANDBOX_ADB_HOST: str | None = os.getenv("SANDBOX_ADB_HOST")


@dataclass
class EmulatorInstance:
    serial:       str   # e.g. "emulator-5554" or "host.docker.internal:5555"
    avd_name:     str
    console_port: int
    remote:       bool  = field(default=False)


def is_available() -> bool:
    """True when ADB is reachable — either local binary or remote TCP host."""
    if SANDBOX_ADB_HOST:
        # Remote mode: just need adb binary to talk to the remote device.
        return shutil.which(ADB_BIN) is not None
    return shutil.which(ADB_BIN) is not None and shutil.which(EMULATOR_BIN) is not None


class EmulatorPool:
    """Thread-safe pool of emulator instances (local or remote)."""

    def __init__(self, avd_name: str | None = None, size: int = POOL_SIZE) -> None:
        self.avd_name  = avd_name or os.getenv("SANDBOX_AVD", "fraudshield_avd")
        self.size      = size
        self._available: "queue.Queue[EmulatorInstance]" = queue.Queue()
        self._lock     = threading.Lock()
        self._started  = False

    # ── lifecycle ─────────────────────────────────────────────────────────
    def warm_up(self) -> bool:
        """Boot or connect to emulator(s). Returns True on success."""
        if not is_available():
            log.warning("emulator.unavailable")
            return False
        with self._lock:
            if self._started:
                return True
            if SANDBOX_ADB_HOST:
                ok = self._connect_remote(SANDBOX_ADB_HOST)
            else:
                ok = self._boot_local()
            self._started = self._available.qsize() > 0
            return ok

    # ── remote-ADB path ───────────────────────────────────────────────────
    def _connect_remote(self, host: str) -> bool:
        """Connect to an already-running emulator over TCP ADB."""
        log.info("emulator.remote_connect", host=host)
        try:
            result = subprocess.run(
                [ADB_BIN, "connect", host],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout.strip()
            log.info("emulator.adb_connect_result", output=output)
            if "connected" not in output.lower() and "already connected" not in output.lower():
                log.warning("emulator.remote_connect_failed", output=output)
                return False

            inst = EmulatorInstance(
                serial=host, avd_name="remote", console_port=0, remote=True
            )
            # Wait until device is online and booted.
            self._wait_for_boot(host)
            self._harden_network(inst)
            self._available.put(inst)
            log.info("emulator.remote_ready", serial=host)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("emulator.remote_connect_error", error=str(exc))
            return False

    # ── local-emulator path ───────────────────────────────────────────────
    def _boot_local(self) -> bool:
        for i in range(self.size):
            port = 5554 + i * 2
            inst = self._boot_one(port)
            if inst:
                self._harden_network(inst)
                self._available.put(inst)
        return self._available.qsize() > 0

    def _boot_one(self, console_port: int) -> EmulatorInstance | None:
        try:
            subprocess.Popen(
                [EMULATOR_BIN, "-avd", self.avd_name,
                 "-port", str(console_port),
                 "-no-window", "-no-audio", "-no-boot-anim", "-wipe-data",
                 "-dns-server", "10.0.2.15",   # fake-DNS sink — no real egress
                 "-no-snapshot-save"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            serial = f"emulator-{console_port}"
            self._wait_for_boot(serial)
            log.info("emulator.booted", serial=serial)
            return EmulatorInstance(
                serial=serial, avd_name=self.avd_name, console_port=console_port
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("emulator.boot_failed", port=console_port, error=str(exc))
            return None

    # ── boot polling ──────────────────────────────────────────────────────
    def _wait_for_boot(self, serial: str) -> None:
        deadline = time.time() + BOOT_TIMEOUT
        log.info("emulator.waiting_boot", serial=serial, timeout=BOOT_TIMEOUT)
        while time.time() < deadline:
            out = subprocess.run(
                [ADB_BIN, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                capture_output=True, text=True, timeout=10,
            )
            if out.stdout.strip() == "1":
                log.info("emulator.boot_complete", serial=serial)
                return
            time.sleep(3)
        raise TimeoutError(f"{serial} did not finish booting within {BOOT_TIMEOUT}s")

    # ── network hardening ─────────────────────────────────────────────────
    def _harden_network(self, inst: EmulatorInstance) -> None:
        """Disable real data/wifi — sample can only reach the ADB loopback sink."""
        for args in (["svc", "data", "disable"], ["svc", "wifi", "disable"]):
            subprocess.run(
                [ADB_BIN, "-s", inst.serial, "shell", *args],
                capture_output=True, text=True, timeout=10,
            )
        log.info("emulator.network_hardened", serial=inst.serial)

    # ── acquire / release ─────────────────────────────────────────────────
    def acquire(self, timeout: int = 180) -> EmulatorInstance:
        if not self._started and not self.warm_up():
            raise RuntimeError("No emulator available (SDK not installed or remote unreachable)")
        return self._available.get(timeout=timeout)

    def release(self, inst: EmulatorInstance) -> None:
        if not inst.remote:
            # Wipe installed packages between samples (local only).
            subprocess.run(
                [ADB_BIN, "-s", inst.serial, "shell", "pm", "clear-all"],
                capture_output=True, text=True, timeout=30,
            )
        self._available.put(inst)

    def shutdown(self) -> None:
        while not self._available.empty():
            inst = self._available.get()
            if not inst.remote:
                subprocess.run(
                    [ADB_BIN, "-s", inst.serial, "emu", "kill"],
                    capture_output=True, text=True,
                )
        self._started = False
