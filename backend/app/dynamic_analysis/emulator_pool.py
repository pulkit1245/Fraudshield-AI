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
import pathlib
import queue
import shutil
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass, field

from app.core.logging import get_logger

log = get_logger(__name__)

ADB_BIN       = os.getenv("ADB_BIN",      "adb")
EMULATOR_BIN  = os.getenv("EMULATOR_BIN", "emulator")
POOL_SIZE     = int(os.getenv("SANDBOX_POOL_SIZE", "1"))
BOOT_TIMEOUT  = int(os.getenv("SANDBOX_BOOT_TIMEOUT", "180"))
# Remote devices are already running, so they need far less than a cold boot —
# but 10s is too tight for a busy emulator and produced spurious timeouts.
REMOTE_BOOT_TIMEOUT = int(os.getenv("SANDBOX_REMOTE_BOOT_TIMEOUT", "90"))

# ── frida-server bootstrap ────────────────────────────────────────────────────
# Downloaded once per container lifetime and cached at this path.
# Failure is NON-FATAL — live analysis continues with logcat fallback.
FRIDA_SERVER_CACHE_DIR = pathlib.Path(os.getenv("FRIDA_SERVER_CACHE", "/tmp/frida_server_cache"))

# Android ABI  →  frida release arch suffix
_ABI_TO_FRIDA_ARCH: dict[str, str] = {
    "arm64-v8a":  "android-arm64",
    "armeabi-v7a": "android-arm",
    "x86_64":     "android-x86_64",
    "x86":        "android-x86",
}

@dataclass
class EmulatorInstance:
    serial:       str   # e.g. "emulator-5554" or "host.docker.internal:5555"
    avd_name:     str
    console_port: int
    remote:       bool  = field(default=False)


def is_available() -> bool:
    """True when ADB is reachable — either local binary or remote TCP host."""
    if os.getenv("SANDBOX_ADB_HOST") or os.getenv("SANDBOX_ADB_SERIAL"):
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
            sandbox_adb_serial = os.getenv("SANDBOX_ADB_SERIAL")
            sandbox_adb_host = os.getenv("SANDBOX_ADB_HOST")
            if sandbox_adb_serial:
                ok = self._connect_serial(sandbox_adb_serial)
            elif sandbox_adb_host:
                ok = self._connect_remote(sandbox_adb_host)
            else:
                ok = self._boot_local()
            self._started = self._available.qsize() > 0
            return ok

    # ── remote-ADB path ───────────────────────────────────────────────────
    def _connect_serial(self, serial: str) -> bool:
        """Connect to an already-multiplexed emulator via an existing ADB server."""
        log.info("emulator.remote_serial", serial=serial)
        inst = EmulatorInstance(
            serial=serial, avd_name="remote", console_port=0, remote=True
        )
        try:
            self._wait_for_boot(serial, remote=True)
            self._harden_network(inst)
            self._available.put(inst)
            log.info("emulator.remote_serial_ready", serial=serial)
            return True
        except Exception as exc:  # noqa: BLE001
            from app.dynamic_analysis.containment import ContainmentError
            if isinstance(exc, ContainmentError):
                raise
            log.warning("emulator.serial_connect_error", error=str(exc))
            return False
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
            if "failed to authenticate" in output.lower():
                log.warning(
                    "emulator.unauthorized",
                    host=host,
                    hint="Accept the 'Allow USB debugging?' prompt on the "
                         "emulator and tick 'Always allow from this computer', "
                         "then re-run. The worker's ADB public key must be in "
                         "the device's /data/misc/adb/adb_keys.",
                )
                return False
            if "connected" not in output.lower() and "already connected" not in output.lower():
                log.warning("emulator.remote_connect_failed", output=output)
                return False

            inst = EmulatorInstance(
                serial=host, avd_name="remote", console_port=0, remote=True
            )
            # Wait until device is online and booted.
            self._wait_for_boot(host, remote=True)
            self._harden_network(inst)
            self._available.put(inst)
            log.info("emulator.remote_ready", serial=host)
            return True
        except Exception as exc:  # noqa: BLE001
            from app.dynamic_analysis.containment import ContainmentError
            if isinstance(exc, ContainmentError):
                raise
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
            from app.dynamic_analysis.containment import ContainmentError
            if isinstance(exc, ContainmentError):
                raise
            log.warning("emulator.boot_failed", port=console_port, error=str(exc))
            return None

    # ── boot polling ──────────────────────────────────────────────────────
    def _wait_for_boot(self, serial: str, remote: bool = False) -> None:
        timeout = REMOTE_BOOT_TIMEOUT if remote else BOOT_TIMEOUT
        deadline = time.time() + timeout
        log.info("emulator.waiting_boot", serial=serial, timeout=timeout)
        while time.time() < deadline:
            out = subprocess.run(
                [ADB_BIN, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                capture_output=True, text=True, timeout=5,
            )
            if out.stdout.strip() == "1":
                log.info("emulator.boot_complete", serial=serial)
                return

            # An unauthorized device never answers getprop, so polling would
            # burn the whole timeout and then report a misleading "did not
            # finish booting". Detect it and say what actually needs doing:
            # accept the "Allow USB debugging?" prompt on the emulator.
            combined = f"{out.stdout} {out.stderr}".lower()
            if "unauthorized" in combined:
                raise RuntimeError(
                    f"{serial} is connected but UNAUTHORIZED — accept the "
                    f"'Allow USB debugging?' prompt on the emulator (tick "
                    f"'Always allow from this computer'). The worker's ADB key "
                    f"is not in the device's adb_keys."
                )

            # Fail fast if device is entirely unreachable for a remote connection
            if remote and "device offline" in out.stderr.lower():
                break

            time.sleep(2)
        raise TimeoutError(f"{serial} did not finish booting within {timeout}s")

    def _harden_network(self, inst: EmulatorInstance) -> None:
        """Disable real data/wifi and verify containment."""
        from app.dynamic_analysis.containment import harden_and_verify
        report = harden_and_verify(inst.serial)
        log.info("emulator.network_hardened", serial=inst.serial, method=report.method)
        # Bootstrap frida-server AFTER network hardening so the emulator is
        # fully ready.  Failure here is intentionally non-fatal.
        self._bootstrap_frida(inst.serial)

    # ── frida-server bootstrap ─────────────────────────────────────────────
    def _bootstrap_frida(self, serial: str) -> None:
        """Push and start frida-server on the emulator.  NON-FATAL.

        Strategy:
        1. If frida-server is already running, skip.
        2. Detect the emulator ABI (arm64-v8a, x86_64, …).
        3. Resolve the matching frida-server binary from FRIDA_SERVER_CACHE_DIR
           (pre-placed by the operator) or download it from GitHub Releases for
           the version that matches the installed frida Python package.
        4. Push via ADB, chmod 755, start in background with nohup.
        5. Any failure logs a WARNING and returns — the sandbox continues with
           the logcat fallback; no exception is propagated.
        """
        from app.dynamic_analysis.frida_hooks import is_frida_server_running

        try:
            # ── 1. Already running? ──────────────────────────────────────
            if is_frida_server_running(serial, ADB_BIN):
                log.info("frida.server_already_running", serial=serial)
                return

            # ── 2. Detect ABI ────────────────────────────────────────────
            abi_out = subprocess.run(
                [ADB_BIN, "-s", serial, "shell", "getprop", "ro.product.cpu.abi"],
                capture_output=True, text=True, timeout=10,
            )
            abi = abi_out.stdout.strip()
            frida_arch = _ABI_TO_FRIDA_ARCH.get(abi)
            if not frida_arch:
                log.warning(
                    "frida.bootstrap_skip",
                    reason=f"unsupported ABI: {abi!r}",
                    serial=serial,
                )
                return

            # ── 3. Resolve binary ────────────────────────────────────────
            try:
                import frida as _frida_pkg
                frida_version = _frida_pkg.__version__
            except ImportError:
                log.warning("frida.bootstrap_skip",
                            reason="frida Python package not installed",
                            serial=serial)
                return

            binary_name = f"frida-server-{frida_version}-{frida_arch}"
            FRIDA_SERVER_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            local_path = FRIDA_SERVER_CACHE_DIR / binary_name

            if not local_path.exists():
                # Try downloading from GitHub Releases (compressed .xz)
                xz_name   = binary_name + ".xz"
                xz_path   = FRIDA_SERVER_CACHE_DIR / xz_name
                url = (
                    f"https://github.com/frida/frida/releases/download/"
                    f"{frida_version}/{xz_name}"
                )
                log.info("frida.server_download", url=url, dest=str(xz_path))
                try:
                    urllib.request.urlretrieve(url, str(xz_path))
                    # Decompress .xz  (lzma is stdlib)
                    import lzma
                    with lzma.open(str(xz_path)) as f_in, \
                         open(str(local_path), "wb") as f_out:
                        f_out.write(f_in.read())
                    xz_path.unlink(missing_ok=True)
                    log.info("frida.server_downloaded", path=str(local_path))
                except Exception as dl_exc:  # noqa: BLE001
                    log.warning(
                        "frida.server_download_failed",
                        url=url,
                        error=str(dl_exc),
                        serial=serial,
                        hint="Pre-place frida-server binary in FRIDA_SERVER_CACHE dir "
                             "or ensure the worker container has internet access. "
                             "Live sandbox will fall back to logcat analysis.",
                    )
                    return

            # ── 4. Push, chmod, start ────────────────────────────────────
            device_path = f"/data/local/tmp/{binary_name}"
            push = subprocess.run(
                [ADB_BIN, "-s", serial, "push", str(local_path), device_path],
                capture_output=True, text=True, timeout=60,
            )
            if push.returncode != 0:
                log.warning("frida.server_push_failed",
                            stderr=push.stderr.strip(), serial=serial)
                return

            subprocess.run(
                [ADB_BIN, "-s", serial, "shell", "chmod", "755", device_path],
                capture_output=True, timeout=10,
            )
            # Start in background — nohup + redirect stdout/stderr to /dev/null
            subprocess.Popen(
                [ADB_BIN, "-s", serial, "shell",
                 f"nohup {device_path} > /dev/null 2>&1 &"],
            )
            # Give it a moment to start
            time.sleep(1)

            # ── 5. Verify it's up ────────────────────────────────────────
            if is_frida_server_running(serial, ADB_BIN):
                log.info("frida.server_started", serial=serial,
                         version=frida_version, arch=frida_arch)
            else:
                log.warning("frida.server_start_unconfirmed", serial=serial,
                            hint="frida-server may still be starting; "
                                 "FridaRunner will retry on attach.")

        except Exception as exc:  # noqa: BLE001
            log.warning(
                "frida.bootstrap_failed",
                serial=serial,
                error=str(exc),
                hint="Live sandbox will use logcat fallback for behaviour detection.",
            )

    # ── acquire / release ─────────────────────────────────────────────────
    def acquire(self, timeout: int = 180) -> EmulatorInstance:
        if not self._started and not self.warm_up():
            raise RuntimeError("No emulator available (SDK not installed or remote unreachable)")
        return self._available.get(timeout=timeout)

    def release(self, inst: EmulatorInstance) -> None:
        try:
            # 1. Enumerate and uninstall 3rd party packages
            out = subprocess.run(
                [ADB_BIN, "-s", inst.serial, "shell", "pm", "list", "packages", "-3"],
                capture_output=True, text=True, timeout=15, check=True
            )
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    pkg = line.split(":", 1)[1]
                    subprocess.run(
                        [ADB_BIN, "-s", inst.serial, "shell", "pm", "uninstall", pkg],
                        capture_output=True, text=True, timeout=15, check=True
                    )
            
            # 2. Clean /data/local/tmp/*
            subprocess.run(
                [ADB_BIN, "-s", inst.serial, "shell", "rm -rf /data/local/tmp/*"],
                capture_output=True, text=True, timeout=15, check=True
            )
        except Exception as exc:
            log.error("emulator.cleanup_failed", serial=inst.serial, error=str(exc))
            # Fail closed: Do NOT return a dirty emulator to the pool.
            return
            
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
