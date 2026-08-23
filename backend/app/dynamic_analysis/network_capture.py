"""Network observation via ADB /proc/net polling.

Replaces the legacy container-loopback capture.
Polls /proc/net/tcp, tcp6, and udp over adb shell to observe
kernel-level socket creations attributed to the sample's UID.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import threading
import time
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

ADB_BIN = os.getenv("ADB_BIN", "adb")

class NetworkObservationError(Exception):
    pass

class AdbNetworkObserver:
    def __init__(self, serial: str, package_name: str, duration: int = 60) -> None:
        self.serial = serial
        self.package_name = package_name
        self.duration = duration
        self._calls: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.uid: int | None = None
        self.error: str | None = None
        self._success = False

    def __enter__(self) -> "AdbNetworkObserver":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        try:
            self.uid = self._get_uid()
            if self.uid is None:
                log.warning("netobs.uid_not_found", package=self.package_name)
                # We can't filter by UID if we don't have one, but we still run
                # to catch if there's any ADB failure.
        except Exception as exc:
            self.error = f"Failed to get UID: {exc}"
            log.error("netobs.uid_error", error=str(exc))
            return

        self._thread = threading.Thread(target=self._poll_proc_net, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _get_uid(self) -> int | None:
        """Resolve the package name to an Android UID using pm list packages -U."""
        out = subprocess.run(
            [ADB_BIN, "-s", self.serial, "shell", "pm", "list", "packages", "-U"],
            capture_output=True, text=True, timeout=10, check=True
        )
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:" + self.package_name + " "):
                m = re.search(r"uid:(\d+)", line)
                if m:
                    return int(m.group(1))
        return None

    def _poll_proc_net(self) -> None:
        deadline = time.time() + self.duration
        poll_interval = 1.0

        self._success = True
        try:
            while not self._stop.is_set() and time.time() < deadline:
                for proto in ["tcp", "tcp6", "udp"]:
                    try:
                        out = subprocess.run(
                            [ADB_BIN, "-s", self.serial, "shell", f"cat /proc/net/{proto}"],
                            capture_output=True, text=True, timeout=15, check=True
                        )
                        self._parse_and_attribute(out.stdout, proto)
                    except subprocess.CalledProcessError as exc:
                        raise NetworkObservationError(f"Failed to read /proc/net/{proto}: {exc.stderr}") from exc
                
                time.sleep(poll_interval)

        except Exception as exc:
            self._success = False
            self.error = str(exc)
            log.error("netobs.poll_error", error=self.error)

    def _parse_and_attribute(self, proc_net_output: str, protocol: str) -> None:
        if self.uid is None:
            return

        lines = proc_net_output.strip().splitlines()
        if not lines:
            return

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 8:
                continue
            
            local_addr = parts[1]
            rem_addr = parts[2]
            uid_str = parts[7]

            try:
                socket_uid = int(uid_str)
            except ValueError:
                continue

            if socket_uid != self.uid:
                continue

            rem_ip_hex, rem_port_hex = rem_addr.split(":")
            
            # Skip listening sockets (0.0.0.0 or ::)
            if all(c == '0' for c in rem_ip_hex):
                continue

            rem_ip = _decode_ip(rem_ip_hex)
            rem_port = int(rem_port_hex, 16)

            self._calls.append({
                "host": rem_ip,
                "port": rem_port,
                "protocol": "udp" if protocol == "udp" else "tcp",
                "ts": time.time(),
                "sink": False
            })

    @property
    def calls(self) -> list[dict[str, Any]] | None:
        """Returns the deduplicated network observations, or None if observation failed."""
        if self.error is not None or not self._success:
            return None
        
        seen, unique = set(), []
        for c in self._calls:
            key = (c["host"], c["port"])
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

def _decode_ip(hex_str: str) -> str:
    """Decodes little-endian hex IP address to string."""
    try:
        if len(hex_str) == 8: # IPv4
            b = bytes.fromhex(hex_str)
            return socket.inet_ntoa(b[::-1])
        elif len(hex_str) == 32: # IPv6
            words = [hex_str[i:i+8] for i in range(0, 32, 8)]
            b = b"".join(bytes.fromhex(w)[::-1] for w in words)
            return socket.inet_ntop(socket.AF_INET6, b)
    except Exception:
        pass
    return hex_str
