"""Network capture against the isolated fake-DNS sink.

The sandbox routes all emulator traffic to a fake-DNS/blackhole sink so nothing
reaches the real internet; every DNS query and outbound connection attempt is
recorded for the report (C2 endpoints, exfil hosts) without ever completing.

`NetworkCapture` runs for the sandbox window and returns a normalized list of
attempts: {host, port, protocol, ts}. Two sources are supported — a UDP DNS sink
(preferred) and `adb logcat` connection-attempt scraping (fallback). Both degrade
to an empty list when the tooling isn't present.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
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
SINK_HOST = os.getenv("FAKE_DNS_HOST", "127.0.0.1")
SINK_PORT = int(os.getenv("FAKE_DNS_PORT", "5353"))

# Matches "connect to host:port" style hints in logcat.
_CONN_RE = re.compile(r"(?:connect(?:ing)?\s+to|Host:)\s+([\w.\-]+)[:/](\d{1,5})",
                      re.IGNORECASE)


class NetworkCapture:
    def __init__(self, serial: str | None = None, duration: int = 60) -> None:
        self.serial = serial
        self.duration = duration
        self._calls: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def __enter__(self) -> "NetworkCapture":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        self._threads = [threading.Thread(target=self._run_dns_sink, daemon=True)]
        if self.serial:
            self._threads.append(threading.Thread(target=self._scrape_logcat, daemon=True))
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)

    # ── DNS sink: record queries, answer with a blackhole address ───────
    def _run_dns_sink(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.bind((SINK_HOST, SINK_PORT))
        except Exception as exc:  # noqa: BLE001
            log.debug("netcap.sink_unavailable", error=str(exc))
            return
        deadline = time.time() + self.duration
        while not self._stop.is_set() and time.time() < deadline:
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except Exception:  # noqa: BLE001
                break
            host = _parse_dns_qname(data)
            if host:
                self._calls.append({
                    "host": host, "port": 53, "protocol": "dns",
                    "ts": time.time(), "sink": True,
                })
        sock.close()

    # ── logcat fallback ─────────────────────────────────────────────────
    def _scrape_logcat(self) -> None:
        try:
            proc = subprocess.Popen(
                [ADB_BIN, "-s", self.serial, "logcat", "-v", "brief"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("netcap.logcat_unavailable", error=str(exc))
            return
        deadline = time.time() + self.duration
        assert proc.stdout is not None
        for line in proc.stdout:
            if self._stop.is_set() or time.time() > deadline:
                break
            m = _CONN_RE.search(line)
            if m:
                self._calls.append({
                    "host": m.group(1), "port": int(m.group(2)),
                    "protocol": "tcp", "ts": time.time(), "sink": True,
                })
        proc.terminate()

    @property
    def calls(self) -> list[dict[str, Any]]:
        # De-duplicate on (host, port).
        seen, unique = set(), []
        for c in self._calls:
            key = (c["host"], c["port"])
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique


def _parse_dns_qname(packet: bytes) -> str | None:
    """Extract the queried name from a raw DNS request packet."""
    try:
        idx = 12  # skip the 12-byte header
        labels = []
        while idx < len(packet):
            length = packet[idx]
            if length == 0:
                break
            labels.append(packet[idx + 1: idx + 1 + length].decode("ascii", "ignore"))
            idx += length + 1
        return ".".join(labels) or None
    except Exception:  # noqa: BLE001
        return None
