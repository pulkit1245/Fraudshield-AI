"""Trace which module causes the startup hang."""
import builtins
import socket
import sys

# Patch socket.connect to show all connection attempts
_orig_connect = socket.socket.connect
def _connect(self, addr):
    print(f"[SOCKET.connect] {addr}", flush=True)
    import traceback; traceback.print_stack(limit=6)
    return _orig_connect(self, addr)
socket.socket.connect = _connect

_orig_connect_ex = socket.socket.connect_ex
def _connect_ex(self, addr):
    print(f"[SOCKET.connect_ex] {addr}", flush=True)
    import traceback; traceback.print_stack(limit=6)
    return _orig_connect_ex(self, addr)
socket.socket.connect_ex = _connect_ex

print("[START] importing app.main", flush=True)
from app.main import app
print("[DONE] app imported OK", flush=True)
