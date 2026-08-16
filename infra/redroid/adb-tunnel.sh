#!/usr/bin/env bash
# ── FraudShield AI · ADB tunnel (Mac → Oracle redroid) ──────────────────────
#
# Forwards the Oracle VM's loopback-bound ADB port to a loopback port on this
# Mac, so worker-dynamic can drive the cloud Android over host.docker.internal.
#
#     ./infra/redroid/adb-tunnel.sh <VM_PUBLIC_IP>
#     ./infra/redroid/adb-tunnel.sh 141.148.x.x --daemon
#
# WHY A TUNNEL AND NOT AN OPEN PORT
#   Port 5555 on the VM stays bound to 127.0.0.1 (see setup-oracle-host.sh).
#   Internet-facing ADB is unauthenticated root shell — it is mass-scanned
#   continuously (ADB.Miner and successors) and would be found within hours.
#   SSH does the authentication; ADB never touches the public interface.
#
# Options (env or flags):
#   SSH_USER   (default ubuntu)      --user <u>
#   SSH_KEY    (default ~/.ssh/id_rsa)  --key <path>
#   LOCAL_PORT (default 5556)        --port <n>
#   REMOTE_PORT(default 5555)
set -euo pipefail

SSH_USER="${SSH_USER:-ubuntu}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
LOCAL_PORT="${LOCAL_PORT:-5556}"   # NOT 5555 — Flower already publishes that.
REMOTE_PORT="${REMOTE_PORT:-5555}"
DAEMON=0
VM_IP=""

log()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mXX %s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --daemon) DAEMON=1; shift ;;
    --user)   SSH_USER="$2"; shift 2 ;;
    --key)    SSH_KEY="$2"; shift 2 ;;
    --port)   LOCAL_PORT="$2"; shift 2 ;;
    --stop)
      pkill -f "L ${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}" 2>/dev/null \
        && log "Tunnel on ${LOCAL_PORT} stopped" || warn "No tunnel running"
      exit 0 ;;
    -*) die "Unknown flag: $1" ;;
    *)  VM_IP="$1"; shift ;;
  esac
done

[ -n "$VM_IP" ] || die "Usage: $0 <VM_PUBLIC_IP> [--daemon] [--user u] [--key path] [--port n]"
[ -f "$SSH_KEY" ] || die "SSH key not found: $SSH_KEY  (pass --key <path>)"

# ── Reuse or replace an existing tunnel ─────────────────────────────────────
if lsof -nP -iTCP:"$LOCAL_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  if pgrep -f "L ${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}" >/dev/null 2>&1; then
    log "Tunnel already listening on 127.0.0.1:${LOCAL_PORT} — reusing"
  else
    die "Port ${LOCAL_PORT} is in use by something that is not this tunnel.
Pick another with --port, or find the holder: lsof -nP -iTCP:${LOCAL_PORT} -sTCP:LISTEN"
  fi
else
  log "Opening tunnel 127.0.0.1:${LOCAL_PORT} → ${VM_IP}:${REMOTE_PORT} (via SSH)"

  # Bind to 127.0.0.1 only. Docker Desktop's host.docker.internal reaches the
  # Mac's loopback, so the worker still gets through without exposing ADB to
  # anyone else on the local network (coffee-shop wifi, shared office LAN).
  SSH_ARGS=(
    -i "$SSH_KEY" -N
    -L "127.0.0.1:${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}"
    -o ExitOnForwardFailure=yes
    -o ServerAliveInterval=20
    -o ServerAliveCountMax=3
    "${SSH_USER}@${VM_IP}"
  )

  # Always background it, in both modes, so the checks below actually run —
  # verifying after `exec ssh` would be unreachable code. Foreground mode just
  # parks on the tunnel at the end.
  if command -v autossh >/dev/null 2>&1; then
    # autossh re-establishes the forward after a laptop sleep or wifi change,
    # which otherwise leaves the worker with a dead device mid-analysis.
    AUTOSSH_GATETIME=0 autossh -M 0 -f "${SSH_ARGS[@]}"
  else
    warn "autossh not installed — the tunnel will not survive a network drop."
    warn "  brew install autossh"
    ssh -f "${SSH_ARGS[@]}"
  fi

  for _ in $(seq 20); do
    lsof -nP -iTCP:"$LOCAL_PORT" -sTCP:LISTEN >/dev/null 2>&1 && break
    sleep 0.5
  done
  lsof -nP -iTCP:"$LOCAL_PORT" -sTCP:LISTEN >/dev/null 2>&1 \
    || die "Tunnel failed to bind ${LOCAL_PORT}. Test SSH first:
  ssh -i $SSH_KEY ${SSH_USER}@${VM_IP} 'sudo docker ps'"
fi

# ── Verify: tunnel up, device booted ────────────────────────────────────────
command -v adb >/dev/null 2>&1 || die "adb not on PATH (brew install android-platform-tools)"

  log "Connecting to the cloud device"
  adb connect "127.0.0.1:${LOCAL_PORT}" >/dev/null 2>&1 || true
  sleep 1
  BOOTED=$(adb -s "127.0.0.1:${LOCAL_PORT}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
  [ "$BOOTED" = "1" ] || die "Tunnel is up but the device did not answer.
On the VM:  sudo docker ps | grep redroid  &&  sudo docker logs fraudshield-redroid"

  REL=$(adb -s "127.0.0.1:${LOCAL_PORT}" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
  ABI=$(adb -s "127.0.0.1:${LOCAL_PORT}" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
  log "Connected — Android ${REL} (${ABI}) on ${VM_IP}"

  cat <<EOF

────────────────────────────────────────────────────────────────────
 Point the worker at it — add to .env (repo root), then recreate:

   SANDBOX_ADB_HOST=host.docker.internal:${LOCAL_PORT}
   SANDBOX_EGRESS_BLOCKED_EXTERNALLY=true

   docker compose -f infra/docker-compose.yml up -d worker-dynamic

 Recreate, don't restart — a container's env is fixed at create time.

 Then confirm the worker can actually see it:
   docker compose -f infra/docker-compose.yml exec worker-dynamic \\
     adb connect host.docker.internal:${LOCAL_PORT}
────────────────────────────────────────────────────────────────────
EOF

if [ "$DAEMON" = "0" ]; then
  # Foreground: block until the tunnel dies or the user hits Ctrl-C.
  # `wait` can't be used — the ssh process was started with -f, so it is not a
  # child of this shell. And `tail --pid` is GNU-only; BSD tail on macOS has no
  # such flag, so poll instead.
  TUN_PID=$(pgrep -f "L ${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}" | head -n1)
  log "Holding tunnel open (Ctrl-C to close). Use --daemon to background it."
  trap 'echo; log "Closing tunnel"; [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null; exit 0' INT TERM
  while [ -n "${TUN_PID:-}" ] && kill -0 "$TUN_PID" 2>/dev/null; do
    sleep 2
  done
  warn "Tunnel process exited."
fi
