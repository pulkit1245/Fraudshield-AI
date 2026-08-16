#!/usr/bin/env bash
# ── FraudShield AI · redroid host provisioning (Oracle Cloud ARM Ampere A1) ──
#
# Turns a fresh Ubuntu 22.04/24.04 aarch64 instance into a containerized
# Android sandbox that the FraudShield dynamic-analysis worker drives over ADB.
#
# Run ON THE ORACLE VM:
#     scp infra/redroid/setup-oracle-host.sh ubuntu@<VM_IP>:~
#     ssh ubuntu@<VM_IP> 'bash ~/setup-oracle-host.sh'
#
# Idempotent — safe to re-run.
#
# SECURITY MODEL (do not weaken):
#   * ADB listens on 127.0.0.1 ONLY. Port 5555 is never internet-facing.
#     Open ADB is mass-scanned and trivially owned; reach it via SSH tunnel.
#   * The Android container sits on an egress-blocked Docker network, so a
#     detonated sample cannot reach real C2 infrastructure. In-guest
#     `svc data disable` does NOT work here — redroid has no radio.
set -euo pipefail

REDROID_IMAGE="${REDROID_IMAGE:-redroid/redroid:13.0.0-arm64}"
CONTAINER_NAME="${CONTAINER_NAME:-fraudshield-redroid}"
NET_NAME="fraudshield-sandbox"
NET_SUBNET="172.31.240.0/24"
FW_CHAIN="FRAUDSHIELD-SANDBOX"
DATA_DIR="${HOME}/redroid-data"

log()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mXX %s\033[0m\n' "$*" >&2; exit 1; }

# ── 0. Sanity ───────────────────────────────────────────────────────────────
[ "$(uname -m)" = "aarch64" ] || die "Expected aarch64 (Ampere A1); got $(uname -m).
Use an ARM shape — on x86 free tiers redroid needs nested virt, which is blocked."

log "Host: $(uname -m), kernel $(uname -r), $(nproc) vCPU, $(free -g | awk '/^Mem:/{print $2}')GB RAM"

# ── 1. Binder kernel module ─────────────────────────────────────────────────
# redroid needs Android's binder IPC. Ubuntu ships it in linux-modules-extra.
log "Ensuring binder kernel module"
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get update -qq
sudo -E apt-get install -y -qq "linux-modules-extra-$(uname -r)" 2>/dev/null \
  || warn "linux-modules-extra-$(uname -r) unavailable; binder may be built in."

binder_ready() {
  # Either the legacy char devices or a mounted binderfs satisfies redroid.
  [ -e /dev/binder ] && return 0
  mountpoint -q /dev/binderfs 2>/dev/null && return 0
  return 1
}

if binder_ready; then
  log "binder already available"
elif sudo modprobe binder_linux devices="binder,hwbinder,vndbinder" 2>/dev/null && binder_ready; then
  log "Loaded binder_linux (legacy devices)"
else
  # Newer kernels expose binder through binderfs instead of static devices.
  sudo modprobe binder_linux 2>/dev/null || true
  sudo mkdir -p /dev/binderfs
  mountpoint -q /dev/binderfs 2>/dev/null \
    || sudo mount -t binder binder /dev/binderfs 2>/dev/null || true
  binder_ready || die "Could not provide binder. Check: zgrep BINDER /proc/config.gz
If CONFIG_ANDROID_BINDER_IPC / CONFIG_ANDROID_BINDERFS are absent you need a
different kernel flavour (try: sudo apt install linux-image-generic)."
  log "Using binderfs at /dev/binderfs"
fi

# Persist across reboots.
echo 'binder_linux' | sudo tee /etc/modules-load.d/redroid.conf >/dev/null
echo 'options binder_linux devices=binder,hwbinder,vndbinder' \
  | sudo tee /etc/modprobe.d/redroid.conf >/dev/null

# ── 2. Docker ───────────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker"
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
  warn "Added $USER to the docker group — log out/in for it to apply."
fi
DK="sudo docker"

# ── 3. Egress-blocked network ───────────────────────────────────────────────
# THIS is the containment boundary — the only thing standing between a live
# sample and real C2 infrastructure. In-guest `svc data disable` does nothing
# on redroid, so it cannot be relied on (see emulator_pool._harden_network).
log "Creating egress-blocked network $NET_NAME ($NET_SUBNET)"
$DK network inspect "$NET_NAME" >/dev/null 2>&1 \
  || $DK network create --driver bridge --subnet "$NET_SUBNET" "$NET_NAME"

sudo -E apt-get install -y -qq iptables-persistent >/dev/null 2>&1 || true

# All rules live in one chain so re-runs can flush instead of accumulating
# duplicates, and so the same policy applies to two different paths:
#   FORWARD (via DOCKER-USER) — container → internet, other containers,
#                               and the cloud metadata service.
#   INPUT                     — container → services on the VM itself, which
#                               DOCKER-USER never sees because that traffic is
#                               host-local rather than forwarded.
if sudo iptables -L "$FW_CHAIN" -n >/dev/null 2>&1; then
  sudo iptables -F "$FW_CHAIN"
else
  sudo iptables -N "$FW_CHAIN"
fi

# Return path first: replies to connections WE initiated (ADB from the host)
# must survive, or ADB stops working along with the sample's egress.
sudo iptables -A "$FW_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# Cloud instance metadata — hands out instance identity and can expose
# credentials. Never reachable from a machine running live malware.
sudo iptables -A "$FW_CHAIN" -d 169.254.0.0/16 -j DROP
# Everything the sample initiates, dropped.
sudo iptables -A "$FW_CHAIN" -j DROP

# Hook the chain in exactly once per parent chain.
sudo iptables -C DOCKER-USER -s "$NET_SUBNET" -j "$FW_CHAIN" 2>/dev/null \
  || sudo iptables -I DOCKER-USER 1 -s "$NET_SUBNET" -j "$FW_CHAIN"
sudo iptables -C INPUT -s "$NET_SUBNET" -j "$FW_CHAIN" 2>/dev/null \
  || sudo iptables -I INPUT 1 -s "$NET_SUBNET" -j "$FW_CHAIN"

sudo netfilter-persistent save >/dev/null 2>&1 \
  || warn "Rules not persisted — re-run this script after a reboot."
log "Egress blocked for $NET_SUBNET (forward + host-local + metadata)"

# ── 4. Launch redroid ───────────────────────────────────────────────────────
log "Starting $CONTAINER_NAME from $REDROID_IMAGE"
mkdir -p "$DATA_DIR"
$DK rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
$DK pull "$REDROID_IMAGE"

# -p 127.0.0.1:5555 — loopback only. Never bind 0.0.0.0 here.
$DK run -itd --privileged \
  --name "$CONTAINER_NAME" \
  --network "$NET_NAME" \
  --restart unless-stopped \
  -v "$DATA_DIR":/data \
  -p 127.0.0.1:5555:5555 \
  "$REDROID_IMAGE" \
  androidboot.redroid_gpu_mode=guest

# ── 5. Wait for boot + verify containment ───────────────────────────────────
command -v adb >/dev/null 2>&1 || { log "Installing adb"; sudo apt-get install -y -qq android-tools-adb; }

log "Waiting for Android to finish booting (up to 120s)"
adb disconnect >/dev/null 2>&1 || true
adb connect 127.0.0.1:5555 >/dev/null 2>&1 || true
for _ in $(seq 60); do
  [ "$(adb -s 127.0.0.1:5555 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
  sleep 2
  adb connect 127.0.0.1:5555 >/dev/null 2>&1 || true
done

BOOTED=$(adb -s 127.0.0.1:5555 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
[ "$BOOTED" = "1" ] || die "Android did not boot. Inspect: sudo docker logs $CONTAINER_NAME"

log "Android is up — release $(adb -s 127.0.0.1:5555 shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"

# ── Containment proof ───────────────────────────────────────────────────────
# Every probe below MUST fail. ICMP alone is not enough: a sample talks TCP to
# a C2 host it resolved over DNS, and those are separate paths through the
# firewall. Test what the malware would actually use.
log "Verifying containment — all four probes must FAIL"
CONTAINMENT_BROKEN=0

probe_blocked() {
  local label="$1"; shift
  local out
  out=$(adb -s 127.0.0.1:5555 shell "$@" 2>&1 || true)
  if printf '%s' "$out" | grep -qiE "$PROBE_SUCCESS_RE"; then
    warn "LEAK: $label succeeded — the guest can reach it"
    CONTAINMENT_BROKEN=1
  else
    printf '   blocked: %s\n' "$label"
  fi
}
PROBE_SUCCESS_RE='1 received|bytes from|succeeded|connected|HTTP/'

probe_blocked "ICMP to 8.8.8.8"        ping -c 1 -W 3 8.8.8.8
probe_blocked "DNS to 8.8.8.8:53"      'echo > /dev/udp/8.8.8.8/53 && echo succeeded'
probe_blocked "TCP to 1.1.1.1:443"     'echo > /dev/tcp/1.1.1.1/443 && echo succeeded'
probe_blocked "instance metadata"      'echo > /dev/tcp/169.254.169.254/80 && echo succeeded'

if [ "$CONTAINMENT_BROKEN" = "1" ]; then
  die "SAMPLE CONTAINMENT FAILED — do not detonate anything on this host.
Inspect:  sudo iptables -L $FW_CHAIN -n -v
          sudo iptables -L DOCKER-USER -n -v
          sudo iptables -L INPUT -n -v | head
A sample believed contained but actually online can reach real C2 servers from
your Oracle tenancy — that is both a safety and an account-termination risk."
fi
log "All probes blocked — guest is contained"

cat <<EOF

────────────────────────────────────────────────────────────────────
 redroid ready on $(hostname -I | awk '{print $1}') (ADB on 127.0.0.1:5555)

 Next, on your Mac:
   ./infra/redroid/adb-tunnel.sh <VM_PUBLIC_IP>

 Oracle security list: allow ONLY inbound TCP 22. Never open 5555.
────────────────────────────────────────────────────────────────────
EOF
