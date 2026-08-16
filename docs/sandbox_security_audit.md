# Sandbox Security Focused Audit

## 1. Docker Runtime
- **Python version**: `3.11-slim`
- **OS/base image**: `python:3.11-slim`
- **Installed apt/system packages**: 
  - Builder stage: `build-essential`, `libpq-dev`
  - Runtime stage: `libpq5`, `android-tools-adb`
- **adb availability**: Yes (installed via `android-tools-adb`).
- **emulator availability**: No (the `emulator` binary is not installed in the Dockerfile).
- **tcpdump availability**: No.
- **tshark availability**: No.
- **iptables availability**: No.
- **other networking/security tools**: None.
- **adb_keys copied into the image**: Yes, baked into `/home/appuser/.android/` (though overridden by a read-only volume in docker-compose).
- **container user**: `appuser` (uid 1000).
- **container capabilities/privileges**: None explicitly granted.

## 2. worker-dynamic Security Boundary
- **networks**: Uses the default compose bridge network (no explicit networks defined).
- **network_mode**: Default.
- **privileged**: Not specified (false).
- **cap_add**: Not specified.
- **ports**: None published.
- **extra_hosts**: `host.docker.internal:host-gateway`
- **volumes**:
  - `apk_storage:/tmp/fraudshield-storage`
  - `~/.android/adbkey:/home/appuser/.android/adbkey:ro`
  - `~/.android/adbkey.pub:/home/appuser/.android/adbkey.pub:ro`
- **environment**: `SANDBOX_MODE: live`, `SANDBOX_ADB_HOST: "host.docker.internal:5555"`, `ADB_BIN: adb`.
- **env_file**: `../.env`
- **ADB configuration**: Reaches out to the host machine's ADB via `host.docker.internal:5555`.
- **host.docker.internal configuration**: Mapped to host gateway via `extra_hosts`.
- **Communication paths**:
  - **host**: Fully reachable via `host.docker.internal:host-gateway`.
  - **emulator**: Reachable via `host.docker.internal:5555`.
  - **other containers**: Reachable via the default compose network (postgres, rabbitmq, redis, backend).
  - **Internet**: Fully reachable via the host's NAT on the default docker bridge.

## 3. Redroid Architecture
- **network topology**: Dedicated bridge network `fraudshield-sandbox`.
- **bridge/subnet**: `172.31.240.0/24`.
- **ADB path**: ADB listens natively on 5555 in the guest, mapped to `127.0.0.1:5555` on the Oracle VM host.
- **SSH tunnel path**: `adb-tunnel.sh` creates a local SSH port forward (`-L 127.0.0.1:LOCAL_PORT:127.0.0.1:5555`) to safely connect the Mac to the VM's loopback interface.
- **exposed ports**: None on the public internet (ADB bound to loopback only).
- **persistence**: Uses `netfilter-persistent save` for firewall rules, `modules-load.d` for binder, and `--restart unless-stopped` for Docker.
- **idempotency**: Safe to re-run (flushes existing iptables chains, verifies hook presence, force removes existing container).
- **failure behavior**: Boot script sends probes for ICMP, DNS, TCP, and Metadata. If any succeed, it sets `CONTAINMENT_BROKEN=1` and fails closed (exits with error).
- **cleanup behavior**: No automatic teardown. The container and network persist indefinitely. Re-running the script destroys and recreates the container.
- **reboot behavior**: Designed to survive reboots (rules saved, modules loaded on boot, container restarts).
- **Fail-closed sandbox**: Yes, the architecture ensures the container cannot communicate outwards unless explicit rules allow it, though it relies on standard iptables rules matching the subnet correctly across reboots.

## 4. Firewall Implementation
- **firewall chains**: Custom chain `FRAUDSHIELD-SANDBOX`.
- **firewall hooks**: Hooked at index 1 of the `DOCKER-USER` (for routed traffic) and `INPUT` (for host-local traffic) chains.
- **INPUT/FORWARD/DOCKER-USER rules**: 
  - Allows `ESTABLISHED,RELATED` connection tracking.
  - Drops traffic to `169.254.0.0/16`.
  - Default drop for all other traffic originating from the subnet.
- **allowed traffic**: Only responses to connections initiated externally (e.g., ADB commands).
- **blocked traffic**: All new outbound connections from the Android container.
- **metadata protection**: Yes (drops `169.254.0.0/16`).
- **DNS behavior**: Relies on default Docker DNS but outbound is dropped, so external resolution fails.

## 5. ADB Path
- Oracle VM runs ADB on `127.0.0.1:5555`.
- Mac runs `adb-tunnel.sh` forwarding `127.0.0.1:5556` -> `VM:5555` via SSH.
- `docker-compose.yml` points `worker-dynamic` to `host.docker.internal:5556`.
- The worker communicates to the Mac's loopback, which is encrypted over SSH to the VM's loopback, and into the Redroid container.

## 6. Network Capture Implementation
*Note: Located in `backend/app/dynamic_analysis/network_capture.py`*
- **class/function**: Contains `NetworkCapture` class and `_parse_dns_qname` helper.
- **imports**: `os`, `re`, `socket`, `subprocess`, `threading`, `time`, `typing`, `app.core.logging`.
- **commands executed**: `adb -s <serial> logcat -v brief`
- **expected interfaces**: Listens on UDP port `5353` locally.
- **input/output**: Takes an adb serial and duration; outputs a de-duplicated list of dictionaries (host, port, protocol, ts, sink).
- **packet capture mechanism**: Implements a crude DNS server (UDP socket reading 512 bytes) and uses a regular expression against `adb logcat` to catch TCP connections.
- **output format**: `[{"host": "...", "port": 53, "protocol": "dns", "ts": 12345.0, "sink": True}, ...]`
- **source/destination IP**: Extracts destination host. Cannot capture source IP.
- **ports**: Hardcoded to 53 for DNS, extracts port from logcat strings for TCP.
- **protocols**: `dns`, `tcp`.
- **DNS**: Intercepts requests sent to `127.0.0.1:5353` and parses QNAME directly from bytes.
- **timestamps**: Captured via `time.time()`.
- **process attribution**: None (cannot map packets to PIDs).
- **distinguish emulator traffic from host traffic**: Cannot. The DNS socket binds locally and captures *anything* on the host sent to that port.
- **integration with SandboxManager**: **Zero.** The file is imported, but the `NetworkCapture` class is never instantiated or used. `sandbox_manager.py` implements its own rudimentary logcat regex instead.

## 7. Frida Implementation
*Note: Located in `backend/app/dynamic_analysis/frida_hooks.py`*
- **hooks**:
  - `SmsManager.sendTextMessage` (SMS send)
  - `ContentResolver.query` (SMS read)
  - `AccessibilityService.onAccessibilityEvent` / `performGlobalAction` (Accessibility abuse)
  - `WindowManagerImpl.addView` (Overlay phishing)
- **APIs monitored**: Telephony, Content Providers, Accessibility, Window Management.
- **network-related hooks**: None.
- **filesystem-related hooks**: None.
- **process-related hooks**: None.
- **dependencies**: `frida` (lazy imported), `time`, `typing`, `logging`.
- **attachment method**: Uses `frida.get_device(serial)`, `device.spawn([package])`, `device.attach(pid)`, compiles JS into a script, loads, and resumes the PID.
- **callers**: **Zero.** `sandbox_manager.py` does not use this script. It uses `adb shell monkey` to launch apps and searches logcat for keywords.

## 8. Android Emulator Configuration
*Note: Located in `backend/app/dynamic_analysis/emulator_pool.py`*
- **AVD names**: `fraudshield_avd` (default).
- **emulator commands**: `emulator -avd <name> -port <port> -no-window -no-audio -no-boot-anim -wipe-data -dns-server 10.0.2.15 -no-snapshot-save`.
- **emulator flags**: Disables UI, audio, animations, and snapshot saving. Injects a fake DNS server.
- **API levels**: **UNKNOWN** (Not specified in repository logic).
- **system images**: **UNKNOWN** (Not specified in repository logic).
- **ADB ports**: Auto-increments from `5554` for local emulators.
- **DNS configuration**: Forced to `10.0.2.15` (intended as a fake-DNS sink).
- **network configuration**: Hardens network post-boot using `adb shell svc data disable` and `adb shell svc wifi disable`. 

## 9. Database Extension Conventions
- **new tables**: Subclass `app.core.database.Base`.
- **JSON/JSONB**: Uses SQLAlchemy `JSONB` for robust indexing and nested querying.
- **timestamps**: Uses `DateTime(timezone=True)`. Recent migrations enforce `nullable=False` and `server_default=sa.text('now()')`.
- **foreign keys**: Uses `UUID(as_uuid=True)` mapped to target columns.
- **indexes**: Defined directly on SQLAlchemy columns (e.g., `index=True` or explicit Alembic commands like `op.create_index`).
- **repository methods**:
  - Inherit standard pattern: `__init__(self, db: Session)`.
  - Uses `select().where().with_for_update()` for locking rows during complex JSON updates.
  - Updates to JSONB arrays are followed by `flag_modified(sub, "column_name")` to ensure SQLAlchemy commits the changes.
- **enum/status fields**: Represented as indexed strings.
- **migration naming**: Sequentially numbered with a descriptive name (e.g., `fc3b3e1b0973_add_analysis_stages_to_apk_submissions.py`).

## 10. Existing Components We Can Reuse
- The Redroid `FRAUDSHIELD-SANDBOX` iptables network isolation architecture.
- The `emulator_pool.py` remote connectivity lifecycle logic.
- The database ORM models and repository abstractions for storing network calls and dynamic findings.

## 11. Existing Components That Are Unsafe/Incomplete
- **`worker-dynamic` Container**: Shares the default docker network and has access to `host.docker.internal`. A malware breakout through ADB could allow lateral movement to the host and local services.
- **Local Emulator Network Hardening**: Relies purely on `svc data disable` which malware can easily turn back on programmatically.
- **`network_capture.py`**: A fundamentally flawed design that misses all raw PCAP capabilities (source IPs, payload analysis, non-DNS/TCP traffic), cannot distinguish host traffic, and isn't even actively used.
- **`sandbox_manager.py`**: Relies entirely on string matching `adb logcat` output instead of true API hooking, missing heavily obfuscated malware behavior.
- **`frida_hooks.py`**: Good foundation but completely disconnected from the execution pipeline and missing network hooking capabilities.

## 12. Verification Tests and Results
The following verification tests were run directly against the live environment to confirm runtime configurations:

### 12.1. Actual Emulator Egress
- **Test:** `adb shell ping -c 1 8.8.8.8`
- **Result:** `connect: Network is unreachable`
- **Status:** **PASS.** The `svc data disable` command successfully removes the default route in the local QEMU emulator, preventing raw IP traffic from leaving the device.

### 12.2. Actual DNS Behavior
- **Test:** `adb shell ping -c 1 google.com`
- **Result:** `ping: unknown host google.com`
- **Status:** **PASS.** Without an active route or network interface, DNS resolution fails completely.

### 12.3. Actual Routing
- **Test:** `adb shell ip route`
- **Result:** *(Returned empty output)*
- **Status:** **PASS.** The routing table inside the Android emulator is empty. The `svc data disable` and `svc wifi disable` commands effectively tore down all routing interfaces.

### 12.4. Actual ADB/Port Exposure
- **Test:** `lsof -nP -iTCP:5555 -sTCP:LISTEN`
- **Result:** 
  ```
  COMMAND    PID        USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
  qemu-syst 2057 pulkitverma   39u  IPv4 0xe455ab7237bbb0fb      0t0  TCP 127.0.0.1:5555 (LISTEN)
  qemu-syst 2057 pulkitverma   40u  IPv6 0x468ceb9c33078fa0      0t0  TCP [::1]:5555 (LISTEN)
  com.docke 2106 pulkitverma  849u  IPv6 0x9b70ef028912f7f3      0t0  TCP *:5555 (LISTEN)
  ```
- **Status:** **MIXED.** 
  - *The Good:* `qemu-system` (the local emulator) correctly binds its ADB port **only** to the loopback interface (`127.0.0.1`), ensuring ADB is not exposed to the local network.
  - *The Bad:* Docker Desktop (`com.docker`) is listening on `*:5555`. This is because `infra/docker-compose.yml` maps `5555:5555` for the **Flower** container. This exposes the Celery Flower monitoring UI to anyone on the local network (e.g., coffee shop wifi), which can be dangerous since Flower allows task execution.

### 12.5. Actual Docker-to-Host Connectivity
- **Test:** Executed a python script inside the `worker-dynamic` container to reach the host's backend API (`http://host.docker.internal:8000/health`).
- **Result:** `b'{"status":"ok","service":"FraudShield AI"}'`
- **Status:** **FAIL (Security-wise).** The `worker-dynamic` container has unrestricted network access to the host machine via `host.docker.internal`. If a malware sample escapes the emulator and achieves RCE on the worker container (e.g., via an ADB vulnerability), it can freely pivot to attack services running on the Mac host or other devices on the local network.
