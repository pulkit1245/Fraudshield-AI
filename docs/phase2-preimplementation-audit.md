# Phase 2 — Read-Only Pre-Implementation Audit

**Date:** 2026-08-17
**Baseline commit:** `2a8f865 chore: checkpoint before sandbox security hardening`
**State at audit time:** Phases 0 and 1 implemented and VERIFIED (240 passed / 0 failed / 0 skipped;
221 baseline preserved + 19 new). Migration `0007` is the sole Alembic head. Phase 2 NOT started.
**Gates:** G0 CLEARED, G4 CLEARED, **G1 / G2 / G3 / G5 OPEN**.
**Nature of this document:** audit only. No application code, test, migration, configuration,
Dockerfile, or dependency was modified in producing it. Every claim below carries a file/line or a
grep result. Where evidence is insufficient to support a conclusion, the finding is marked
`NOT VERIFIED` rather than assumed either way.

---

## 1. Live sandbox path — complete trace

### 1.1 Request / input model

There is no Pydantic request body for the submission that starts a sandbox run; it is a multipart
upload.

| Concern | Location |
| --- | --- |
| Route | `backend/app/api/v1/submissions.py` — `POST /api/v1/submissions`, `file: UploadFile = File(...)`, plus `db` and `current_user` dependencies |
| Payload validation | `backend/app/utils/validators.py::validate_apk_upload` (:55) → `check_size` (:30, `settings.MAX_UPLOAD_BYTES`) and `has_zip_magic` (:39, `_ZIP_MAGICS` at :18) then a `zipfile` open asserting `AndroidManifest.xml` is present (:44-51) |
| Failure codes | 413 on size, 415 on signature / missing manifest |

The APK bytes go to object storage; the sandbox later re-materializes them from
`submission.storage_path`. Nothing about sandbox mode is accepted from the client — mode is entirely
server-side environment state. That is a good property and Phase 2 should preserve it.

### 1.2 Enqueue

`backend/app/api/v1/submissions.py::_enqueue_pipeline` dispatches the dynamic task **by name**:

```python
get_celery_app().send_task(
    "app.workers.tasks.dynamic_task.run_dynamic_analysis",
    args=[sid],
    queue="dynamic_queue",
)
```

wrapped in `try/except Exception → log.debug("enqueue.dynamic_skipped", ...)`. The enqueue is
best-effort by design, so a broker outage produces a successful upload with no dynamic analysis and
no error surfaced to the caller. Routing is also declared in `backend/app/workers/celery_app.py:70`
(`"app.workers.tasks.dynamic_task.*": {"queue": "dynamic_queue"}`).

### 1.3 Mode selection — two different defaults

Mode is read from the environment in **two independent places with two different fallbacks**:

| File / line | Code | Default |
| --- | --- | --- |
| `backend/app/workers/tasks/dynamic_task.py:55` | `sandbox_mode = os.getenv("SANDBOX_MODE", "simulate").lower()` | `simulate` |
| `backend/app/dynamic_analysis/sandbox_manager.py:35` | `requested = (mode or os.getenv("SANDBOX_MODE", "mobsf")).lower()` | `mobsf` |

The task-level read at `:55` does **not** select the sandbox. Its only effect is the
wait-for-static-analysis retry loop at `:56-71` (up to 3 retries at 5 s so simulation has static
signals to derive from). The value that actually chooses the execution path is the one read inside
`SandboxManager.__init__`. So with `SANDBOX_MODE` unset the task would take the simulate-specific
wait branch while the sandbox would attempt MobSF — an incoherent combination that is only masked
today because `infra/docker-compose.yml:32` sets `SANDBOX_MODE: live` explicitly.

Dispatch itself is `SandboxManager.run` (`sandbox_manager.py:44-62`):

```python
if self.mode == "mobsf":
    ...                                  # :47-56
if self.mode == "live":
    try:
        return self._run_live(submission_id, apk_path, package_name)   # :59
    except Exception as exc:             # :60  ← catch-all
        log.warning("sandbox.live_failed_simulate", error=str(exc))
return self._run_simulated(submission_id, static_hint or {})           # :62
```

### 1.4 Service orchestration

`backend/app/services/dynamic_analysis_service.py::DynamicAnalysisService.analyze` (:36-60):

1. `_as_uuid` (:125) then `db.get(Submission, ...)`; raises `ValueError` if absent (:39-40).
2. `_static_hint` (:63-73) — projects `package_name`, `permissions`, `api_call_graph`.
3. `tempfile.mkdtemp(prefix="dynamic_")` (:44), `apk_path = <workdir>/sample.apk` (:45).
4. `_materialize_apk` (:75-83) — `storage.download`, and on any exception logs
   `dynamic.apk_materialize_skipped` at **debug** level and returns the path anyway (:80-83). The
   comment states "Simulation mode doesn't need the bytes; live mode will error clearly." In live
   mode this produces a missing/empty file that surfaces later as an `adb install` failure, which
   `run()` then swallows into a simulate fallback — so it does *not* error clearly end-to-end.
5. `self.sandbox.run(...)` (:48-52).
6. `_persist` (:85-122).
7. `finally: shutil.rmtree(workdir, ignore_errors=True)` (:60).

`SandboxManager` is constructed at `DynamicAnalysisService.__init__:34` (`sandbox or SandboxManager()`),
which means the `EmulatorPool` is constructed eagerly at service construction whenever mode is live
(`sandbox_manager.py:37`), before any APK work begins. Construction is cheap (no connection is made
in `EmulatorPool.__init__`), so this is not a functional issue today, but it does mean the pool object
lifetime equals the service lifetime — one pool per task invocation, never shared.

### 1.5 Sandbox creation / emulator startup

All in `backend/app/dynamic_analysis/emulator_pool.py`:

| Step | Function / line |
| --- | --- |
| Pool object | `EmulatorPool.__init__:63-68` — `avd_name` from `SANDBOX_AVD` (default `fraudshield_avd`), `size` from `POOL_SIZE` (`SANDBOX_POOL_SIZE`, default 1), a `queue.Queue`, a `threading.Lock`, `_started = False` |
| Acquire | `acquire:199-202` — `if not self._started and not self.warm_up(): raise RuntimeError("No emulator available (SDK not installed or remote unreachable)")`, then `self._available.get(timeout=timeout)` with `timeout: int = 180` |
| Capability check | `is_available:52-57` — remote branch requires only `shutil.which(ADB_BIN)`; local branch requires `ADB_BIN` **and** `EMULATOR_BIN` |
| Warm-up | `warm_up:71-84` — under `self._lock`, branches on the module-level `SANDBOX_ADB_HOST` (:41) |
| Remote path | `_connect_remote:87-122` — `adb connect <host>` (timeout 15), string-matches `"failed to authenticate"` → `emulator.unauthorized` + `return False` (:97-106), then requires `connected`/`already connected` in stdout (:107-109), builds `EmulatorInstance(remote=True)`, `_wait_for_boot(host, remote=True)`, `_harden_network(inst)`, `queue.put` |
| Local path | `_boot_local:125-132` → `_boot_one:134-152` — `Popen([EMULATOR_BIN, "-avd", avd, "-port", ..., "-no-window", "-no-audio", "-no-boot-anim", "-wipe-data", "-dns-server", "10.0.2.15", "-no-snapshot-save"])`, then `_wait_for_boot`, then `_harden_network` |
| Boot polling | `_wait_for_boot:155-186` — polls `getprop sys.boot_completed` every 2 s until `== "1"`; raises `RuntimeError` on `"unauthorized"` in combined stdout/stderr (:173-179); breaks early on `"device offline"` for remote (:182-183); otherwise raises `TimeoutError` (:186). Timeout is `REMOTE_BOOT_TIMEOUT` (90 s) for remote, `BOOT_TIMEOUT` (180 s) for local |
| Containment attempt | `_harden_network:189-196` — see §4 |

Note that `_connect_remote`'s body is wrapped in `except Exception → log.warning("emulator.remote_connect_error"); return False` (:120-122), so **both** exception types raised by `_wait_for_boot` — the `RuntimeError` for UNAUTHORIZED and the `TimeoutError` — are converted into a boolean `False`. The specific, actionable reason is reduced to one stdout log line and then discarded; `acquire` re-raises only the generic `"No emulator available (SDK not installed or remote unreachable)"`.

`SANDBOX_ADB_HOST` is captured **at module import** (`emulator_pool.py:41`), not per call. Any change
to the variable after the worker process imports the module has no effect, and the remote/local
branch is therefore fixed for the lifetime of the worker.

### 1.6 APK installation

`sandbox_manager.py::_run_live:107-115`:

```python
install = subprocess.run(
    [ADB_BIN, "-s", inst.serial, "install", "--bypass-low-target-sdk-block", "-r", "-d", "-t", apk_path],
    capture_output=True, text=True, timeout=120,
)
if install.returncode != 0:
    raise RuntimeError(f"adb install failed: {install.stderr.strip() or install.stdout.strip()}")
```

Return code **is** checked here. This is the single strongest piece of evidence behind the G4
conclusion: a persisted `mode: "live"` blob implies this line returned 0.

Package name comes from `package_name or self._infer_package(apk_path)` (:101), and `_infer_package`
(:176-182) falls back to the literal string `"unknown"` on any androguard failure. `adb install`
would still succeed with `pkg == "unknown"`, and every subsequent step keyed on `pkg` (launch,
force-stop, uninstall) would then target a nonexistent package.

### 1.7 Execution

`sandbox_manager.py::_run_live:118-141`:

1. `logcat -c` to clear the buffer (:118-119, timeout 5) — return code not checked.
2. Launch (:122-127):

```python
subprocess.run(
    [ADB_BIN, "-s", inst.serial, "shell",
     "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"],
    capture_output=True, text=True, timeout=15,
)
```

   **The return code and output are not examined at all**, and the very next line logs
   `sandbox.live.launched` unconditionally (:128). `monkey` reports "No activities found to run" and
   similar conditions on stdout, so an APK that never started is indistinguishable here from one
   that ran. This is the single largest correctness gap in the live path.

3. Observation window (:131-141) — `Popen([ADB_BIN, "-s", serial, "logcat", "-v", "brief"])`,
   `time.sleep(RUN_SECONDS)` where `RUN_SECONDS = int(os.getenv("SANDBOX_RUN_SECONDS", "60"))` (:30),
   then `terminate()` and `communicate(timeout=5)` with a `kill()` + `logcat_output = ""` fallback
   (:139-141). A kill path therefore yields an empty transcript, which parses to all-False flags and
   an empty `network_calls` list — a clean-looking result.

### 1.8 Instrumentation

**There is none at runtime.** This contradicts three docstrings in the tree.

| Claim | Location | Reality |
| --- | --- | --- |
| "Acquire local Android emulator, install APK, instrument with Frida. Requires Android SDK + Frida installed on the host." | `sandbox_manager.py:6-7` | No Frida call anywhere in the live path |
| "(live emulator+Frida or judge-safe simulation)" | `dynamic_analysis_service.py:4` | Same |
| Frida reference in the `sandbox_log_path` comment | `models/dynamic_finding.py:40` | Same |

`backend/app/dynamic_analysis/frida_hooks.py` exists (`FRIDA_HOOK_JS` at :24, `class FridaRunner` at
:82, `import frida` at :92) and `frida==16.4.8` is a real installed dependency
(`backend/requirements.txt:52`), but `git grep -n "frida_hooks" -- app/` returns **zero importers**.
`FridaRunner` is dead code.

Actual "instrumentation" is regex matching over logcat text: `_PATTERNS` (:232-246) and
`_parse_logcat` (:254-284).

### 1.9 Telemetry collection

`_parse_logcat(logcat: str, pkg: str)` (:254) returns `(flags, network_calls, events)`:

- `flags` — exactly three booleans: `sms_access`, `accessibility_abuse`, `overlay_detected`.
- `events` — `{"type": name, "line": line[:200]}` per matched line.
- `network_calls` — see §1.10.

Two properties of this function matter for Phase 2:

1. **`pkg` is accepted and never used.** Verified: the parameter appears only on the signature line;
   the body (:256-284) never references it. The parser therefore attributes behaviour found anywhere
   in the *device-wide* logcat to the sample under analysis — including system components and any
   other app resident on the device.
2. **The match is a substring regex over log text, not an API trace.** `_PATTERNS` keys on tokens like
   `SmsManager`, `AccessibilityService`, `TYPE_VIEW`, `OkHttp`. Any process that writes those strings
   to logcat sets the corresponding flag.

Together these mean the telemetry is attacker-influenceable and cross-contaminable. There is no
syscall capture, no API hooking, no process attribution, and no pcap anywhere in the tree.

### 1.10 Network observation

Live-mode `network_calls` are produced entirely inside `_parse_logcat` (:271-281), only for lines that
matched the `c2_connect` pattern (:244-245: `HttpURLConnection|OkHttp|volley|Retrofit|socket\.connect|SSLSocket`):

```python
for m in _NETWORK_RE.finditer(line):
    host = m.group(1)
    port = int(m.group(2) or 443)
    if host not in seen_hosts and not host.endswith(".android.com"):
        seen_hosts.add(host)
        network_calls.append({"host": host, "port": port, "protocol": "tcp", "sink": False})
```

`_NETWORK_RE` (:248-251) matches any hostname-shaped token. So the host is scraped from log text, the
port is the regex capture **or a hardcoded 443**, and the protocol is the hardcoded string `"tcp"`.
No destination IP, no DNS resolution, and no connection state is ever observed. Details in §4.

`backend/app/dynamic_analysis/network_capture.py` — which does contain a real DNS sink
(`_run_dns_sink`, binding `FAKE_DNS_HOST` `127.0.0.1:5353`, recording
`{host, port: 53, protocol: "dns", ts, sink: True}`) and a `_scrape_logcat` fallback — is imported at
`sandbox_manager.py:23` and **never instantiated**. `git grep -n "NetworkCapture(\|network_capture\."`
returns matches only in `docs/` and `fraudshield_architecture.html`, never in `backend/app/`.

### 1.11 Result persistence

Two separate persistence steps:

| Artifact | Function | Notes |
| --- | --- | --- |
| Blob | `sandbox_manager._store_log:218-227` — key `sandbox_logs/{submission_id}/{uuid4}.json` via `storage.upload_artifact` | On any exception logs `sandbox.log_store_failed` and **returns the key anyway** (:225-227), so `sandbox_log_path` can reference a blob that was never written |
| DB row | `dynamic_analysis_service._persist:85-122` | Upsert on `submission_id`; writes `sms_access`, `accessibility_abuse`, `overlay_detected` (coerced with `bool()`), `network_calls` (`or []`), `sandbox_log_path`, then the two Phase 1 provenance columns |

The Phase 1 provenance write (:118-119) is deliberately uncoerced:

```python
finding.mode = result.get("mode")
finding.containment_verified = result.get("containment_verified")
```

Live mode returns `"mode": "live"` at `sandbox_manager.py:173`. **No code path anywhere sets
`containment_verified`** — verified by grep; the key is absent from all three of `_run_live`,
`_run_simulated`, and `_run_mobsf`, so the column is NULL (= NOT VERIFIED) for every row written
today. Phase 3 is what populates it.

### 1.12 Cleanup

`_run_live`'s `finally` block (:147-158):

```python
finally:
    try:
        subprocess.run([... "am", "force-stop", pkg], capture_output=True, timeout=10)
        subprocess.run([... "uninstall", pkg],        capture_output=True, timeout=30)
        log.info("sandbox.live.uninstalled", pkg=pkg)
    except Exception:
        pass
    self._pool.release(inst)
```

Neither return code is checked, and the blanket `except Exception: pass` means a `TimeoutExpired` on
either call is silently ignored — the sample stays installed and `sandbox.live.uninstalled` may
still be skipped or logged depending on where the failure occurred.

`EmulatorPool.release:204-211` then does:

```python
if not inst.remote:
    subprocess.run([ADB_BIN, "-s", inst.serial, "shell", "pm", "clear-all"], ... timeout=30)
self._available.put(inst)
```

**State wiping is skipped entirely for remote devices** — that is, for the only path that can work
in-container (§2) and the only path that can drive redroid. `EmulatorPool.shutdown:213-221` exists and
has **zero callers** (`git grep -n "\.shutdown()" -- backend/` → none).

Workdir cleanup is sound: `shutil.rmtree(workdir, ignore_errors=True)` in `analyze`'s `finally` (:60).

### 1.13 Failure handling

| Layer | Behaviour |
| --- | --- |
| `_run_live` internals | `adb install` non-zero → `RuntimeError` (:111-114); `acquire` failure → `RuntimeError` (`emulator_pool.py:201`); boot failure → `RuntimeError`/`TimeoutError`, already downgraded to `False` by `_connect_remote` (:120-122) |
| `SandboxManager.run` | **catch-all** at :60 → `log.warning("sandbox.live_failed_simulate")` → falls through to `_run_simulated` at :62. Fail-open. |
| `DynamicAnalysisService.analyze` | No sandbox-specific handling; only the `finally` rmtree |
| `dynamic_task.run_dynamic_analysis` | `except Exception` (:103) → `log.error("dynamic_task.failed")` → `self.retry(exc=exc)` (max 6, 15 s default delay) → on `MaxRetriesExceededError` (:107) sets status `failed` + stage `failed` with `error_message` and re-raises |

The decisive consequence: because `run()` absorbs every live failure at `:60`, **the task-level retry
and failed-status machinery is unreachable for live-mode failures.** `max_retries=6`,
`update_status(..., "failed", completed=True)`, and `error_message` never engage for a broken
emulator. Instead `dynamic_task.py:86` writes stage detail `"capturing syscalls"` — a capability that
does not exist anywhere in the codebase — and `:94` calls
`repo.update_analysis_stage(submission_id, "Dynamic Analysis", "completed")` **unconditionally**,
regardless of which mode actually ran, followed by `update_status(submission_id, "scoring")` at :97.

### 1.14 Timeout handling

| Scope | Value | Location |
| --- | --- | --- |
| `adb install` | 120 s | `sandbox_manager.py:109` |
| `logcat -c` | 5 s | `:119` |
| `monkey` launch | 15 s | `:126` |
| logcat `communicate` | 5 s | `:138` |
| `am force-stop` | 10 s | `:152` |
| `adb uninstall` | 30 s | `:154` |
| Observation window | `SANDBOX_RUN_SECONDS`, default 60 s | `:30`, slept at `:135` |
| `adb connect` | 15 s | `emulator_pool.py:93` |
| `getprop` poll | 5 s each, 2 s sleep | `:162`, `:185` |
| `_harden_network` per command | 10 s | `:194` |
| `pm clear-all` | 30 s | `:209` |
| Boot | 180 s local / 90 s remote | `:34`, `:37` |
| `acquire` queue wait | 180 s | `:199` |
| Celery soft / hard | 840 s / 900 s | `backend/app/workers/celery_app.py:63-64` |

Worst-case live path is roughly 15 + 90 + 20 (warm-up) + 180 (queue wait) + 120 + 5 + 15 + 60 + 40
≈ 545 s, which sits under the 840 s soft limit at the default `SANDBOX_RUN_SECONDS=60`. Two
observations for Phase 2:

1. `celery.exceptions.SoftTimeLimitExceeded` derives from `Exception`, so if the soft limit *were*
   reached inside `_run_live` (e.g. a raised `SANDBOX_RUN_SECONDS`, or a slow queue wait), the
   catch-all at `sandbox_manager.py:60` would swallow it and the task would proceed to fabricate a
   simulate result rather than abort. The fail-open path therefore also captures timeout control.
2. The 900 s hard limit kills the worker process. With `task_acks_late=True` and
   `task_reject_on_worker_lost=True` (`celery_app.py:52-53`) the message is redelivered, so a sample
   can be installed and executed more than once, and `_persist` upserts over the earlier row.

---

## 2. Live-mode pre-flight

Nothing was launched, connected to, or mutated to produce this section. Classifications are used
strictly as follows: **implemented** = code exists that does the thing; **configured** = a value is
declared in compose/`.env`/a script; **available** = the artifact is present in the image or repo;
**not verified** = cannot be established without running something, and no evidence in-tree settles
it; **missing** = required and absent.

### 2.1 Item-by-item

| # | Item | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Container runtime dependency of the live path itself | **implemented, none required** | `_run_live` is pure `subprocess` + `adb`. No Docker API, no socket. The redroid *target* needs Docker, but on the Oracle host, not here |
| 2 | Compose declares live mode | **configured** | `infra/docker-compose.yml:32` (`x-backend-env` anchor) and `:143` (worker-dynamic) both set `SANDBOX_MODE: live` |
| 3 | Compose declares a remote ADB endpoint | **configured — and internally inconsistent** | `:146` `SANDBOX_ADB_HOST: "host.docker.internal:5555"`; see §2.2 |
| 4 | `adb` binary in the worker image | **available** | `backend/Dockerfile:23-26` installs `android-tools-adb`. Version unpinned (`apt-get` latest at build time) |
| 5 | `emulator` binary / Android SDK in the image | **missing** | `backend/Dockerfile` runtime stage installs only `libpq5` and `android-tools-adb`. `git grep -ni "sdkmanager\|avdmanager\|system-images"` → no matches anywhere in `backend/` or `infra/` |
| 6 | Local-QEMU live mode in-container | **impossible today** | `emulator_pool.is_available:57` requires `shutil.which(EMULATOR_BIN)`; per item 5 that is never satisfiable inside the image, so `warm_up` logs `emulator.unavailable` (:74) and returns False. Every in-container live run is forced onto the remote path |
| 7 | Host-side emulator actually listening | **not verified** | Requires host inspection. Compose comment `:144-145` documents the manual prerequisite: "The emulator must be started on the host with: `adb tcpip 5555`" |
| 8 | ADB keypair delivery | **configured** | `:158-161` read-only mounts `~/.android/adbkey` and `.pub` to `/home/appuser/.android/`; `Dockerfile:44` pre-creates that directory owned by appuser. Phase 0 removed the baked key |
| 9 | Host keypair exists and is authorized by the device | **not verified** | Cannot be checked read-only from here. If the host file is absent, Docker creates a *directory* at the mount target and `adb` cannot load a key — a silent live failure |
| 10 | redroid image | **configured, not pinned, not verified** | `infra/redroid/setup-oracle-host.sh` `REDROID_IMAGE="${REDROID_IMAGE:-redroid/redroid:13.0.0-arm64}"` — a mutable tag, no digest. No evidence in-tree that it was ever pulled or run |
| 11 | MobSF service | **missing** | `sandbox_manager.py:56` prints the hint "Start MobSF: docker compose -f infra/docker-compose.yml up mobsf", but no `mobsf` service exists in that file. The `mobsf` mode is unreachable via compose |
| 12 | Python deps for the live path | **available** | Only `subprocess`/`adb` are needed. `frida==16.4.8` (`requirements.txt:52`) is installed but unused (§1.8) |
| 13 | Node deps | **not applicable** | The live path has no Node component. Frontend has zero test files; `tsc --noEmit` is its only gate |
| 14 | `extra_hosts` for host reachability | **configured** | `:162-163` `host.docker.internal:host-gateway` on worker-dynamic only |
| 15 | Elevated capabilities in the worker | **absent (by design)** | `git grep -n "docker.sock\|privileged\|cap_add\|devices:\|security_opt" -- infra/ backend/Dockerfile` → the **only** match is `setup-oracle-host.sh:132` `--privileged`, which applies to the redroid container on the Oracle host, not to any compose service |
| 16 | Worker runs unprivileged | **implemented** | `Dockerfile:36` creates uid 1000 `appuser`; `:46` `USER appuser` |
| 17 | Mounted volumes | **configured** | worker-dynamic `:156-161` — `apk_storage:/tmp/fraudshield-storage` plus the two read-only key files. The comment at `:154-155` correctly notes YAML merge keys replace rather than concatenate sequences |
| 18 | Storage backend resolution | **configured** | `.env` leaves `STORAGE_KEY`/`STORAGE_SECRET` empty → `_build_storage()` returns `LocalStorage` rooted at `/tmp/fraudshield-storage`, which is exactly where `apk_storage` mounts. This is why the G4 blob evidence exists |
| 19 | Published ports | **configured, all on all interfaces** | postgres `5433:5432`, rabbitmq `5672` + `15672`, redis `6379:6379`, backend `8000:8000`, flower `5555:5555`, frontend `5173:80`. None carries a `127.0.0.1:` prefix |
| 20 | Env vars the live path reads | **see §2.3** | — |
| 21 | Egress restriction on the analysis network | **missing in compose** | `infra/docker-compose.yml` declares **no `networks:` block at all** — every service shares the implicit default bridge with default outbound allowed. No `internal: true` anywhere |
| 22 | External egress-block signal | **missing (dead config)** | `SANDBOX_EGRESS_BLOCKED_EXTERNALLY` is read by **no application code** — grep finds it only in `infra/redroid/adb-tunnel.sh:117` output text and in `docs/` |
| 23 | Containment verification writer | **missing** | Nothing sets `containment_verified` (§1.11). Phase 3 scope |
| 24 | Runtime capability detection (decision D1) | **missing** | `is_available:52-57` detects only *binary presence*, and `_connect_remote` never determines whether the far end is a QEMU AVD or a redroid container. There is no probe of the containment property itself |

### 2.2 The `5555` conflict — a concrete pre-flight defect

Three facts, each directly from the repo:

1. `infra/docker-compose.yml:190-191` publishes **host port 5555** for Flower.
2. `infra/docker-compose.yml:146` tells worker-dynamic to reach the emulator at
   `host.docker.internal:5555`.
3. `infra/redroid/adb-tunnel.sh` sets `LOCAL_PORT="${LOCAL_PORT:-5556}"` with the inline comment
   `# NOT 5555 — Flower already publishes that.`, and its instructions tell the operator to put
   `SANDBOX_ADB_HOST=host.docker.internal:5556` and `SANDBOX_EGRESS_BLOCKED_EXTERNALLY=true` into the
   repo-root `.env`.

So the redroid tooling and the compose file disagree about the port, and the tooling's own comment
says why. Worse, the disagreement cannot be resolved by editing `.env`: the compose header comment
(`:9-14`) states that values under `environment:` are **overrides that win over the repo-root `.env`**,
and `SANDBOX_ADB_HOST` is listed under `environment:` at `:146`. Following `adb-tunnel.sh`'s
instructions verbatim therefore has **no effect** — the container keeps `5555`.

Two consequences, stated at the confidence the evidence supports:

- **Fact:** host port 5555 is contested between Flower's published port and the conventional
  emulator ADB port. Whichever binds first wins; the other fails.
- **NOT VERIFIED:** whether `adb connect host.docker.internal:5555` from the worker would reach an
  emulator, reach Flower's HTTP listener, or fail outright. That depends on host bind addresses and
  Docker Desktop's loopback forwarding behaviour, neither of which can be established read-only from
  inside this sandbox. It must be checked on the host before Phase 2's fail-closed behaviour lands.

This matters disproportionately because of the standing constraint recorded from the G4 work: no
dynamic run has ever been recorded under the current configuration (`761aa92` onward, which `2a8f865`
ships). Every one of the 14 `mode:"live"` blobs predates 2026-08-11.

### 2.3 Environment variables read by the live path

| Variable | Read at | Default | Set in compose? |
| --- | --- | --- | --- |
| `SANDBOX_MODE` | `sandbox_manager.py:35`; `dynamic_task.py:55` | `mobsf` / `simulate` (mismatched) | Yes — `:32` anchor and `:143` |
| `ADB_BIN` | `sandbox_manager.py:29`; `emulator_pool.py:31` | `adb` | Yes — `:147` |
| `SANDBOX_ADB_HOST` | `emulator_pool.py:41` (**import time**) | unset | Yes — `:146` |
| `EMULATOR_BIN` | `emulator_pool.py:32` | `emulator` | No |
| `SANDBOX_POOL_SIZE` | `emulator_pool.py:33` | `1` | No |
| `SANDBOX_BOOT_TIMEOUT` | `emulator_pool.py:34` | `180` | No |
| `SANDBOX_REMOTE_BOOT_TIMEOUT` | `emulator_pool.py:37` | `90` | No |
| `SANDBOX_AVD` | `emulator_pool.py:64` | `fraudshield_avd` | No |
| `SANDBOX_RUN_SECONDS` | `sandbox_manager.py:30` | `60` | No |
| `MOBSF_URL` | `sandbox_manager.py:55` | `http://localhost:8008` | No |
| `SANDBOX_EGRESS_BLOCKED_EXTERNALLY` | **nowhere** | — | No |

Four of these (`ADB_BIN`, `EMULATOR_BIN`, `SANDBOX_ADB_HOST`, plus the timeouts and `RUN_SECONDS`) are
captured as **module-level constants at import**, so they are fixed per worker process and are not
re-read between tasks.

### 2.4 Pre-flight verdict

Live mode is **configured but not currently demonstrable**, and the local-QEMU half of decision D1 is
**not executable in-container at all**. The remote path is the only viable one, it depends on three
unverified host-side facts (emulator listening, keypair present, keypair authorized), and its
configured endpoint collides with a port compose itself publishes for another service. `SANDBOX_MODE:
live` sitting in the *shared* anchor (`:32`) additionally means `backend`, `worker-static`, `beat`, and
`flower` all request live mode despite having no ADB key mount and no `extra_hosts` entry — for those
services `is_available()` is satisfiable (adb is in the image) but `adb connect` cannot resolve
`host.docker.internal`, so any dynamic work they attempted would fail into the simulate fallback.

---

## 3. G2 audit — redroid deployment unverified

### 3.1 Authoritative definition

From `docs/sandbox-hardening-plan.md:538-544`, verbatim:

> **G2 — redroid deployment unverified.** `infra/redroid/` is committed but there is no evidence it has
> ever run. `.env` contains neither `SANDBOX_ADB_HOST` nor `SANDBOX_EGRESS_BLOCKED_EXTERNALLY`. Under D1
> the code is target-agnostic, so this does **not** block Phases 0–7 — but the redroid half of D1 stays
> theoretical until the VM exists and `setup-oracle-host.sh` completes with all four probes blocked.
> Do not describe redroid containment as verified before then. **Blocks: nothing; constrains claims.**

**Both evidence clauses re-verified today and both still hold.** `.env` exists (2,622 bytes,
gitignored via `.gitignore:3`) and contains `SANDBOX_MODE=live` at line 34 with the inline comment
`# simulate | live`, but a targeted grep for `^SANDBOX`/`^ADB`/`^EMULATOR`/`^MOBSF` returns that one
line only — neither `SANDBOX_ADB_HOST` nor `SANDBOX_EGRESS_BLOCKED_EXTERNALLY` is present. G2 remains
**OPEN**.

A secondary consequence worth recording: because `.env` sets `SANDBOX_MODE=live` but no
`SANDBOX_ADB_HOST`, any invocation *outside* compose (a bare `celery`/`python` run reading only `.env`)
resolves `emulator_pool.SANDBOX_ADB_HOST = None` at import and takes the **local** branch, which
`is_available:57` can only satisfy if an `emulator` binary is on PATH. Live mode outside compose is
therefore gated on a host Android SDK that the repo never provisions.

### 3.2 What implements G2

`infra/redroid/` contains exactly two files, both executable, both untouched since 2026-08-11:

| File | Size | Role |
| --- | --- | --- |
| `setup-oracle-host.sh` | 10,066 B | Provisions the Oracle ARM VM: Docker network, iptables chain, redroid container, containment probes |
| `adb-tunnel.sh` | 6,454 B | Establishes the SSH tunnel from the developer machine to the VM's loopback-bound ADB |

There is no README in that directory.

**`setup-oracle-host.sh` — the security model it asserts** (header comment): ADB listens on
`127.0.0.1` only; the Android container sits on an egress-blocked Docker network; and — decisively for
this audit — *"In-guest `svc data disable` does NOT work here — redroid has no radio."*

Its concrete mechanisms:

- `REDROID_IMAGE="${REDROID_IMAGE:-redroid/redroid:13.0.0-arm64}"` — a mutable tag (see §4.1).
- `NET_NAME="fraudshield-sandbox"`, `NET_SUBNET="172.31.240.0/24"`, `FW_CHAIN="FRAUDSHIELD-SANDBOX"`.
- An iptables chain: `ESTABLISHED,RELATED → RETURN`; `-d 169.254.0.0/16 -j DROP` (cloud metadata);
  catch-all `-j DROP`. Hooked into both `DOCKER-USER` and `INPUT`.
- Container launch at `:132`: `$DK run -itd --privileged --name ... --network fraudshield-sandbox
  -v "$DATA_DIR":/data -p 127.0.0.1:5555:5555`. The `-p 127.0.0.1:` binding satisfies the standing
  constraint "do not expose ADB publicly"; `--privileged` is discussed in §7.
- A containment proof block at `:158-191` running four probes — ICMP to `8.8.8.8`, DNS via
  `/dev/udp/8.8.8.8/53`, TCP via `/dev/tcp/1.1.1.1/443`, and metadata `169.254.169.254:80` — matched
  against `PROBE_SUCCESS_RE='1 received|bytes from|succeeded|connected|HTTP/'`.

**`adb-tunnel.sh`** sets `LOCAL_PORT="${LOCAL_PORT:-5556}"` with the comment
`# NOT 5555 — Flower already publishes that.`, and at `:117` instructs the operator to add
`SANDBOX_EGRESS_BLOCKED_EXTERNALLY=true` (plus `SANDBOX_ADB_HOST=host.docker.internal:5556`) to the
repo-root `.env`, followed by "Recreate, don't restart — a container's env is fixed at create time."

**Application code that could drive a redroid target:** only the remote branch —
`emulator_pool.is_available:52-57`, `warm_up:71-84`, `_connect_remote:87-122`, `_wait_for_boot:155-186`,
`_harden_network:189-196`, `release:204-211`. Nothing in that code is redroid-aware.

### 3.3 What verifies G2

**Nothing.** Grep-verified across `backend/app/tests/` (14 test files, 240 collected items):

| Symbol searched | Test files matching |
| --- | --- |
| `emulator_pool`, `EmulatorPool` | 0 |
| `_harden_network` | 0 |
| `NetworkCapture`, `network_capture` | 0 |
| `adb`, `ADB_BIN` | 0 |
| `dynamic_task`, `run_dynamic_analysis` | 0 |
| `redroid` | 0 |
| `SANDBOX_ADB_HOST`, `SANDBOX_EGRESS_BLOCKED_EXTERNALLY` | 0 |

The four containment probes in `setup-oracle-host.sh:158-191` run **once at provisioning time, in
bash, out of band**. No Python code invokes them, no result is captured, and nothing writes their
outcome anywhere the application can read. This is why `containment_verified` is NULL for every row.

### 3.4 What is still missing for G2

1. The Oracle VM itself, and a completed `setup-oracle-host.sh` run with all four probes blocked.
2. `SANDBOX_ADB_HOST` and `SANDBOX_EGRESS_BLOCKED_EXTERNALLY` in `.env` — **and** removal of the
   compose `environment:` override at `:146` that would otherwise shadow the first of them.
3. Any code that reads `SANDBOX_EGRESS_BLOCKED_EXTERNALLY`. Today it is pure documentation.
4. Runtime capability detection per decision D1. `is_available` detects binaries, not containment
   properties, and `_connect_remote` cannot tell a QEMU AVD from a redroid container. The
   distinction matters precisely because `svc data disable` works on one and is a documented no-op on
   the other.
5. Reconciliation of the 5555/5556 conflict (§2.2).
6. Digest pinning (that is G5 — §4.1).

### 3.5 Can current behaviour produce false claims of successful live execution?

**Yes. Five distinct mechanisms, each independently sufficient.**

**(a) Unconditional containment success log.** `emulator_pool._harden_network:189-196` runs
`svc data disable` and `svc wifi disable` without capturing or checking either return code, then logs
`emulator.network_hardened` unconditionally at `:196`. On redroid — the D1 target — the setup script
itself documents that these commands cannot work because there is no radio. So the one in-code
containment mechanism is a no-op on that target while still emitting a success line. This is the exact
situation the standing constraint addresses: containment must be reported UNKNOWN when the probe
cannot establish the property.

**(b) Unchecked app launch.** `sandbox_manager.py:122-127` ignores `monkey`'s return code and output,
and `:128` logs `sandbox.live.launched` regardless. A sample that never started yields all-False flags
and empty `network_calls`, and the function still returns `"mode": "live"` at `:173`. `_persist` writes
`mode='live'`, and the frontend maps `case "live"` to `runtimeObserved: true` — rendering
"Suspicious behaviour observed" provenance for a run in which nothing was observed at all.

**(c) Empty-transcript indistinguishability.** If `communicate` times out, `:140-141` sets
`logcat_output = ""`. A parse of the empty string is indistinguishable from a genuinely clean sample.

**(d) Unconditional stage completion.** `dynamic_task.py:94` calls
`update_analysis_stage(submission_id, "Dynamic Analysis", "completed")` with no reference to the mode
that ran, and `:86` writes the stage detail `"capturing syscalls"` — a capability with no
implementation anywhere in the repo. Both statements are made even when the run silently fell back to
simulation.

**(e) Phantom artifact path.** `_store_log:225-227` swallows the storage exception and returns the key,
so `dynamic_findings.sandbox_log_path` can point at a blob that was never written.

Mechanisms (a) and (b) are pure G2 concerns and constrain what may be claimed about the 14 historical
live blobs. (d) is the one that reaches the user interface.

---

## 4. G5 audit — and a definitional mismatch to resolve

### 4.0 Mismatch: two different things are being called "G5"

This needs flagging before the audit itself, because adopting either framing silently would corrupt
the gate ledger.

The plan's G5 (`docs/sandbox-hardening-plan.md:583-587`) is about **emulator image pinning**:

> **G5 — Emulator image unpinned.** Neither the Android API level nor the system image is specified
> anywhere in the repo (`sandbox_security_audit.md` §8 lists both as UNKNOWN; re-verified). Behavioural
> results are therefore not reproducible across machines. Not a blocker, but containment behaviour can
> legitimately differ between API levels, so record what was actually tested against. **Blocks: nothing.**

The audit request's section 4 asks for network/security behaviour end-to-end — DNS observation,
destination IP, port/protocol, connection telemetry, isolation, egress control, fail-open/fail-closed.
In this plan's ledger that subject matter is **G1** (probe conclusiveness, `:529-536`, blocks Phase 3
completion) together with **G3** (the ML feature contract, `:546-548`, blocks Phase 5) — not G5.

Both are therefore audited below: §4.1 answers the plan's G5, §4.2 onward answers the requested
network/security trace and attributes each finding to the gate that actually governs it.

### 4.1 The plan's G5 — image pinning. Status: OPEN, re-verified

`git grep -ni "sdkmanager\|avdmanager\|system-images\|android-3[0-9]\|API level" -- backend/ infra/`
returns **no matches**. Specifically:

| Target | What is specified | What is missing |
| --- | --- | --- |
| Local QEMU | `emulator_pool.py:64` — `SANDBOX_AVD`, default `"fraudshield_avd"`; `_boot_one:137` passes only `-avd <name>` | The AVD is referenced **by name only**. No API level, no system image, no ABI, no `avdmanager create` recipe. The AVD is assumed to pre-exist on the host with unknown contents |
| redroid | `setup-oracle-host.sh` — `redroid/redroid:13.0.0-arm64` | A **mutable tag**, not a digest. Android 13 is implied by the tag but the underlying image can be republished |

So neither half of D1 is reproducible. G5 stands **OPEN**, and per its own text it blocks nothing but
constrains reproducibility claims. Two Phase 2-relevant implications: containment behaviour is
API-level dependent (Android 10+ changed background-start and overlay rules, which is exactly what
`_PATTERNS` keys on), and `-wipe-data` at `_boot_one:139` guarantees a clean *data* partition but says
nothing about which system image is being wiped back to.

### 4.2 DNS observation — none in the live path

| Mechanism | Status |
| --- | --- |
| `network_capture.NetworkCapture._run_dns_sink` — binds `FAKE_DNS_HOST` `127.0.0.1:5353`, parses DNS qnames, records `{host, port: 53, protocol: "dns", ts, sink: True}` | **Dead code.** Imported at `sandbox_manager.py:23`, never instantiated. Grep for `NetworkCapture(` finds matches only in `docs/` and `fraudshield_architecture.html` |
| `_boot_local` → `_boot_one:140` passes `-dns-server 10.0.2.15` with the comment `# fake-DNS sink — no real egress` | **Local path only, and the address is questionable.** `10.0.2.15` is the *guest's own* address in QEMU's standard slirp mapping — the emulator's own IP, not a sink the host controls. Nothing in this repo listens there. Whatever the effect is, it is not an observation mechanism: no code reads DNS results |
| Remote / redroid path | **No DNS argument at all.** `_connect_remote:87-122` never sets a resolver. The `-dns-server` flag exists only on the local branch |

Net: **zero DNS observation** reaches the database in any mode. The fabricated `sink: True` entries in
`_run_simulated:199-202` (`c2-sink.local`, `otp-collect.sink`) are the only DNS-flavoured data the
system ever persists, and they are derived from static permissions, not from a resolver.

### 4.3 Destination IP observation — none

No code anywhere resolves, captures, or records a destination IP. `_NETWORK_RE:248-251` captures a
hostname-shaped token and an optional port from log *text*. There is no `getaddrinfo`, no `netstat`, no
`ss`, no `tcpdump`, no pcap, and no `VpnService` in the tree.

### 4.4 Port / protocol observation — partly fabricated

From `_parse_logcat:273-281`: `port = int(m.group(2) or 443)` — absent an explicit port in the log line,
**443 is invented**. `"protocol": "tcp"` is a hardcoded literal; UDP, QUIC, and raw sockets are
indistinguishable and all get labelled `tcp`. `"sink": False` is likewise hardcoded on the live path
and `True` on the simulate path, making `sink` the only field that reliably separates fabricated from
scraped entries — and it is not surfaced in the UI.

### 4.5 Connection telemetry — none

There is no record of connection attempt versus success, no byte counts, no timing, no TLS metadata,
no SNI. `events` (`:268`) holds only `{"type", "line"}` with the line truncated to 200 characters.

### 4.6 Network isolation

| Layer | Mechanism | Assessment |
| --- | --- | --- |
| In-guest, in-code | `_harden_network:189-196` | Unchecked return codes, unconditional success log, and a documented no-op on redroid. See §3.5(a) |
| Local emulator | `-dns-server 10.0.2.15` (`:140`) | Not an isolation control; at most it misdirects DNS |
| Oracle host | iptables `FRAUDSHIELD-SANDBOX` chain + dedicated `172.31.240.0/24` Docker network, `setup-oracle-host.sh` | The only real egress control in the repo. Out-of-band, host-side, **unverified (G2)**. The standing constraint forbids weakening it |
| Compose | — | **No `networks:` block exists in `infra/docker-compose.yml` at all.** Single default bridge, no segmentation, no `internal: true` |

### 4.7 Egress control signalling — dead

`SANDBOX_EGRESS_BLOCKED_EXTERNALLY` is read by no application code (grep: only
`infra/redroid/adb-tunnel.sh:117` and three `docs/current-state-audit.md` references, which already
flagged this as finding S6). So even a correctly provisioned, fully egress-blocked redroid VM has no
way to tell the application that containment holds, and the application has no way to require it.

### 4.8 Fail-open vs fail-closed — currently fail-open on both axes

| Axis | Behaviour | Location |
| --- | --- | --- |
| Live execution | **Fail-open.** Any exception → simulate, result persisted, pipeline marked completed | `sandbox_manager.py:57-62`; `dynamic_task.py:94` |
| Containment | **Fail-open.** Hardening failures are invisible; `containment_verified` is never written, so NULL |  `emulator_pool.py:189-196`; `_persist:119` |
| APK materialization | **Fail-open.** Download failure logged at debug, path returned anyway | `dynamic_analysis_service.py:80-83` |
| Artifact storage | **Fail-open.** Key returned as if stored | `sandbox_manager.py:225-227` |
| Enqueue | **Fail-open.** Missing broker → upload succeeds with no dynamic analysis | `api/v1/submissions.py::_enqueue_pipeline` |

Decision D2 requires fail-closed on the first of these. Phase 2 is precisely that change.

### 4.9 Persistence of network/security state

`dynamic_findings` carries `network_calls` (JSON), `sandbox_log_path`, and — since Phase 1 — `mode`
(VARCHAR(16), indexed) and `containment_verified` (BOOLEAN, three-valued). Migration
`0007_dynamic_finding_provenance.py` is the sole head, has no `server_default` and no `UPDATE`/
`op.execute`, so legacy rows remain NULL at the DDL level. `containment_verified` is NULL for **every**
row in existence because no writer exists.

### 4.10 Frontend / API exposure

`network_calls` reaches the report payload through the dynamic section of the submission response and
is consumed alongside provenance. Provenance rendering is centralized in
`frontend/src/utils/sandboxProvenance.ts`, where `runtimeObserved: true` is reachable from exactly
**one** place — `case "live"` — with `COMPLETED_UNVERIFIED` covering NULL/`simulate`/`mobsf`.
`ReportViewer.tsx:706` switches the pill between "Suspicious behaviour observed" and "Suspicious
behaviour reported — unverified" on that flag. This single-source property was established and verified
in Phase 1 and must be preserved: a second, divergent liveness check anywhere in the frontend would
reintroduce the class of bug Phase 1 closed.

### 4.11 The ML coupling — why network fidelity cannot be improved in Phase 2

`backend/app/ml/feature_spec.py:86` feeds `float(len(dynamic.get("network_calls") or []))` into the
trained classifier as `dyn_network_calls`, with `W_CLASSIFIER = 0.60`, and `train_real.py:182` confirms
all four `dyn_*` features were **zero for every training row**. Improving network observation therefore
moves risk scores with no retraining, violating decision D3. This is gate **G3** and it blocks Phase 5,
not Phase 2 — but it is the reason `network_capture.py` must stay dead until G3 is resolved, and the
reason Phase 2 must not "fix" the dead import while it is in there.

A sharper consequence discovered during this audit: because `_parse_logcat` extracts hostnames from
arbitrary log text on any line matching tokens like `OkHttp`, **a sample can inflate
`dyn_network_calls` at will** by writing hostname-shaped strings to logcat, and — since `pkg` is
unused (§1.9) — so can any other process on the device. That makes a trained ML input
attacker-influenceable. It is a G3/Phase 5 problem to fix, but it should be recorded now.

---

## 5. Live → simulate fallback

### 5.1 Is `live failure → simulate fallback → result persisted` currently possible?

**Confirmed: yes.** It is the default behaviour of the current code, not an edge case.

| Question | Answer |
| --- | --- |
| Exact function | `backend.app.dynamic_analysis.sandbox_manager.SandboxManager.run`, lines 57-62 |
| Exact condition | `self.mode == "live"` **and** `self._run_live(...)` raises **any** `Exception` (bare `except Exception` at `:60`) |
| Exact fallback behaviour | `log.warning("sandbox.live_failed_simulate", error=str(exc))` at `:61`, then control falls out of the `if` block to `return self._run_simulated(submission_id, static_hint or {})` at `:62` |
| `mode` written | `"simulate"` — returned at `sandbox_manager.py:214`, persisted verbatim at `dynamic_analysis_service.py:118` |
| `containment_verified` written | Key absent from the result dict → `result.get(...)` yields `None` → column persists as **NULL** (`:119`) |
| Result persisted | Yes. `_persist` commits at `:120` and refreshes at `:121` |
| Pipeline outcome | `dynamic_task.py:86` sets detail `"capturing syscalls"`; `:94` marks the stage `completed`; `:96-98` advances status to `scoring` and enqueues it |

```python
        if self.mode == "live":
            try:
                return self._run_live(submission_id, apk_path, package_name)
            except Exception as exc:  # noqa: BLE001
                log.warning("sandbox.live_failed_simulate", error=str(exc))
        return self._run_simulated(submission_id, static_hint or {})
```

Every failure enumerated in §1.13 funnels here: `adb install` non-zero, `acquire`'s
`RuntimeError("No emulator available ...")`, an UNAUTHORIZED device, a boot timeout, a missing ADB key,
an unreachable host, and — per §1.14 — a Celery `SoftTimeLimitExceeded` raised inside the window.

### 5.2 What the fallback fabricates

`_run_simulated:185-215` derives the three behaviour flags from static permissions and
`sensitive_calls`, then at `:196-202`:

```python
if sensitive.get("telephony") or sensitive.get("dynamic_code") or sms:
    network_calls = [
        {"host": "c2-sink.local",   "port": 443, "protocol": "tcp", "sink": True},
        {"host": "otp-collect.sink","port": 80,  "protocol": "tcp", "sink": True},
    ]
```

These two hostnames are the fabricated C2 indicators referenced in the project's motivation. They are
written into `dynamic_findings.network_calls`, counted into the ML `dyn_network_calls` feature, and
rendered in the report.

### 5.3 Why live and configured-simulate become indistinguishable

After a fallback, compare the two states an operator can actually inspect:

| Surface | Configured `SANDBOX_MODE=simulate` | Live run that failed and fell back |
| --- | --- | --- |
| `dynamic_findings.mode` | `'simulate'` | `'simulate'` — identical |
| `dynamic_findings.containment_verified` | NULL | NULL — identical |
| `network_calls` | `c2-sink.local`, `otp-collect.sink` | identical |
| Blob `"mode"` field | `"simulate"` | `"simulate"` — identical |
| Blob `"derived_from"` | `"static_signals"` | `"static_signals"` — identical |
| API/report payload | identical | identical |
| Analysis stage | `completed` | `completed` — identical |
| Only difference | — | one `sandbox.live_failed_simulate` **stdout** log line |

The sole distinguishing signal is a structlog warning, and this project **persists no application logs
at all**: `app/core/logging.py` uses structlog's `PrintLoggerFactory` (stdout only, no FileHandler
anywhere in `backend/app/`) and compose declares no `logging:` driver, so container stdout dies with
the container. The distinction is therefore unrecoverable the moment the worker is recreated — which
is exactly why the G4 investigation had to rely on mode-stamped artifact blobs rather than logs.

This is the accepted, documented Phase 1 limitation. It is recorded in the `_persist` comment block
(`dynamic_analysis_service.py:108-117`) and asserted by
`test_dynamic_provenance.py::test_live_fallback_is_indistinguishable_from_configured_simulate` (:236)
and `::test_fallback_and_configured_simulate_persist_identically` (:269). **Both tests encode the
behaviour Phase 2 removes and must be replaced rather than quietly deleted.**

A second-order effect: because `run()` absorbs the exception, the failure never reaches
`dynamic_task`'s handler, so `max_retries=6`, the `failed` status, and `error_message` are all dead
code for live-mode failures. Phase 2's fail-closed change is what makes that machinery live.

---

## 6. Existing test coverage

Inventory is grep-derived from `backend/app/tests/`. Nothing is inferred; tests that do not exist are
listed as absent. Total: 14 test files, **240 collected items**, 240 passing.

All tests in this suite run **in-process against in-memory SQLite** (`create_engine("sqlite://")` with
`StaticPool`), using FastAPI `app.dependency_overrides` where an HTTP surface is involved. There is no
`pytest.ini`/`pyproject.toml`/`setup.cfg`, so pytest runs on defaults. `conftest.py` provides one
autouse fixture, `captured_fallbacks`, patching `emit_fallback` at four call sites to keep tests off
live Redis.

### 6.1 Tests that exist and are relevant

`app/tests/test_dynamic_provenance.py` — 14 functions expanding to **19 items** via two `parametrize`
decorators (`:163` over `["live","simulate","mobsf"]`, `:177` over the containment tri-state):

| Test | Line | Class | Covers |
| --- | --- | --- | --- |
| `test_migration_columns_are_present_on_the_model` | 143 | unit | Model/migration surface |
| `test_new_row_defaults_to_unknown_provenance` | 152 | unit | NULL = UNKNOWN |
| `test_persist_records_the_mode_the_sandbox_reported` | 164 | unit (×3) | `live`/`simulate`/`mobsf` passthrough |
| `test_persist_leaves_mode_null_when_the_result_omits_it` | 170 | unit | Missing key → NULL |
| `test_persist_preserves_containment_tristate` | 186 | unit (×4) | NULL vs False vs True distinguishable |
| `test_persist_does_not_coerce_mode_to_bool` | 193 | unit | No `bool()`/`or` coercion |
| `test_rerun_updates_provenance_on_the_existing_row` | 201 | unit | Upsert semantics |
| `test_analyze_persists_provenance_end_to_end` | 212 | integration (in-process) | `analyze()` → DB, with `_NoStorage` monkeypatch |
| `test_live_fallback_is_indistinguishable_from_configured_simulate` | 236 | unit | **Documents the fallback limitation** |
| `test_fallback_and_configured_simulate_persist_identically` | 269 | integration | Same, at the persistence layer |
| `test_schema_exposes_provenance` | 292 | integration | API schema surface |
| `test_schema_reports_legacy_rows_as_unknown` | 300 | integration | Legacy NULL handling |
| `test_scoring_input_is_unchanged_by_the_new_columns` | 345 | unit (AST-based) | Decision D3 — asserts `_fetch_dynamic` still projects exactly the four original columns |
| `test_provenance_columns_are_readable_over_raw_sql` | 380 | integration | Dialect-correct read (binds `submission_id.hex` for SQLite) |

`app/tests/test_dynamic_cluster_exposure.py` — 5 items, all **integration** via `TestClient`:
`test_with_dynamic_and_cluster` (:127), `test_without_dynamic` (:153), `test_without_cluster` (:161),
`test_both_missing` (:169), `test_existing_fields_preserved` (:177). These exercise the API exposure of
the dynamic section including `network_calls`, not sandbox behaviour.

Those two files are the **entire** relevant surface. `test_threat_intelligence.py` matches a grep for
`mode` only because of `match_mode` in a threat-intel helper (`:7-8`) — unrelated.

### 6.2 Coverage by requested category

| Category | Coverage |
| --- | --- |
| Provenance | **Good** — 19 unit + integration items, Phase 1 |
| Simulate mode | **Partial** — covered only as the fallback's destination; `_run_simulated`'s flag derivation is untested |
| Live sandbox | **None.** Zero tests reference `_run_live`, `EmulatorPool`, `emulator_pool`, `adb`, or `ADB_BIN` |
| Containment verification | **None.** Nothing tests `_harden_network`; no writer exists to test |
| Network telemetry | **None.** `_parse_logcat`, `_PATTERNS`, and `_NETWORK_RE` are wholly untested; `NetworkCapture` is untested dead code |
| G2 (redroid) | **None.** No test references redroid or the remote path |
| G5 (image pinning) | **None**, and not testable in-process by nature |
| Fallback / error handling | **Partial** — the fallback's *provenance outcome* is asserted (`:236`, `:269`); the failure *paths* into it are not. No test drives `run()` through an `_run_live` exception |
| Task orchestration | **None.** Zero tests reference `dynamic_task` or `run_dynamic_analysis`, so the unconditional `completed` at `:94` is unguarded |

### 6.3 Test classes absent entirely

- **Container tests:** none. The suite runs inside one container but nothing tests container topology, compose wiring, or the image's contents.
- **End-to-end tests:** none. No test exercises upload → static → dynamic → scoring against real services.
- **Frontend tests:** none. `frontend/` contains zero test files; `npx tsc --noEmit` is the only gate.
- **Migration tests:** none beyond `test_migration_columns_are_present_on_the_model`, which inspects the model rather than running Alembic.

---

## 7. Security boundary audit

Actual configuration as committed. No recommendations in this section.

An orientation point first: the **analysis target does not execute inside any compose container**. The
APK runs on a host emulator or on the Oracle redroid container, reached over ADB. So the compose
containers are not a malware sandbox; they are the *orchestrator*, and the boundary questions below are
about what the orchestrator holds and what it can reach.

| Asset | Exposure | Evidence |
| --- | --- | --- |
| Docker socket | **Not exposed.** No `/var/run/docker.sock` mount anywhere | `git grep -n "docker.sock" -- infra/ backend/Dockerfile` → no matches |
| Elevated capabilities (compose) | **None.** No `privileged`, `cap_add`, `devices:`, or `security_opt` on any service | Same grep; the **only** `--privileged` in the repo is `setup-oracle-host.sh:132` |
| Host filesystem | **Two read-only file mounts only** — `~/.android/adbkey` and `~/.android/adbkey.pub` on worker-dynamic. Plus the named volume `apk_storage`. No source bind-mount exists | `infra/docker-compose.yml:156-161` |
| Runtime user | Non-root uid 1000 `appuser` | `backend/Dockerfile:36`, `:46` |
| **ADB access** | **Present and privileged in effect.** worker-dynamic holds the host developer's ADB **private key** and can reach `host.docker.internal:5555`. ADB confers device shell plus `push`/`pull`. The mounted key is the operator's personal `~/.android/adbkey`, i.e. the same identity authorized on any other device that developer owns | `:146`, `:158-163` |
| `JWT_SECRET` | **Hardcoded in the compose file** and injected into **every** backend-derived service, including worker-dynamic, beat, and flower | `:27` in the `x-backend-env` anchor |
| Database credentials | `fraudshield:fraudshield` in `DATABASE_URL` in every service env; Postgres also published | `:24`, `:56-58`, `:59-60` (`5433:5432`) |
| Redis | Published `6379:6379` with **no password** — `redis:7-alpine` with no `command` override and no `requirepass` | `:82-91` |
| RabbitMQ | Published `5672` **and** management UI `15672`, default `guest:guest` credentials in `RABBITMQ_URL` | `:26`, `:70-80` |
| Flower | Published `5555:5555` with **no authentication flags** on the `celery ... flower` command. Flower exposes task arguments and worker control | `:179`, `:190-191` |
| Bind interfaces | **Every** published port omits a `127.0.0.1:` prefix, so all bind on all interfaces: 5433, 5672, 15672, 6379, 8000, 5555, 5173 | `:59-60`, `:72-74`, `:84-85`, `:108-109`, `:190-191`, `:203-204` |
| Outbound network | **Unrestricted.** `infra/docker-compose.yml` declares **no `networks:` section at all** → implicit default bridge, default-allow egress, no segmentation, no `internal: true` | whole-file read |
| Sensitive env vars | `env_file: ../.env` on the shared `x-backend-base` (`:44-46`) injects the full `.env` into every backend service, worker-dynamic included: `GROQ_API_KEY`, `GEMINI_API_KEY`, `CLAUDE_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `STORAGE_*`, `JWT_SECRET`. `STORAGE_KEY`/`STORAGE_SECRET` are empty, so storage resolves to `LocalStorage` | `.env` key inventory (values not read) |
| Sandbox escape surface | On the Oracle host, redroid runs `--privileged` with `-v "$DATA_DIR":/data`. `--privileged` is a documented container-escape surface. ADB is correctly bound `127.0.0.1:5555` only, satisfying "do not expose ADB publicly" | `setup-oracle-host.sh:132` |
| Egress control (real) | Only the host-side iptables `FRAUDSHIELD-SANDBOX` chain, unverified per G2 | `setup-oracle-host.sh` |

Two findings deserve emphasis because they are properties of the *live* configuration specifically:

1. **The worker that handles untrusted samples is also the worker holding the ADB private key, the JWT
   signing secret, database credentials, and every third-party API key** — a consequence of
   `x-backend-env` and `env_file` being shared anchors rather than per-service. Nothing in the current
   design contains a compromise of worker-dynamic.
2. **`SANDBOX_MODE: live` is in the shared anchor** (`:32`), so `backend`, `worker-static`, `beat`, and
   `flower` all request live mode without the ADB key mount or `extra_hosts`. worker-dynamic re-declares
   it at `:143` redundantly.

---

## 8. Phase 2 change surface

Derived from repository state only. Nothing below was modified.

### 8.1 Required

| File | Why it changes | Behaviour change |
| --- | --- | --- |
| `backend/app/dynamic_analysis/sandbox_manager.py` | The fallback at `:57-62` is the fail-open defect D2 targets | Replace the bare `except Exception` with a raise (a typed sandbox error). `mode="simulate"` becomes reachable only when explicitly configured. Note the `mobsf` branch at `:47-56` has the *same* fallback shape and must be decided deliberately, not silently inherited |
| `backend/app/services/dynamic_analysis_service.py` | Must let the failure propagate, and `_materialize_apk:80-83` must not swallow a download failure when live mode requires the bytes | Live failures reach the task instead of producing a row. `_persist`'s Phase 1 comment block (`:108-117`) needs rewriting since it documents a limitation being removed |
| `backend/app/workers/tasks/dynamic_task.py` | Three defects: the unconditional `completed` at `:94`, the false `"capturing syscalls"` detail at `:86`, and the `SANDBOX_MODE` default mismatch at `:55` (`simulate`) versus `sandbox_manager.py:35` (`mobsf`) | Stage becomes `failed` with the real reason on live failure. The existing retry/`MaxRetriesExceededError` machinery (`:103-119`) becomes reachable for the first time — decide whether a broken emulator should burn 6 retries at 15 s |
| `backend/app/tests/test_dynamic_provenance.py` | `test_live_fallback_is_indistinguishable_from_configured_simulate` (:236) and `test_fallback_and_configured_simulate_persist_identically` (:269) assert the behaviour being removed | Both **replaced** — not deleted — with fail-closed assertions. Expect the 240 gate to move; state the new count and delta explicitly |
| `backend/app/tests/` (new file or additions) | No test exists for the live path, the fallback trigger, or task orchestration (§6.2) | New coverage: live failure raises; no row is written; stage becomes failed; configured-simulate still works |
| `docs/sandbox-hardening-plan.md` | Phase status and gate ledger | Documentation only |

### 8.2 Required for configuration coherence

| File | Why | Required? |
| --- | --- | --- |
| `infra/docker-compose.yml` | `SANDBOX_MODE: live` in the shared anchor `:32` makes four non-ADB services request live mode — under fail-closed that turns a previously silent degradation into visible failures. The `SANDBOX_ADB_HOST: ...:5555` at `:146` collides with Flower's published 5555 (`:190-191`) and overrides `.env`, so the documented redroid wiring cannot take effect | **Required** — fail-closed without this converts a latent misconfiguration into broken submissions |
| `.env` (operator action, not a repo change) | Lacks `SANDBOX_ADB_HOST` and `SANDBOX_EGRESS_BLOCKED_EXTERNALLY` | Required before live can be exercised |

### 8.3 Optional in Phase 2 / owned by later phases

| File | Why | Phase |
| --- | --- | --- |
| `backend/app/dynamic_analysis/emulator_pool.py` | `_harden_network:189-196` must check return codes and report status rather than logging success unconditionally; `release:204-211` skips `pm clear-all` for remote devices; `shutdown:213` has no callers; `SANDBOX_ADB_HOST` is captured at import (`:41`); `_connect_remote:120-122` flattens the actionable UNAUTHORIZED/timeout reasons into `False`. D1 capability detection also lands here | Partly Phase 2 (error propagation), mainly **Phase 3** (containment probing) |
| `backend/app/dynamic_analysis/network_capture.py` | Dead code: imported at `sandbox_manager.py:23`, never instantiated | **Phase 5**, gated on G3. Do not wire or delete in Phase 2 |
| `backend/app/dynamic_analysis/frida_hooks.py` | Dead code: zero importers, though `frida==16.4.8` is installed | Out of Phase 2 scope; a deletion decision, not a behaviour change |
| Docstrings claiming Frida instrumentation — `sandbox_manager.py:6-7`, `dynamic_analysis_service.py:4`, `models/dynamic_finding.py:40` | Factually wrong (§1.8) | Optional; comment-only, and `dynamic_finding.py:39` already received the same treatment in Phase 1 |
| `frontend/src/utils/sandboxProvenance.ts` + `ReportViewer.tsx` | A distinct "dynamic analysis failed" state becomes representable once failures surface | Optional in Phase 2. **Preserve** the single-source `runtimeObserved` property |
| `infra/redroid/setup-oracle-host.sh` | Digest pinning (G5); probe logic greps success strings so an unsupported `/dev/tcp` reads as "blocked" (G1 false negative) | **G5 / Phase 3** |
| `infra/redroid/adb-tunnel.sh` | Port reconciliation with compose | With the compose change |
| `backend/app/ml/feature_spec.py` | `dyn_network_calls` coupling | **Phase 5**, blocked by G3 |

### 8.4 Explicitly not needed

**No migration.** `0007` already provides both `mode` and `containment_verified` as nullable columns
with the correct three-valued semantics. Phase 2 changes *which values get written and when*, not the
schema. `0007` must remain the sole head and must not be edited.

---

## 9. Phase 2 risks

| # | Risk | Evidence | Severity |
| --- | --- | --- | --- |
| R1 | **Silent fallback** — the defect Phase 2 removes | `sandbox_manager.py:57-62` | Critical |
| R2 | **False provenance** — `mode='live'` is returned even when `monkey` never launched the app, because the return code is unchecked, and the frontend maps `live` → `runtimeObserved: true`. Fail-closed does **not** fix this: it is a false *positive*, orthogonal to the false negative | `:122-127`, `:173` | Critical |
| R3 | **False containment claims** — `emulator.network_hardened` logged unconditionally; the mechanism is a documented no-op on redroid | `emulator_pool.py:189-196`; `setup-oracle-host.sh` header | Critical |
| R4 | **Fail-closed may fail everything** — no dynamic run has ever been recorded under the current config; all 14 live blobs predate 2026-08-11; the configured ADB port collides with Flower's. If live is currently broken, Phase 2 turns every submission red and it will look like Phase 2's fault | G4 record; §2.2 | **Highest process risk** |
| R5 | **Timeout escapes containment** — `SoftTimeLimitExceeded` subclasses `Exception`, so it is caught by the catch-all at `:60` and converted into a fabricated simulate result | `celery_app.py:63-64`; `sandbox_manager.py:60` | High |
| R6 | **Duplicate execution** — the 900 s hard limit kills the worker; `task_acks_late=True` + `task_reject_on_worker_lost=True` redeliver; `_persist` upserts, hiding it | `celery_app.py:52-53` | Medium |
| R7 | **Stale device state** — `release:205` skips `pm clear-all` for remote devices, i.e. for the only viable in-container path and the only redroid path. Combined with the swallowed `uninstall` failure, samples can accumulate | `emulator_pool.py:204-211`; `sandbox_manager.py:147-157` | High |
| R8 | **Cross-sample attribution** — `_parse_logcat` accepts `pkg` and never uses it, so device-wide logcat is attributed to the current sample. Compounds R7 | `sandbox_manager.py:254-284` | High |
| R9 | **Attacker-influenceable ML input** — `dyn_network_calls` is `len(network_calls)`, and entries are hostname-shaped tokens scraped from arbitrary log text | `feature_spec.py:86`; `sandbox_manager.py:271-281` | High (G3/Phase 5) |
| R10 | **Telemetry gaps** — no DNS, no destination IP, no real protocol, no connection state, no syscalls, no instrumentation. Port 443 is invented when absent | §4.2-4.5 | High |
| R11 | **Unrestricted egress** — compose declares no networks at all; the only real control is unverified host-side iptables | §4.6 | High |
| R12 | **Sandbox escape surface** — redroid runs `--privileged`; worker-dynamic holds the ADB private key alongside `JWT_SECRET`, DB credentials, and all API keys | §7 | High |
| R13 | **Race conditions** — `SANDBOX_ADB_HOST` fixed at import; a fresh `EmulatorPool` per `SandboxManager` means `warm_up`'s `self._lock` (`:76`) provides no cross-task mutual exclusion, so two pools would independently `_connect_remote` and `_harden_network` the same device. `--concurrency=1` (`:140`) masks this today | `emulator_pool.py:41`, `:63-84`; `sandbox_manager.py:37` | Medium |
| R14 | **Phantom artifact paths** — `_store_log` returns the key after a storage failure | `sandbox_manager.py:225-227` | Medium |
| R15 | **Retry storm under fail-closed** — reaching `dynamic_task`'s handler for the first time means 6 retries × 15 s per submission against a dead emulator | `dynamic_task.py:44-48`, `:103-119` | Medium |
| R16 | **Unreachable `mobsf` mode** — the branch exists and prints a hint for a compose service that does not exist | `sandbox_manager.py:47-56`; compose has no `mobsf` | Low |
| R17 | **Test-gate churn** — two Phase 1 tests encode the removed behaviour and must be replaced, moving the 240 gate | §8.1 | Low, but must be stated up front |

---

# 10. FINAL REPORT

## A. CURRENT LIVE PATH

`POST /api/v1/submissions` (`api/v1/submissions.py`, multipart `UploadFile`, validated by
`utils/validators.py::validate_apk_upload`) → `_enqueue_pipeline` sends
`app.workers.tasks.dynamic_task.run_dynamic_analysis` by name to `dynamic_queue` inside a swallowed
`try/except` → `dynamic_task.run_dynamic_analysis:49` (reads `SANDBOX_MODE` at `:55` **only** for the
wait-for-static loop) → `DynamicAnalysisService.analyze:36` (`_static_hint:63`, `mkdtemp:44`,
`_materialize_apk:75` which swallows download failure) → `SandboxManager.__init__:34` selects the mode
from `SANDBOX_MODE` with default `mobsf`, constructing `EmulatorPool` at `:37` → `run:44` dispatches at
`:57` → `_run_live:98`.

Inside `_run_live`: `EmulatorPool.acquire:199` → `warm_up:71` → `is_available:52` → `_connect_remote:87`
(remote) or `_boot_local:125`/`_boot_one:134` (local) → `_wait_for_boot:155` → `_harden_network:189` →
`adb install --bypass-low-target-sdk-block -r -d -t` at `:107` (**return code checked**, raises) →
`logcat -c` at `:118` → `monkey` launch at `:122` (**return code NOT checked**) → `Popen` logcat +
`time.sleep(RUN_SECONDS)` at `:131-135` → `_parse_logcat:254` (regex over log text; `pkg` accepted and
never used) → `finally` at `:147` force-stop + uninstall inside `except Exception: pass`, then
`release:204` which skips `pm clear-all` for remote devices → `_store_log:218` (swallows storage
failure, returns key anyway) → returns `"mode": "live"` at `:173` →
`dynamic_analysis_service._persist:85` writes flags, `network_calls`, `sandbox_log_path`, and the two
uncoerced provenance columns at `:118-119` → `dynamic_task:86` writes the false detail
`"capturing syscalls"`, `:94` marks the stage `completed` unconditionally, `:96-98` advances to scoring.

**Instrumentation is absent.** `frida_hooks.py` has zero importers and `network_capture.py` is never
instantiated, despite docstrings at `sandbox_manager.py:6-7`, `dynamic_analysis_service.py:4`, and
`models/dynamic_finding.py:40` claiming Frida instrumentation. Timeouts are per-subprocess (5-120 s),
boot 90 s remote / 180 s local, `acquire` 180 s, Celery soft 840 s / hard 900 s.

## B. G2 STATUS

**OPEN.** Both evidence clauses in `docs/sandbox-hardening-plan.md:538-544` re-verified today:
`infra/redroid/` holds exactly two scripts with no evidence of ever having run, and `.env` contains
`SANDBOX_MODE=live` at line 34 but **neither** `SANDBOX_ADB_HOST` **nor**
`SANDBOX_EGRESS_BLOCKED_EXTERNALLY`. Per the plan, G2 blocks nothing but constrains claims.

Implementation: `setup-oracle-host.sh` (network `172.31.240.0/24`, chain `FRAUDSHIELD-SANDBOX`,
`--privileged` container at `:132`, ADB bound `127.0.0.1:5555`, four out-of-band containment probes at
`:158-191`) and `adb-tunnel.sh` (`LOCAL_PORT` default **5556**, "NOT 5555 — Flower already publishes
that"). Application-side, only `emulator_pool`'s remote branch can drive it, and that code is not
redroid-aware.

Tests verifying G2: **zero**. Grep across all 14 test files finds no reference to `emulator_pool`,
`EmulatorPool`, `_harden_network`, `NetworkCapture`, `adb`, `redroid`, `dynamic_task`, or either
environment variable.

Still missing: the VM; both `.env` variables plus removal of the compose override that shadows the
first; any reader of `SANDBOX_EGRESS_BLOCKED_EXTERNALLY`; D1 runtime capability detection; and the
5555/5556 reconciliation.

**Can current behaviour produce false claims of successful live execution? Yes — five mechanisms:**
(a) `_harden_network:189-196` logs `emulator.network_hardened` unconditionally, and the mechanism is a
documented no-op on redroid; (b) `monkey`'s return code is unchecked at `:122-127` yet `mode: "live"` is
still returned, which the frontend renders as `runtimeObserved: true`; (c) a killed logcat yields
`logcat_output = ""`, indistinguishable from a clean sample; (d) `dynamic_task.py:94` marks the stage
`completed` regardless of mode and `:86` claims syscall capture that does not exist; (e)
`_store_log:225-227` returns a path to a blob that may never have been written.

## C. G5 STATUS

**Two different things are being called G5; both are reported rather than silently merging them.**

**The plan's G5 (`:583-587`) — emulator image unpinned. OPEN, re-verified.**
`git grep -ni "sdkmanager\|avdmanager\|system-images\|android-3[0-9]\|API level" -- backend/ infra/`
returns no matches. Local QEMU is referenced by AVD *name* only (`emulator_pool.py:64`,
`_boot_one:137`), with no API level, system image, or ABI anywhere; redroid is pinned to the **mutable
tag** `redroid/redroid:13.0.0-arm64`, not a digest. Blocks nothing; constrains reproducibility.

**The requested network/security subject matter is governed by G1 and G3, not G5.** G1
(`:529-536`, blocks Phase 3 completion) covers probe conclusiveness — and the probe block at
`setup-oracle-host.sh:158-191` greps for success strings, so an unsupported `/dev/tcp` under mksh
produces no match and is reported "blocked": a false negative, exactly G1. G3 (`:546-548`, blocks
Phase 5) covers the ML coupling.

End-to-end network behaviour: **DNS observation — none** (`NetworkCapture._run_dns_sink` never
instantiated; `-dns-server 10.0.2.15` is local-branch-only and points at the guest's own address;
remote path sets no resolver). **Destination IP — never observed.** **Port/protocol — partly
fabricated** (443 invented when absent, `"tcp"` hardcoded). **Connection telemetry — none.**
**Isolation** — in-code `_harden_network` only, unchecked and a redroid no-op; real control is
host-side iptables, unverified; compose declares **no `networks:` block at all**. **Egress control
signal — dead** (`SANDBOX_EGRESS_BLOCKED_EXTERNALLY` read by no code). **Fail-open on every axis**
(execution, containment, materialization, storage, enqueue). **Persistence** — `network_calls`,
`sandbox_log_path`, `mode`, and `containment_verified`, the last NULL for every row because no writer
exists. **Frontend/API** — `network_calls` in the dynamic section; provenance via
`sandboxProvenance.ts`, where `runtimeObserved: true` is reachable from exactly one place (`case
"live"`), consumed at `ReportViewer.tsx:706`.

## D. LIVE PRE-FLIGHT STATUS

**Configured, not demonstrable.** `adb` is **available** in the image; `SANDBOX_MODE: live`,
`SANDBOX_ADB_HOST`, `ADB_BIN`, the key mounts, and `extra_hosts` are **configured**; the emulator binary
and Android SDK are **missing** from the image, so local-QEMU live mode is impossible in-container and
every live run is forced onto the remote path; the redroid image is **configured but tag-pinned and not
verified**; a `mobsf` compose service is **missing** although `sandbox_manager.py:56` advertises it;
`SANDBOX_EGRESS_BLOCKED_EXTERNALLY`, containment verification, and D1 capability detection are
**missing**; and three host-side facts are **not verified** — emulator listening, keypair present,
keypair authorized.

One concrete configuration defect: compose publishes host port **5555** for Flower (`:190-191`) while
telling worker-dynamic to reach the emulator at `host.docker.internal:5555` (`:146`).
`adb-tunnel.sh` deliberately uses 5556 and says why. Because compose `environment:` overrides
`.env` (`:9-14`), the documented redroid wiring cannot take effect by editing `.env` alone. Whether
`adb connect` currently reaches an emulator, reaches Flower, or fails is **NOT VERIFIED** and must be
checked on the host. Also: `SANDBOX_MODE: live` sits in the *shared* anchor, so `backend`,
`worker-static`, `beat`, and `flower` all request live mode without ADB keys or `extra_hosts`.

## E. FALLBACK BEHAVIOR

**`live failure → simulate fallback → result persisted` is confirmed possible and is the current
default.** Function `SandboxManager.run`, lines 57-62. Condition: `self.mode == "live"` and
`_run_live` raises **any** `Exception`. Behaviour: `log.warning("sandbox.live_failed_simulate")` then
fall through to `_run_simulated` at `:62`. Provenance written: `mode='simulate'` (from `:214`, persisted
at `dynamic_analysis_service.py:118`); `containment_verified` **NULL** because the key is absent and
`_persist:119` performs no coercion. The row is committed at `:120`, the stage is marked `completed`
at `dynamic_task.py:94`, and the pipeline advances to scoring.

Indistinguishability: after a fallback, `mode`, `containment_verified`, `network_calls` (the fabricated
`c2-sink.local` and `otp-collect.sink` from `:199-202`), the blob's `"mode"` and `"derived_from"`
fields, the API payload, and the analysis stage are **byte-identical** to a configured simulate run.
The only difference is one structlog warning on **stdout**, and this project persists no application
logs at all (`PrintLoggerFactory`, no compose `logging:` driver), so the distinction is unrecoverable
once the container is recreated. Because `run()` absorbs the exception, `dynamic_task`'s retry and
`failed`-status machinery is currently dead code for live failures.

## F. EXISTING TEST COVERAGE

14 test files, 240 collected items, all in-process against in-memory SQLite. Nothing inferred.

Relevant tests exist in exactly two files. `test_dynamic_provenance.py` — 14 functions / 19 items:
`test_migration_columns_are_present_on_the_model` (unit), `test_new_row_defaults_to_unknown_provenance`
(unit), `test_persist_records_the_mode_the_sandbox_reported` (unit ×3),
`test_persist_leaves_mode_null_when_the_result_omits_it` (unit),
`test_persist_preserves_containment_tristate` (unit ×4), `test_persist_does_not_coerce_mode_to_bool`
(unit), `test_rerun_updates_provenance_on_the_existing_row` (unit),
`test_analyze_persists_provenance_end_to_end` (integration),
`test_live_fallback_is_indistinguishable_from_configured_simulate` (unit),
`test_fallback_and_configured_simulate_persist_identically` (integration),
`test_schema_exposes_provenance` (integration), `test_schema_reports_legacy_rows_as_unknown`
(integration), `test_scoring_input_is_unchanged_by_the_new_columns` (unit, AST-based, guards D3),
`test_provenance_columns_are_readable_over_raw_sql` (integration).
`test_dynamic_cluster_exposure.py` — 5 integration tests via `TestClient`.

By category: provenance **good**; simulate **partial**; fallback/error handling **partial** (outcome
asserted, trigger paths not); live sandbox, containment verification, network telemetry, G2, G5, and
task orchestration all **none**. **Zero container tests, zero end-to-end tests, zero frontend tests.**

## G. SECURITY BOUNDARY FINDINGS

The analysis target does not run in any compose container — it runs on a host emulator or the Oracle
redroid container over ADB. So compose is the orchestrator, not the sandbox.

Not exposed: Docker socket (no `docker.sock` mount anywhere); elevated capabilities (no `privileged`,
`cap_add`, `devices:`, or `security_opt` on any compose service); host filesystem beyond two read-only
ADB key files. Worker runs as non-root uid 1000.

Exposed as configured: the host developer's **ADB private key** in worker-dynamic, conferring device
shell plus push/pull; `JWT_SECRET` hardcoded at compose `:27` and injected into every backend service;
DB credentials `fraudshield:fraudshield` everywhere plus Postgres on `5433`; **Redis on 6379 with no
password**; **RabbitMQ 5672 + management 15672 on default guest:guest**; **Flower on 5555 with no
authentication**; every published port bound on all interfaces with no `127.0.0.1:` prefix;
**unrestricted outbound egress** because compose declares no `networks:` section at all; and the entire
`.env` — `GROQ_API_KEY`, `GEMINI_API_KEY`, `CLAUDE_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`,
`STORAGE_*` — injected into every backend service via the shared `env_file`. On the Oracle host, redroid
runs `--privileged` with a `/data` bind, though ADB is correctly bound `127.0.0.1:5555` only.

The structural point: the worker handling untrusted samples is also the worker holding the ADB private
key, the JWT signing secret, database credentials, and every third-party API key.

## H. PHASE 2 CHANGE SURFACE

**Required:** `sandbox_manager.py` (remove the `:57-62` fallback; decide the identical `mobsf` fallback
at `:47-56` deliberately); `dynamic_analysis_service.py` (propagate the failure; stop swallowing
`_materialize_apk` at `:80-83`; rewrite the `_persist` comment block at `:108-117`);
`dynamic_task.py` (the unconditional `completed` at `:94`, the false `"capturing syscalls"` at `:86`, and
the `SANDBOX_MODE` default mismatch at `:55` versus `sandbox_manager.py:35`);
`test_dynamic_provenance.py` (**replace**, not delete, the two tests at `:236` and `:269`); new
fail-closed tests; `docs/sandbox-hardening-plan.md`.

**Required for coherence:** `infra/docker-compose.yml` — move `SANDBOX_MODE` out of the shared anchor
and resolve the 5555 collision, because fail-closed converts today's silent degradation on four
services into visible failures. Plus the two `.env` variables as an operator action.

**Optional / later phases:** `emulator_pool.py` (return-code checking, remote `pm clear-all`, unused
`shutdown`, import-time `SANDBOX_ADB_HOST`, flattened error reasons in `_connect_remote:120-122`, D1
detection — mainly Phase 3); `network_capture.py` (Phase 5, blocked by G3 — do not touch in Phase 2);
`frida_hooks.py` and the three Frida docstrings; the frontend failed-state (preserving the
single-source `runtimeObserved` property); `infra/redroid/*` (G5 digest pinning, G1 probe logic);
`feature_spec.py` (Phase 5).

**Explicitly not needed: no migration.** `0007` already supplies both columns with correct three-valued
semantics; Phase 2 changes which values are written, not the schema. `0007` stays the sole head,
unedited.

## I. BLOCKERS

1. **Live health under the current configuration is unverified, and this is the real blocker.** No
   dynamic run has ever been recorded under `761aa92`-onward config; all 14 `mode:"live"` blobs predate
   2026-08-11. Landing fail-closed before confirming live works would turn every submission red for a
   stale ADB authorization and it would look like Phase 2's fault. The G4 record already flags this as a
   Phase 2 pre-flight requirement.
2. **The 5555 port collision** between Flower's published port and `SANDBOX_ADB_HOST`, unresolvable via
   `.env` because compose `environment:` wins. Must be settled before live can be exercised.
3. **Decide the `mobsf` branch.** It carries the same fallback shape at `:47-56` for a service that does
   not exist in compose. Fixing only the live branch leaves a second silent-degradation path.
4. **False-positive provenance (R2) is not fixed by fail-closed.** `mode='live'` with an unchecked
   `monkey` return code produces "runtime observed" for a run in which nothing ran. Confirm whether
   checking that return code is in Phase 2's scope or deferred, since it is a behaviour change to the
   live path.
5. **Two Phase 1 tests must be replaced**, moving the 240 gate. Agree the expected new count before
   implementation so the delta is explainable.
6. **G2 and G5 remain OPEN** and constrain claims: no statement that redroid containment is verified,
   and no reproducibility claim across API levels.
7. Retry policy under fail-closed (R15) — 6 retries × 15 s against a dead emulator per submission.

## J. RECOMMENDED IMPLEMENTATION ORDER

1. **Host pre-flight first, before any code change.** Confirm on the host whether live works under the
   current configuration: is an emulator listening, does `~/.android/adbkey` exist, is it authorized,
   and what actually answers on host port 5555. This is read-only and it decides whether Phase 2 is
   safe to land at all. It also closes blockers 1 and 2.
2. **Resolve the port and mode-scoping configuration** in compose, then re-run the pre-flight. Nothing
   downstream is meaningful until a live run succeeds under the current config.
3. **Settle the four scope questions** with explicit approval: the `mobsf` branch, whether the `monkey`
   return code is checked in Phase 2, the retry policy, and the expected post-Phase-2 test count.
4. **Implement fail-closed** in `sandbox_manager.run`, letting the typed error propagate through
   `dynamic_analysis_service.analyze` to `dynamic_task`, and make the stage report the real reason
   instead of unconditional `completed`. Smallest possible diff; no emulator or network changes.
5. **Replace the two Phase 1 fallback tests** and add coverage for the live failure paths and task
   orchestration — the first tests this repo will have for either.
6. **Rebuild `worker-static` first** (`COPY . .` at `Dockerfile:33`, no source bind-mount), then run the
   full gate and report the exact new count and delta against 240.
7. **Then Phase 3** for containment probing, which is where `_harden_network`'s return codes, G1 probe
   conclusiveness, and the first `containment_verified` writer belong. Leave `network_capture.py` alone
   until G3 is resolved in Phase 5.

---

## 11. Host-Side ADB/Docker Pre-Flight — Verified Evidence (2026-08-17)

> **Nature of this section:** All 11 items below are host-verified observations recorded from live
> `lsof`, `ps`, `adb`, `docker`, and in-container commands run on the developer Mac. No application
> code, test, migration, configuration, Dockerfile, or environment file was modified to produce them.
> Phase 2 has NOT been started.

### 11.1 Running containers

```
CONTAINER                      STATUS         PORTS (published)
fraudshield-worker-dynamic-1   Up             8000/tcp (internal only)
fraudshield-worker-static-1    Up             8000/tcp (internal only)
fraudshield-backend-1          Up (healthy)   0.0.0.0:8000->8000/tcp
fraudshield-flower-1           Up             0.0.0.0:5555->5555/tcp  [::]:5555->5555/tcp
fraudshield-beat-1             Up             8000/tcp (internal only)
fraudshield-frontend-1         Up             0.0.0.0:5173->80/tcp
fraudshield-redis-1            Up (healthy)   0.0.0.0:6379->6379/tcp
fraudshield-rabbitmq-1         Up (healthy)   0.0.0.0:5672, 0.0.0.0:15672/tcp
fraudshield-postgres-1         Up (healthy)   0.0.0.0:5433->5432/tcp
```

All services are running. `worker-dynamic` is up. Stack is healthy.

### 11.2 Host ADB keypair

```
~/.android/adbkey      mode 600  (private key, present)
~/.android/adbkey.pub  mode 644  (public key, present, 734 bytes)
```

**Verified:** The keypair exists on the host. The Compose read-only mounts
(`~/.android/adbkey:/home/appuser/.android/adbkey:ro`) would succeed — no directory-creation-on-mount
failure.

### 11.3 Host ADB sees an authorized local QEMU emulator

```
adb devices -l

List of devices attached
emulator-5554  device  product:sdk_gphone16k_arm64  model:sdk_gphone16k_arm64
                       device:emu64a16k  transport_id:14
```

**Verified:** A local QEMU emulator is running and authorized on the host.

### 11.4 Host port 5555 ownership — host-verified, defect confirmed

```
lsof -nP -iTCP:5555 -sTCP:LISTEN

COMMAND    PID         USER   FD   TYPE  DEVICE  NODE  NAME
com.docke  8943  pulkitverma  ...  IPv6   ...    TCP   *:5555 (LISTEN)   ← Docker Desktop / Flower
qemu-syst 36850  pulkitverma  ...  IPv4   ...    TCP   127.0.0.1:5555 (LISTEN)  ← QEMU emulator
qemu-syst 36850  pulkitverma  ...  IPv6   ...    TCP   [::1]:5555 (LISTEN)      ← QEMU emulator
```

Three listeners on port 5555, two different owners:

| Owner | Bind address | What it is |
| --- | --- | --- |
| `com.docke` (Docker Desktop / Flower) | `*:5555` (all interfaces, wildcard) | Celery Flower UI published by `infra/docker-compose.yml:190-191` |
| `qemu-system` | `127.0.0.1:5555` | Local QEMU Android emulator ADB interface |
| `qemu-system` | `[::1]:5555` | Same, IPv6 loopback |

**Defect status upgraded from "latent/unresolved" to host-verified:** Flower holds the wildcard bind.
This is **not** latent — it is an observable, confirmed collision in the running environment.

### 11.5 No tunnel running — host-verified

```
ps aux | grep -Ei 'adb-tunnel|ssh.*5556|ssh.*5555|socat' | grep -v grep
→ (no output)

lsof -nP -iTCP:5556
→ (no output)
```

**Verified:** `adb-tunnel.sh` is **not running**. Nothing is listening on host port 5556. The
project's intended `Mac 127.0.0.1:5556 → SSH → Oracle VM 127.0.0.1:5555 → redroid` path does not
exist as a live circuit.

### 11.6 Effective Compose configuration for worker-dynamic (confirmed)

From `infra/docker-compose.yml` lines 138–163, as-deployed:

```yaml
SANDBOX_ADB_HOST: "host.docker.internal:5555"
SANDBOX_MODE: live
ADB_BIN: adb
extra_hosts:
  - "host.docker.internal:host-gateway"
volumes:
  - apk_storage:/tmp/fraudshield-storage
  - ~/.android/adbkey:/home/appuser/.android/adbkey:ro
  - ~/.android/adbkey.pub:/home/appuser/.android/adbkey.pub:ro
```

### 11.7 What worker-dynamic actually connects to on port 5555

Executed **inside** `fraudshield-worker-dynamic-1`:

```python
import socket
s = socket.create_connection(('host.docker.internal', 5555), 5)
print('CONNECTED:', s.getpeername())
s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
print(s.recv(500).decode(errors='replace'))
s.close()
```

Result:
```
CONNECTED: ('192.168.65.254', 5555)
[HTTP response from Flower UI — not an ADB handshake]
```

**Critical finding, host-verified:** `host.docker.internal:5555` from inside `worker-dynamic`
resolves to `192.168.65.254:5555`, which is the Docker Desktop host bridge IP. The wildcard Flower
listener (`*:5555`) answers the connection. **The worker is talking HTTP to the Flower UI, not ADB
to an Android emulator.**

TCP reachability of port 5555 does NOT establish ADB reachability. It only establishes TCP
connectivity to the first process that holds the wildcard bind — which is Flower.

### 11.8 Port 5556 is unavailable from worker-dynamic

```
port 5555: OPEN  → Flower (confirmed above)
port 5556: CLOSED — OSError [Errno 101] Network is unreachable
```

Port 5556 is unreachable because no tunnel is running and nothing is bound there. The intended
`SANDBOX_ADB_HOST=host.docker.internal:5556` path does not exist as a live circuit.

### 11.9 adb-tunnel.sh port design (re-confirmed from source)

`infra/redroid/adb-tunnel.sh` line 25:
```bash
LOCAL_PORT="${LOCAL_PORT:-5556}"   # NOT 5555 — Flower already publishes that.
```

The script explicitly documents the collision and reserves 5556 for the ADB tunnel. After a
successful tunnel setup, the script instructs the operator to set:
```
SANDBOX_ADB_HOST=host.docker.internal:5556
SANDBOX_EGRESS_BLOCKED_EXTERNALLY=true
```

### 11.10 setup-oracle-host.sh redroid target (re-confirmed from source)

`infra/redroid/setup-oracle-host.sh` line 137:
```bash
-p 127.0.0.1:5555:5555
```

On the Oracle VM, redroid ADB is bound to `127.0.0.1:5555` (loopback only, never the public
interface). The intended ADB path is:

```
worker-dynamic
  └─► host.docker.internal:5556   (Mac loopback)
        └─► SSH tunnel
              └─► Oracle VM 127.0.0.1:5555
                    └─► redroid ADB
```

This path requires: (a) `adb-tunnel.sh` running and holding port 5556 on the Mac; (b) the Oracle VM
to be provisioned and redroid running; (c) `SANDBOX_ADB_HOST` changed to `host.docker.internal:5556`
in the Compose file (`.env` is not enough — `environment:` in compose wins).

### 11.11 Docker-to-host connectivity (unrestricted — security concern confirmed)

Executed **inside** `fraudshield-worker-dynamic-1`:
```python
import urllib.request
urllib.request.urlopen('http://host.docker.internal:8000/health', timeout=2).read()
→ b'{"status":"ok","service":"FraudShield AI"}'
```

**Confirmed:** `worker-dynamic` has unrestricted HTTP access to the host. If malware escapes the
emulator and achieves RCE on the worker container, it can pivot to host services and any device on
the local network. This compounds the risk documented in §7.

---

## 12. §2.2 Correction — Port 5555 Collision Status Upgraded

Section §2.2 previously stated:

> **NOT VERIFIED:** whether `adb connect host.docker.internal:5555` from the worker would reach an
> emulator, reach Flower's HTTP listener, or fail outright. That depends on host bind addresses and
> Docker Desktop's loopback forwarding behaviour, neither of which can be established read-only from
> inside this sandbox. It must be checked on the host before Phase 2's fail-closed behaviour lands.

**That paragraph is now superseded by host-verified evidence (§11.7 above). The correct statement is:**

The collision is **host-verified and definitively resolved**:

1. **Flower** (`com.docke`, PID 8943) holds the wildcard bind `*:5555` on the Mac host.
2. **QEMU** (PID 36850) holds `127.0.0.1:5555` and `[::1]:5555`.
3. From inside `worker-dynamic`, `host.docker.internal:5555` resolves to `192.168.65.254:5555`.
   Docker Desktop routes this to the wildcard listener, which is **Flower**.
4. A Python `socket.create_connection` + HTTP GET from the worker container confirmed it connects
   to Flower, not to an ADB daemon.
5. `adb connect host.docker.internal:5555` from the worker would connect to Flower's HTTP port. ADB
   would receive an HTTP response, fail the protocol handshake, and report connection failure or
   unauthorized — it would not establish a working ADB session.
6. Port 5556 (the tunnel port) is completely unreachable — no tunnel, no listener, no circuit.
7. `adb-tunnel.sh` explicitly uses 5556 precisely because Flower already owns 5555.
8. Because `SANDBOX_ADB_HOST` is declared under `environment:` in Compose (`:146`), and Compose
   header documentation (`:9-14`) states that `environment:` values **override** `.env`, editing
   `.env` to set `SANDBOX_ADB_HOST=host.docker.internal:5556` has **zero effect** on `worker-dynamic`.

**The current `SANDBOX_ADB_HOST: host.docker.internal:5555` is definitively invalid for the intended
redroid architecture. There is no working ADB path from worker-dynamic to any Android device.**

---

## 13. Summary of Verified vs Unverified Evidence

### 13.1 Now VERIFIED (host-confirmed, 2026-08-17)

| # | Fact | Evidence |
| --- | --- | --- |
| V1 | Docker stack is running (all 9 containers up/healthy) | `docker ps` output §11.1 |
| V2 | Host ADB keypair exists with correct permissions (600 / 644, pub 734 bytes) | `ls -l` + `wc -c` §11.2 |
| V3 | Local QEMU emulator (emulator-5554) is running and authorized on the host | `adb devices -l` §11.3 |
| V4 | Flower holds wildcard `*:5555` on the Mac host | `lsof` §11.4 |
| V5 | QEMU emulator holds loopback-only `127.0.0.1:5555` and `[::1]:5555` | `lsof` §11.4 |
| V6 | No adb-tunnel.sh process is running; port 5556 is not bound | `ps aux`, `lsof` §11.5 |
| V7 | `worker-dynamic`'s `host.docker.internal:5555` connects to Flower, not ADB | TCP probe §11.7 |
| V8 | Port 5556 is unreachable from inside `worker-dynamic` | socket probe §11.8 |
| V9 | `worker-dynamic` has unrestricted HTTP access to the host via `host.docker.internal` | `urllib.request` §11.11 |
| V10 | `SANDBOX_ADB_HOST: host.docker.internal:5555` is overridden by `environment:` in compose (cannot be fixed in `.env` alone) | Compose header comment `:9-14`; `:146` |
| V11 | Local QEMU emulator egress is blocked (`ip route` empty, ping unreachable) | `adb shell ping`, `adb shell ip route` (sandbox_security_audit.md §12) |

### 13.2 Still UNVERIFIED (cannot be established without further action)

| # | Fact | Why unverified | What would verify it |
| --- | --- | --- | --- |
| U1 | Oracle VM is provisioned and reachable | No VM IP recorded; no SSH probe run; no `setup-oracle-host.sh` run confirmed | `ssh ubuntu@<VM_IP> 'sudo docker ps'` |
| U2 | redroid container is running on the Oracle VM | Follows from U1 | `ssh ubuntu@<VM_IP> 'sudo docker ps | grep redroid'` |
| U3 | Oracle VM's ADB is bound to `127.0.0.1:5555` (not public) | Follows from U1 | `ssh ubuntu@<VM_IP> 'sudo ss -tlnp | grep 5555'` |
| U4 | The `FRAUDSHIELD-SANDBOX` iptables chain is active and correctly positioned on the Oracle VM | Depends on U2 | `ssh ubuntu@<VM_IP> 'sudo iptables -L FRAUDSHIELD-SANDBOX -n -v'` |
| U5 | Redroid containment probes (ICMP, DNS, TCP, metadata) all report blocked | Depends on U2, U4 | Re-run the containment proof block from `setup-oracle-host.sh:158-191` |
| U6 | The host ADB key (`~/.android/adbkey.pub`) is authorized inside the redroid container | Depends on U2 | `adb -s 127.0.0.1:5555 shell getprop sys.boot_completed` from the Oracle VM |
| U7 | An SSH tunnel on Mac port 5556 can be established to `Oracle_VM:5555` | Depends on U1-U3 | Run `adb-tunnel.sh <VM_IP>` in foreground mode |
| U8 | After the tunnel, `adb connect 127.0.0.1:5556` from the Mac succeeds and gets `device` | Depends on U7 | The tunnel script already validates this |
| U9 | After the tunnel, `adb connect host.docker.internal:5556` from **inside** `worker-dynamic` succeeds | Depends on U7-U8, plus Compose being updated to 5556 | `docker exec fraudshield-worker-dynamic-1 adb connect host.docker.internal:5556` |
| U10 | G2 gates (VM provisioned, both `.env` variables set, compose override removed) | G2 definition §3.4 | Complete §3.4 checklist |
| U11 | G5 gates (image digest pinned, AVD creation recipe documented) | G5 definition §4.1 | Out of pre-flight scope |

### 13.3 Why the current 5555 path is invalid for the intended redroid architecture

The intended architecture, as documented in `adb-tunnel.sh` and `setup-oracle-host.sh`, is:

```
worker-dynamic  →  host.docker.internal:5556
                       ↓  (Mac loopback port 5556, bound by adb-tunnel.sh)
                   SSH tunnel
                       ↓
                   Oracle VM 127.0.0.1:5555
                       ↓  (loopback only, never public)
                   redroid container ADB
```

The current running configuration creates:

```
worker-dynamic  →  host.docker.internal:5555
                       ↓  (Mac wildcard *:5555, owned by Docker Desktop / Flower)
                   Flower HTTP UI
                       ↓  (HTTP response, not ADB protocol)
                   *** ADB handshake fails ***
```

The two paths share a port number (`5555`) and nothing else. They are structurally incompatible.
`adb-tunnel.sh` acknowledges this conflict in its own source code and reserves a different port
(5556) specifically to avoid it. The Compose `environment:` override means this cannot be fixed
by editing `.env`; the Compose file itself must be changed.

---

## 14. Single Remaining Environmental Prerequisite for a Valid Phase 2 Live-Path Pre-Flight

Before Phase 2 implementation begins, **one environmental action** is required to establish a valid,
working ADB path from `worker-dynamic` to a contained Android instance:

### Prerequisite: Establish the Oracle/redroid ADB tunnel on port 5556

This is the only path that satisfies all design constraints simultaneously:
- ADB not exposed to the public internet (redroid binds `127.0.0.1:5555` on Oracle VM)
- ADB not colliding with Flower (tunnel uses Mac port 5556)
- Compose `environment:` override corrected (must change `:146` from 5555 to 5556)
- Egress-blocked containment on the Android side (iptables `FRAUDSHIELD-SANDBOX` chain)

The prerequisite decomposes into the following ordered steps, each of which must pass before the
next can be attempted:

#### Step P1 — Verify the Oracle VM is provisioned (read-only)
```bash
ssh ubuntu@<VM_IP> 'sudo docker ps | grep redroid && sudo docker logs fraudshield-redroid --tail 10'
```
Expected: redroid container is `Up`, last log lines show Android boot completed.

#### Step P2 — Verify redroid ADB is loopback-only (read-only)
```bash
ssh ubuntu@<VM_IP> 'sudo ss -tlnp | grep 5555'
```
Expected: `127.0.0.1:5555` only. If `0.0.0.0:5555` appears, the firewall assumption is wrong.

#### Step P3 — Verify Oracle VM iptables containment chain (read-only)
```bash
ssh ubuntu@<VM_IP> 'sudo iptables -L FRAUDSHIELD-SANDBOX -n -v && sudo iptables -L DOCKER-USER -n -v | head -20'
```
Expected: `FRAUDSHIELD-SANDBOX` chain exists with `ESTABLISHED,RELATED → RETURN`,
`169.254.0.0/16 DROP`, and catch-all `DROP`. Chain is inserted at position 1 of `DOCKER-USER`
and `INPUT`.

#### Step P4 — Verify host public key is authorized in redroid (read-only, from Oracle VM)
```bash
adb connect 127.0.0.1:5555
adb -s 127.0.0.1:5555 shell getprop sys.boot_completed
```
Expected: `1` (booted and authorized). If output is `unauthorized`, the key in the Compose mount
(`~/.android/adbkey.pub`) has not been accepted by the device.

#### Step P5 — Run the tunnel (manual, non-destructive to repo)
```bash
./infra/redroid/adb-tunnel.sh <VM_IP> --daemon
```
Expected: `adb connect 127.0.0.1:5556` returns `connected` or `already connected`, and
`adb -s 127.0.0.1:5556 shell getprop sys.boot_completed` returns `1`.

#### Step P6 — Verify tunnel is reachable from inside worker-dynamic (read-only command, requires Compose change first)

Before this step, `infra/docker-compose.yml` line 146 must be changed from
`SANDBOX_ADB_HOST: "host.docker.internal:5555"` to
`SANDBOX_ADB_HOST: "host.docker.internal:5556"`, and the worker container must be **recreated**
(not restarted — `SANDBOX_ADB_HOST` is captured at module import):

```bash
docker compose -f infra/docker-compose.yml up -d worker-dynamic
docker exec fraudshield-worker-dynamic-1 adb connect host.docker.internal:5556
```
Expected: `connected to host.docker.internal:5556` or `already connected`.

Only after all six steps pass is the worker-to-redroid ADB path verified and Phase 2 implementation
safe to start.

> **If the Oracle VM does not currently exist**, Steps P1–P4 cannot proceed. In that case, the next
> action is to provision the VM by running `setup-oracle-host.sh` on a fresh Oracle Cloud ARM
> Ampere A1 instance (Ubuntu 22.04/24.04, aarch64). This is not a code change and is not part of
> Phase 2 implementation — it is an infrastructure prerequisite.

---

## 15. Phase 2 Gate Status — Updated (2026-08-17)

| Gate | Status | Notes |
| --- | --- | --- |
| G0 | **CLEARED** | Phase 0 implemented, 221 baseline tests pass |
| G4 | **CLEARED** | Phase 1 provenance columns verified, 240 tests pass |
| G1 | **OPEN** | Probe conclusiveness; blocks Phase 3 completion |
| G2 | **OPEN** | No Oracle VM verified, no tunnel running, no `SANDBOX_ADB_HOST` in `.env`, compose override still 5555 |
| G3 | **OPEN** | ML feature contract; blocks Phase 5 |
| G5 | **OPEN** | Emulator image unpinned; constrains reproducibility claims |

**Phase 2 pre-flight: INCOMPLETE.** G2 is the single open environmental gate blocking a valid
pre-flight. Steps P1–P6 in §14 are the exact remaining verification sequence.

---

*Audit updated read-only (host evidence added, §2.2 corrected). No application code, test,
migration, configuration, Dockerfile, or dependency was modified. Phase 2 NOT STARTED.*
