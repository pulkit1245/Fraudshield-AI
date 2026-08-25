# G4 — Has live sandbox mode ever succeeded on this machine?

**Verdict: G4 CLEARED — YES, live-mode execution has occurred.** Fourteen persisted
sandbox artifacts are stamped `"mode": "live"`, and that stamp is written at exactly one
place in the code, reachable only from inside the live execution path after a real ADB
connection, an authorized+booted device, and a successful `adb install`. See §5 for the
precise boundary between what this proves and what it does not.

**It does not prove that live runs were fully successful, that the sample was actually
observed, or that containment held.** It proves the live code path was entered and ran to
completion at least 14 times. §5.2 lists what remains unproven and why.

Investigation date: 2026-08-16. Baseline commit: `2a8f865`. No application code was
modified for this gate. No service was started. The only container created was a
throwaway read-only `busybox` reading a Docker volume.

---

## 1. The plan's stated G4 method could not be executed

*(Preserved: this is why the question stayed open as long as it did, and it remains a
correction to the hardening plan.)*

`docs/sandbox-hardening-plan.md:507-513` proposes: "Grepping historical worker logs for
`sandbox.live_failed_simulate` versus `emulator.remote_ready` would settle it."

**There are no historical worker logs.** This is a defect in the plan, not a gap in the
search:

- `backend/app/core/logging.py:24-28,44-49` configures structlog with
  `stream=sys.stdout` and `logger_factory=structlog.PrintLoggerFactory()`. The
  application writes log lines to stdout and to nothing else. Verified: no `FileHandler`,
  `RotatingFileHandler`, `WatchedFileHandler`, or `basicConfig(filename=...)` anywhere in
  `backend/app/`.
- `infra/docker-compose.yml` declares no `logging:` driver on any service (verified by
  grep), so container stdout goes to Docker's default `json-file` driver — scoped to the
  **container's** lifetime, not the project's. `docker compose up --build` recreates
  containers and discards the previous container's log file with it.
- A filesystem sweep of the whole repository found exactly one `*.log` file, and it
  belongs to a vendored npm package (`frontend/node_modules/nwsapi/dist/lint.log`).
  There is no `logs/`, no `nohup.out`, no captured terminal output, and neither audit
  document quotes any observed runtime output.

The log corpus the plan assumes has never existed. The evidence that *did* settle G4 was
the persisted artifact blobs (§4), which are strictly better than logs: per-run,
mode-stamped, and durable across container recreation.

---

## 2. What the repository established before the probe

### 2.1 Live mode was not wired until 2026-08-06

`SANDBOX_MODE` for `worker-dynamic`, reconstructed at every commit that contains a
compose file:

| commit | date | shared anchor | worker-dynamic | `SANDBOX_ADB_HOST` |
|---|---|---|---|---|
| `0e4048b` | 2026-07-04 | — | `simulate` | none |
| `582b932` | 2026-07-05 | — | `simulate` | none |
| `00adc58` | 2026-07-11 | — | `simulate` | none |
| `0c17675` | 2026-07-17 | — | `simulate` | none |
| `ecf0a7d` | 2026-07-30 | — | `simulate` | none |
| `01d2228` | 2026-07-31 | — | `simulate` | none |
| `85eb05f` | 2026-08-06 18:34 | `simulate` | **`live`** | `host.docker.internal:5555` |
| `0043a24` | 2026-08-10 | `simulate` | **`live`** | `host.docker.internal:5555` |
| `d0994d4` | 2026-08-11 00:59 | `simulate` | **`live`** | `host.docker.internal:5555` |
| `04d5a43` | 2026-08-11 11:28 | `simulate` | `simulate` | `host.docker.internal:5555` |
| `a641714` | 2026-08-11 13:07 | `simulate` | `simulate` | `host.docker.internal:5555` |
| `761aa92` | 2026-08-11 22:19 | **`live`** | **`live`** | `host.docker.internal:5555` |
| `604c55c` | 2026-08-11 | **`live`** | **`live`** | `host.docker.internal:5555` |
| `2a8f865` | 2026-08-16 | **`live`** | **`live`** | `host.docker.internal:5555` |

Live was configured in two windows: 2026-08-06 18:34 → 2026-08-11 11:28, and 2026-08-11
22:19 → now. The `simulate` reversion at `04d5a43`/`a641714` came in on the
classification branch and its merge, which reads as collateral damage from conflict
resolution rather than a decision; `761aa92` restored it five hours later and
additionally promoted `live` into the shared anchor.

### 2.2 The 2026-08-11 ADB debugging session

`d0994d4` (2026-08-11 00:59) introduced into `emulator_pool.py`:

- `REMOTE_BOOT_TIMEOUT`, raised from 10 s to 90 s, commented "10s is too tight for a busy
  emulator and **produced spurious timeouts**" (`:36-37`).
- Detection of the literal string `failed to authenticate` in `adb connect` output, plus
  the `emulator.unauthorized` warning telling the operator to accept "Allow USB
  debugging?" and tick "Always allow from this computer" (`:97-106`).
- An UNAUTHORIZED fast-fail inside the boot poll, commented "An unauthorized device never
  answers getprop, so polling would burn the whole timeout and then report a misleading
  'did not finish booting'" (`:167-179`).

These are retrofitted responses to observed symptoms. Before the probe they were the
strongest available evidence that a real ADB connection had been reached — circumstantial
but pointed. **The probe has since superseded them as evidence, and inverted their
significance: see §5.3, because every one of these diagnostics was written *after* the
last recorded live run.**

### 2.3 One earlier signal, checked and rejected

`sandbox_manager.py:108` passes `--bypass-low-target-sdk-block` to `adb install`,
commented "Android 14+ blocks low target SDKs by default, bypass it." That flag is the
specific remedy for `INSTALL_FAILED_DEPRECATED_SDK_VERSION`, observable only on a real
authorized device — which would have been decisive.

`git log -S` restricted to `backend/app/dynamic_analysis/` dates it to `85eb05f`, the same
commit that introduced the live path, not to a later fix. Added defensively alongside the
code it protects, it carries no evidentiary weight. **Recorded so it is not mistaken for
proof later.** (The unrestricted `git log -S` additionally lists `2a8f865`; that is only
because the audit documents added at the checkpoint quote the flag in prose.)

### 2.4 The redroid half never ran

`infra/redroid/adb-tunnel.sh` and `setup-oracle-host.sh` first appear at the checkpoint
commit `2a8f865` and carry on-disk mtimes of 2026-08-11 15:26 and 15:31 — written during
the window when compose had been reverted to `simulate`. Nothing indicates either has been
executed. Consistent with G2 remaining OPEN. **The 14 live runs are therefore attributable
to the local QEMU-on-Mac target, not to redroid.**

---

## 3. Why the artifact blobs are recoverable at all

Every sandbox run writes a JSON blob stamped with its own mode, and on this machine those
blobs persist:

1. `sandbox_manager._store_log:218-227` writes `sandbox_logs/{submission_id}/{uuid}.json`
   via `storage.upload_artifact`. Verified by grep: `sandbox_logs` appears at exactly one
   line in the entire backend, so this is the only writer.
2. `file_storage._build_storage:132-139` returns `S3Storage` only when **both**
   `STORAGE_KEY` and `STORAGE_SECRET` are non-empty. Both are present-but-empty in the
   repo-root `.env` (length 0, verified without reading their values), and
   `config.py:49-50` defaults both to `""`. Compose does not set either in
   `x-backend-env`, so nothing shadows them. The backend therefore always uses
   `LocalStorage`.
3. `LocalStorage.__init__:96` roots at `LOCAL_STORAGE_DIR`, set nowhere in the repository,
   so it falls back to `/tmp/fraudshield-storage`.
4. `docker-compose.yml:48` mounts the named volume `apk_storage` at exactly
   `/tmp/fraudshield-storage` on every backend-derived service, and `:157` repeats it for
   `worker-dynamic` (YAML merge keys replace sequences rather than concatenate).

So the blobs live in the Docker volume `fraudshield_apk_storage`, which survives container
recreation.

---

## 4. Host probe results — 2026-08-16

Executed on the host by the operator, read-only (`docker run --rm -v
fraudshield_apk_storage:/data:ro busybox`), no service started:

| measurement | result |
|---|---|
| volume `fraudshield_apk_storage` | exists |
| total sandbox log blobs | **46** |
| blobs with `"mode": "live"` | **14** |
| blobs with `"mode": "simulate"` | **32** |
| blobs with `"mode": "mobsf"` | 0 (implied: 14 + 32 = 46) |
| oldest blob | **Aug 6, 13:01** |
| newest blob | **Aug 10, 17:43** |

---

## 5. Verifying the interpretation against the implementation

### 5.1 `"mode": "live"` cannot be a configuration label

Three independent checks, all read-only:

**Only three writers of a blob `mode` exist**, and each is inside the body of the method
that performs that mode's work: `"mobsf"` at `sandbox_manager.py:76`, `"live"` at `:161`,
`"simulate"` at `:204`. There is no code path that stamps a blob from `SANDBOX_MODE`, from
`self.mode`, or from any configuration value. The `mode` at
`dynamic_analysis_service.py:55` is a log field, not a blob field, and is read back off
the returned result rather than off configuration.

**No test can fabricate one.** `backend/app/tests/` contains no reference to `_run_live`,
to `mode="live"`, to `_store_log`, or to `upload_artifact`. (This also explains why the
newest blob is Aug 10 and none of the Phase 0 pytest runs on Aug 16 added any: those runs
targeted `app/tests`, so the old module-level `backend/test_sandbox.py` — which did write
a `simulate` blob on collection — was never collected.)

**The live stamp sits at the end of the live path, not the start.** `log_blob = {"mode":
"live", ...}` at `:160-165` is reached only after every preceding statement in `_run_live`
returned without raising. Reconstructing that chain:

| step | code | what must have happened |
|---|---|---|
| 1 | `self._pool.acquire()` `:100` | `warm_up()` → `is_available()` true → `_connect_remote()` returned True |
| 2 | `_connect_remote` `:87-119` | `adb connect` output contained `connected`/`already connected` and **not** `failed to authenticate` |
| 3 | `_wait_for_boot(host, remote=True)` `:155-186` | `getprop sys.boot_completed` returned exactly `1` — so the device was **online, authorized, and fully booted**. An unauthorized device raises here; a silent one times out |
| 4 | `_harden_network(inst)` `:189-196` | `svc data disable` / `svc wifi disable` were **issued** |
| 5 | `adb install --bypass-low-target-sdk-block -r -d -t` `:107-114` | returncode **0** — a real APK installed on a real device. Non-zero raises `RuntimeError`; a >120 s hang raises `TimeoutExpired`. Either falls back to simulate |
| 6 | `logcat -v brief` + `sleep(RUN_SECONDS)` `:131-141` | a 60 s capture window elapsed |
| 7 | `_parse_logcat` `:144` | parsing completed |

Any failure at steps 1–3, or 5, is caught by `run():60-62`, logged as
`sandbox.live_failed_simulate`, and redirected to `_run_simulated` — whose blob is stamped
`"simulate"`. **A `"mode": "live"` blob therefore cannot exist unless steps 1–7 all
completed.**

Because `EmulatorPool` is constructed per `SandboxManager` (`:37`) and a fresh
`SandboxManager()` is built per service instance (`dynamic_analysis_service.py:34`, the
only construction site outside the module), `warm_up` runs per analysis. So each of the 14
blobs required its **own** successful connect-and-boot check, not one lucky session
amortized across all of them.

### 5.2 What is proven, and what is not

**Proven.** At least 14 sandbox executions entered the live path and ran it to completion.
ADB authentication succeeded against a real, booted Android device. `adb install` returned
0 on a real device. A 60 s logcat capture window elapsed and was parsed. The floor is 14,
not the ceiling: `_store_log:225-227` swallows storage failures and returns the key anyway,
so additional live runs may have completed without leaving a blob.

**Not proven — do not claim any of these.**

*That the sample actually launched.* The `monkey` launch at `:122-127` runs with
`capture_output=True` and **no returncode check**. A failed launch is silently ignored and
does not stop the run. Installation is proven; execution of the sample is not.

*That anything was observed.* If `logcat_proc.communicate` times out, `:139-141` kills it
and sets `logcat_output = ""`, yielding all-False flags and zero events. A live blob is
fully consistent with having captured nothing. Each blob's own `events` and `network_calls`
fields answer this per run — unread so far (§7).

*That containment held.* `_harden_network:189-196` issues `svc data disable` / `svc wifi
disable`, **never checks either returncode**, and logs `emulator.network_hardened`
unconditionally. This is the audit's existing finding, and it means step 4 above proves
only that the commands were *issued*. Egress containment during those 14 runs is
**UNKNOWN**, not verified. Under the standing constraint this must be reported as
INCONCLUSIVE.

*That cleanup succeeded.* The `finally` block at `:147-158` wraps force-stop and uninstall
in `except Exception: pass`. A sample may have remained installed after a run.

*That every live attempt succeeded.* 14 blobs mean 14 recorded live *executions*. Live
attempts that failed at steps 1–3 or 5 fell back and are stamped `simulate`, so they are
indistinguishable inside the 32 (§6).

### 5.3 The dates invert §2.2, and that is the most important finding

The newest blob is **Aug 10 17:43**. Cross-referencing §2.1:

**Every recorded run predates 2026-08-11 entirely.** So all 14 live runs happened in the
*first* live window, and:

- They predate `d0994d4` (Aug 11 00:59) — meaning the entire ADB-authentication diagnostic
  effort of §2.2 was written **after** the last recorded successful live run. The coherent
  reading is that live worked Aug 6–10 and then **stopped** working around Aug 11, and
  those diagnostics were the response to it breaking — an emulator restart or a regenerated
  key would produce exactly the `failed to authenticate` / unauthorized states they added
  handling for. **This is a hypothesis consistent with the timeline, not an established
  fact.** It is worth stating because it is the opposite of the reassuring reading.
- They predate `761aa92` (Aug 11 22:19), which is the configuration that `2a8f865` ships.
  **No dynamic run has ever been recorded under the current configuration.** Live is
  proven possible on this machine; it is not proven working as currently configured.
- The oldest blob (Aug 6 13:01) *precedes* `85eb05f` (Aug 6 18:34) by ~5.5 hours, so the
  earliest blobs were produced by working-tree code that was never committed and cannot be
  inspected. A limit on attribution for that window only.

---

## 6. The 32 simulate blobs are NOT attributable to fallback

Tempting and wrong. `_run_simulated:204-206` writes an identical blob whether it was
invoked directly (configured simulate) or as the fallback from a failed live attempt —
there is no marker distinguishing the two. At least three innocent explanations coexist:

1. **Configured simulate.** The shared anchor stayed `simulate` until Aug 11 22:19, so
   `backend`, `worker-static`, `beat`, and `flower` were all legitimately simulate for the
   entire window in which these blobs were written.
2. **Pytest collection.** The old module-level `backend/test_sandbox.py` wrote one
   `simulate` blob every time it was collected, and any in-container run mounts the volume.
3. **Genuine live→simulate fallback**, which given §5.3's breakage hypothesis is likely to
   account for some of them.

A 14:32 ratio is suggestive of frequent degradation but proves nothing on its own. §7 gives
the probe that would settle it.

---

## 7. Optional follow-up probes (not required to close G4)

Both are read-only against the same volume and start no service.

**Per-blob mode and timestamp** — would separate the three explanations in §6, and would
show whether live and simulate blobs interleave within a single day (fallback) or cluster
on separate days (configuration changes):

```bash
docker run --rm -v fraudshield_apk_storage:/data:ro busybox sh -c '
  find /data/sandbox_logs -name "*.json" | while read f; do
    printf "%s  %s\n" "$(ls -l "$f" | awk "{print \$6, \$7, \$8}")" \
                      "$(grep -o "\"mode\": \"[a-z]*\"" "$f" | head -1)"
  done | sort
'
```

**Contents of the 14 live blobs** — answers §5.2's open questions directly. Each live blob
carries `events` (populated only if logcat produced matching lines) and `network_calls`
(hosts parsed from logcat with `sink: false`). Empty `events` across all 14 would indicate
the sample never launched or nothing was captured; any real external hostname in
`network_calls` would be a containment signal worth escalating, given that
`_harden_network` never verified its own work:

```bash
docker run --rm -v fraudshield_apk_storage:/data:ro busybox sh -c '
  grep -rl "\"mode\": \"live\"" /data/sandbox_logs | while read f; do
    echo "=== $f"; head -c 600 "$f"; echo
  done
'
```

---

## 8. Consequences for Phase 2, recorded now

**Fail-closed is now a much safer change than the pessimistic case, but not a free one.**
Live has demonstrably worked on this machine, so Phase 2 is not switching on a path that
has never functioned. However, per §5.3 the last recorded live run was Aug 10 — six days
before the checkpoint, under a compose configuration that has since changed twice — and the
Aug 11 diagnostics suggest the connection had broken by then. **Before Phase 2 lands, live
mode should be confirmed working under the current configuration**, otherwise fail-closed
will turn every dynamic submission red and the cause will be a stale ADB authorization
rather than anything Phase 2 did. That is a pre-flight check, not a blocker on Phase 1.

Phase 3 (real containment probing) is also now better motivated than before, not less:
§5.2 shows 14 live runs took place with egress containment entirely unverified.

Two related facts to carry forward. Neither is a G4 finding; neither should be acted on in
Phase 1.

**`SANDBOX_MODE: live` now sits in the shared anchor** (`:32`, since `761aa92`), so
`backend`, `worker-static`, `beat`, and `flower` all also believe they are live — but none
receives `SANDBOX_ADB_HOST`, and the image ships `android-tools-adb` without the `emulator`
binary. In those services `is_available()` returns False, `warm_up` logs
`emulator.unavailable`, `acquire` raises, and any `SandboxManager` built there simulates
100% of the time. In practice `run_dynamic_analysis` is routed to `dynamic_queue`, which
only `worker-dynamic` consumes, so this is a latent trap rather than an active one. Already
tracked as audit item S10 and plan item 19 (Phase 6).

**The two `.env` files disagree** — repo-root says `SANDBOX_MODE=live`, `backend/.env` says
`simulate`. `config.py:20` sets `env_file=".env"` relative to the working directory, and
compose loads `../.env` (repo root) explicitly, so compose runs are unambiguously `live`.
Only a bare-metal worker started from `backend/` would pick up `simulate` — relevant to
interpreting the pre-Aug-6 blobs.

---

## 9. Open question for Phase 1 design

Not a change request; flagging because it affects the phase awaiting approval. Phase 1
persists the `mode` returned by `SandboxManager.run()`. On a live→simulate fallback that
returned value is `"simulate"` (`:214`), so the new column would record a fallback
identically to a configured simulate run — reproducing at the database layer the exact
ambiguity that made §6 unresolvable. Phase 2's fail-closed change removes the fallback
entirely, which makes this moot, but Phases 1 and 2 land separately. Worth deciding
explicitly before writing the migration.
