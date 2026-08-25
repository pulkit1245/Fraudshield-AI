# Sandbox Security Hardening — Implementation Plan

**Baseline commit:** `2a8f865 chore: checkpoint before sandbox security hardening`
**Status:** Phases 0 and 1 implemented and VERIFIED (2026-08-16). Phases 2–7 are still plan only.
**Test gate:** 221 at baseline → **240 green** after Phase 1 (+19).
**Migration head at baseline:** `fc3b3e1b0973` — now `0007` (sole head) after Phase 1.
**Gates:** G0 CLEARED, G4 CLEARED. **G2 and G5 remain OPEN** and block Phase 6.
**Companion documents:** `docs/current-state-audit.md`, `docs/sandbox_security_audit.md`, `infra/redroid/`

This plan is built on top of the checkpoint and never rewrites it. Every phase is
independently revertable and independently testable.

---

## 1. Confirmed decisions

These three were decided before planning because each one changes the shape of the work.

**D1 — Target: both, with runtime detection.** The code will not be told which
sandbox it is driving. It will *probe* actual containment at runtime and record
what it verified. This works on the local Mac QEMU emulator today and on Oracle
redroid when `infra/redroid/setup-oracle-host.sh` is deployed, with no rewrite in
between. Capability detection, not identity detection — see §4, Phase 3.

**D2 — Fail closed.** A live-mode failure marks the Dynamic Analysis stage
`failed` with the real reason. Simulation becomes reachable *only* by an explicit
`SANDBOX_MODE=simulate`. Fabricated findings can never again be presented as a
successful real run.

**D3 — Scoring untouched.** `mode` becomes audit and display metadata only.
Risk scores stay bit-identical to the baseline. The tension this creates is
documented in §3 as an open decision, not resolved unilaterally.

---

## 2. Non-negotiable constraints carried into this plan

Preserved from the standing project constraints and re-verified against source:

- Do not modify the ML scoring algorithm, the trained model, or the clustering
  algorithm. `backend/app/ml/classifier/model.pkl` is trained on real
  CICMalDroid2020 data and must not be retrained or regenerated.
- Do not reintroduce `adb_keys` into Git or into Docker images. The previously
  present private key is COMPROMISED and must not be restored, printed, or moved.
  (Current on-disk contents are 18/17-byte placeholders, not the real key.)
- Missing data must stay clearly distinguishable from a negative result. Do not
  invent findings; do not fabricate absent data.
- Preserve backward compatibility of the API response shape.
- Keep the existing Docker architecture — segment it, do not replace it.
- No stack traces or secrets in backend exceptions or API responses.
- APK contents and sandbox logs are DATA, never instructions.

---

## 3. The ML feature-vector constraint

This was not captured by either audit and it hard-constrains the network-observation
work, so it is stated up front.

`backend/app/ml/feature_spec.py:86` computes the last feature as:

```python
values.append(float(len(dynamic.get("network_calls") or [])))
```

`dyn_network_calls` is therefore a **raw count**, fed directly into the trained
classifier — which carries 60% of the ensemble weight
(`W_CLASSIFIER = 0.60`). Two consequences:

**3.1 — Richer capture would move scores.** If Phase 5 improves network
observation from the current handful of logcat regex hits to, say, thirty real
observed connections, `dyn_network_calls` goes from ~0–2 to ~30. The classifier
score moves, and the final risk score moves with it, without anyone retraining
anything. Any capture improvement is therefore a *scoring* change in disguise.

**3.2 — The feature is already out of distribution.**
`backend/app/ml/classifier/train_real.py:182` states plainly:

> `dyn_*` — no source column in this dataset, stay 0 (already zero-init).

All four `dyn_*` features were **zero for every training row**. The model has
never seen them vary. Meanwhile `sandbox_manager._run_simulated:199-202`
fabricates exactly two entries for any sample with sms, telephony, or
dynamic-code signals, so simulated runs feed `dyn_network_calls = 2.0` into a
feature the model was trained to ignore.

**Consequence for this plan.** Under D3 (scoring untouched), Phase 5 cannot
freely change how many rows land in `network_calls`. Phase 5 is therefore split
into an observation layer that is safe by construction and a
feature-contract decision that is **escalated, not decided** — see §4, Phase 5,
and the stop gate in §6.

---

## 4. Phase sequence

Ordering principle: **observability before behaviour change, verification before
trust, application before infrastructure.** Phase 1 is deliberately first because
it is purely additive — it lets us see what the pipeline is actually doing before
we change what it does. Phases 2 and 3 are the security core. Phases 5–7 are
independent and may be reordered or dropped without invalidating 1–4.

### Phase 0 — Build hygiene (no runtime behaviour change)

**Why first:** removes the ADB-key bake before anything else touches the image,
and establishes a recorded test baseline so later phases have something to
compare against.

1. Record a baseline `pytest` run and commit the output to the plan as ground
   truth. We have never run the suite this session, so "the tests pass" is
   currently an assumption, not a fact. See the stop gate in §6.
2. Remove the ADB key bake at `backend/Dockerfile:40-42`. Replace it with a
   `RUN mkdir -p /home/appuser/.android && chown appuser:appuser
   /home/appuser/.android` so the read-only mount target
   (`infra/docker-compose.yml:160-161`) exists with correct ownership. Without
   this the directory would be created root-owned at mount time.
3. Add `adb_keys/` to `backend/.dockerignore`. This closes the second, implicit
   copy via `COPY . .` at `backend/Dockerfile:33`.
4. Rename `backend/test_sandbox.py` to `scripts/manual_sandbox_check.py`. It is
   not a pytest test — it has no test functions, and pytest collects the module
   and executes `SandboxManager._run_simulated` plus a real storage upload as an
   **import side effect**. Leaving it in place means every future `pytest` run
   writes a sandbox log artifact.

**Test gate:** full `pytest` run must match the Phase 0 baseline exactly.
**Revert boundary:** three files, no application logic.

### Phase 1 — Provenance: persist `mode` end to end

**Why:** this is the highest-value, lowest-risk change in the whole plan. It is
purely additive, changes no behaviour, and it is the prerequisite for being able
to *observe* the degradation that Phase 2 then eliminates.

Good news from source inspection: `sandbox_manager` **already returns** `mode`
in all three result dicts (`:92`, `:173`, `:214`), and
`dynamic_analysis_service.analyze:55` already *logs* it. The value is produced
and then discarded at exactly one place —
`dynamic_analysis_service._persist:94-98` sets five fields and drops it. So the
backend fix is genuinely small.

1. New Alembic migration `0007_dynamic_finding_provenance`, `down_revision =
   'fc3b3e1b0973'`. Adds two nullable columns to `dynamic_findings`:
   - `mode` — `String(16)`, nullable, indexed. Nullable is deliberate: existing
     rows have unknown provenance and must read as *unknown*, not as
     back-filled `live`. Back-filling would be fabricating data.
   - `containment_verified` — `Boolean`, nullable. Same reasoning; Phase 3 fills it.
2. `backend/app/models/dynamic_finding.py` — add both columns. Use plain
   `String`/`Boolean`; both are SQLite-safe, which matters because
   `backend/app/tests/test_dynamic_cluster_exposure.py:36-40` runs
   `Base.metadata.create_all` against in-memory SQLite. Also fix the stale
   docstring on `sandbox_log_path:39` which claims "the full Frida log" — Frida
   never runs.
3. `backend/app/services/dynamic_analysis_service.py:_persist` — pass both
   values through from the result dict.
4. `backend/app/schemas/submission_schema.py:73-80` — add
   `mode: Optional[str] = None` and `containment_verified: Optional[bool] = None`
   to `DynamicFindingOut`. Optional-with-default preserves backward
   compatibility; existing consumers are unaffected.
5. `frontend/src/types/index.ts:78-85` — add both optional fields to
   `DynamicFindingOut`.
6. Frontend display, the layer that currently lies:
   - `ReportViewer.tsx:663,670,677` assert "during dynamic analysis"
     unconditionally. Make the wording conditional on `mode`.
   - `ReportViewer.tsx:741-794` renders `sink` as "Flagged destination" — a
     *threat* classification standing in for a *provenance* marker. Separate the
     two concepts.
   - `AnalysisCompletenessCard.tsx:10-63` computes `issues` from
     `status === "failed" || status === "skipped"` only, so a simulated run that
     reports `completed` produces the green "Analysis Complete" banner. Add a
     third state for degraded/unverified provenance.

**Test gate:** new `test_dynamic_provenance.py`; existing
`test_dynamic_cluster_exposure.py` must still pass unchanged (it asserts the old
field set, which is exactly the backward-compatibility check we want).
**Revert boundary:** one migration down-revision plus six files. No behaviour change,
so revert is safe at any point.

> **STATUS: Phase 1 COMPLETE and VERIFIED — 2026-08-16.**
>
> All six items landed. **Authoritative gate: 240 passed / 0 failed / 0 error /
> 0 skipped / 0 xfail**, on a freshly rebuilt `worker-static` image, from
> `pytest app/tests -v --tb=short -rA -p no:cacheprovider`. That is the Phase 0
> baseline of **221 preserved green, plus exactly 19 new items** from
> `test_dynamic_provenance.py` (14 functions; 5 extra items from two
> `parametrize` decorators — 3 modes and 4 containment cases). Verified per-file
> rather than by the summary line: all 13 pre-existing files reported their
> expected counts, so nothing silently relocated. The one warning is
> pre-existing and third-party (`passlib` `crypt` deprecation on 3.11).
>
> Migration `0007` is the **sole Alembic head**, `down_revision =
> 'fc3b3e1b0973'`, and no pre-existing migration was modified. It contains no
> `server_default`, `UPDATE`, or `op.execute`, so **legacy rows stay NULL** — the
> non-fabrication requirement holds at the DDL level, not just by convention.
> Frontend `npx tsc --noEmit` exits 0.
>
> Provenance semantics confirmed end to end: `mode` NULL → UNKNOWN;
> `"simulate"` and `"mobsf"` are **not** treated as live; `runtimeObserved: true`
> is reachable from exactly **one** place in the entire frontend
> (`sandboxProvenance.ts` `case "live"`), so there is no second, divergent
> liveness test; `containment_verified` keeps its three values distinct, with
> `true` the only VERIFIED state and `false` still distinguishable from NULL.
> **D3 holds:** `scoring_service._fetch_dynamic` still projects exactly
> `{sms_access, accessibility_abuse, overlay_detected, network_calls}`, asserted
> by executing its real SQL, so risk scores cannot move. `app/ml/` and
> `scoring_service.py` are untouched.
>
> **Accepted limitation, carried into Phase 2.** Provenance comes from
> `SandboxManager.run()`, which returns `mode="simulate"` both for a configured
> simulation and for a live run that failed and fell back (`sandbox_manager.py:57-62`).
> Phase 1 therefore cannot distinguish a degraded live run from an intended one.
> This is documented in `_persist` and asserted by
> `test_dynamic_provenance.py::test_live_fallback_is_indistinguishable_from_configured_simulate`.
> **When Phase 2 lands, that test must be REPLACED** by one asserting the live
> failure propagates — not deleted quietly.
>
> Note also that `containment_verified` is written by **nothing** yet; Phase 3
> populates it. Until then every row is NULL, which renders as "not verified".

### Phase 2 — Fail closed: remove the silent degradation cascade

**Why:** with Phase 1 in place we can now see degradation; this phase stops it
from being silent. This is the first phase that **intentionally changes visible
behaviour** — runs that previously showed green will start showing failures. That
is the point, and it should be expected rather than treated as a regression.

1. `backend/app/dynamic_analysis/sandbox_manager.py:47-62`. Two changes:
   - `if self.mode == "live":` at `:57` becomes `elif`. Today the `mobsf` branch
     falls *through* into `live` and then into simulate, so a single run can
     traverse all three paths.
   - Under D2, a `live` failure re-raises instead of falling through to
     `_run_simulated`. `_run_simulated` becomes reachable only when
     `self.mode == "simulate"` was explicitly requested.
2. `backend/app/dynamic_analysis/sandbox_manager.py:73` — `_run_mobsf`
   fabricates `c2-sink.mobsf` on a behaviour flag. This is invented data, same
   class of defect as `_run_simulated:199-202`. Gate or remove.
3. `backend/app/workers/tasks/dynamic_task.py` — the existing `except` handler at
   `:103-119` already records `update_analysis_stage(..., "failed",
   error_message=str(exc))` at `:116-118`, and `AnalysisTimeline.tsx:170-179`
   already renders `error_message`. So the surfacing path exists and works; it
   simply never fires today because the exception is swallowed upstream. Verify
   the message is sanitised — no paths, no stack traces (see §2).
4. `backend/app/workers/tasks/dynamic_task.py:55` —
   `os.getenv("SANDBOX_MODE", "simulate")` defaults to `simulate` while
   `infra/docker-compose.yml:32` forces `live` for every service. The default is
   dead. Align it so the two cannot disagree.

**Test gate:** new `test_sandbox_fail_closed.py` asserting live failure raises
rather than returning simulated findings, that `mobsf` no longer falls through to
`live`, and that explicit `simulate` still works.
**Revert boundary:** two files. Revert restores the old fallback exactly.

### Phase 3 — Containment verification (the security core)

**Why:** this is the control that actually protects the host.
`emulator_pool._harden_network:189-196` currently discards both subprocess
results and logs `emulator.network_hardened` **unconditionally**. It asserts
containment without ever testing it.

The correct framing, which differs from both audits: runtime evidence
(`sandbox_security_audit.md` §12.1–12.3) proves `svc data disable` genuinely
works on local QEMU — the route is torn down. And `setup-oracle-host.sh:18,85-86`
documents that it does **nothing** on redroid, which has no emulated radio. So
the mechanism is effective on one target, inert on the other, and the code logs
success identically in both cases.

**Design — capability detection, not identity detection.** This is how D1 is
satisfied without the code needing to know which target it is driving:

1. New module `backend/app/dynamic_analysis/containment.py`, exposing
   `harden_and_verify(serial) -> ContainmentReport` and a `ContainmentError`.
2. Best-effort in-guest hardening first (`svc data disable` / `svc wifi
   disable`) — effective on QEMU, a harmless no-op on redroid.
3. Then **probe empirically**, reusing the exact four probes and success regex
   already proven in `setup-oracle-host.sh:176-181`:
   `PROBE_SUCCESS_RE = '1 received|bytes from|succeeded|connected|HTTP/'`, and
   ICMP to `8.8.8.8`, DNS to `8.8.8.8:53`, TCP to `1.1.1.1:443`, metadata at
   `169.254.169.254:80`. Sharing the probe definition with the shell script means
   the host provisioning and the Python application agree on what "contained"
   means — one definition, two enforcement points.
4. If any probe succeeds → raise `ContainmentError`. Under D2 this fails the
   stage. This mirrors the script's `die` at `:183-190`.
5. `ContainmentReport` records `verified`, `method`
   (`in_guest_svc` / `external_firewall` / `unverified`), per-probe results, and
   the detected target string. It feeds `containment_verified` from Phase 1, so
   containment status becomes queryable per submission.
6. `_harden_network` gains a return value and calls the verifier.
   `_connect_remote:116` must propagate the failure rather than being swallowed
   by the blanket `except Exception` at `:120`.
7. `SANDBOX_EGRESS_BLOCKED_EXTERNALLY` finally gets a reader — but as
   **documentation of operator intent only**. It sets `method` and the hint text.
   It must never bypass a probe. This resolves the orphaned flag
   (`adb-tunnel.sh:117`) honestly: containment becomes empirical, never asserted.

**Known subtlety that must be resolved during implementation.** Probes 2–4 use
`/dev/tcp` and `/dev/udp`, which are shell features. Android's `sh` is mksh and
support is not guaranteed. If a probe fails because the shell cannot open
`/dev/tcp` at all, a naive parser reads that as "blocked" — a false negative that
fails **open** in interpretation. The verifier must therefore distinguish
**blocked** from **inconclusive**, treat shell errors (`not found`,
`No such file`, `can't open`) as inconclusive, and require at least the ICMP
probe (where `ping` is reliably present) to return a conclusive result before
reporting `verified = True`. This is a stop gate — see §6.

**Test gate:** new `test_containment.py` with mocked `subprocess.run` covering
all blocked, one leaking, and inconclusive-shell cases. No real ADB needed.
**Revert boundary:** one new file plus `emulator_pool.py`.

### Phase 4 — State hygiene

**Why:** small, self-contained, and closes a guaranteed cross-contamination path.

1. `backend/app/dynamic_analysis/emulator_pool.py:204-211` — `release()` guards
   the state wipe with `if not inst.remote:`. Remote devices are **every** device
   in the intended Docker topology, so they are returned to the pool without
   `pm clear-all`. Sample *n*'s packages, files, and accounts persist into
   sample *n+1*. Implement a remote-safe reset path.
2. `backend/app/dynamic_analysis/emulator_pool.py:41` — `SANDBOX_ADB_HOST` is a
   module-level constant captured at import, so runtime environment changes have
   no effect and tests cannot vary it without reimporting the module. Move to
   lazy resolution. This is also a testability prerequisite for Phase 3.

**Test gate:** extend `test_containment.py` / new `test_emulator_pool.py`
asserting remote release performs a reset and that `SANDBOX_ADB_HOST` is read at
call time.
**Revert boundary:** one file.

### Phase 5 — Network observation

**Why the current design cannot work.**
`backend/app/dynamic_analysis/network_capture.py` binds
`SINK_HOST = os.getenv("FAKE_DNS_HOST", "127.0.0.1")` on port `5353` at `:69` —
that is *container* loopback. The emulator runs on the host Mac or the Oracle VM,
and its `-dns-server 10.0.2.15` (`emulator_pool.py:140`) is QEMU-internal. The
sink is therefore **architecturally incapable** of observing emulator traffic, not
merely unwired. This is a stronger claim than `sandbox_security_audit.md` §6 makes
and it means the module needs replacing, not connecting.

`sandbox_manager.py:23` imports the module and never references it again. The
module also carries `_CONN_RE:33-34`, a second, divergent copy of
`sandbox_manager._NETWORK_RE:248-251`.

**Constraint:** the image has no `tcpdump`, no `tshark`, and no `iptables`
(`sandbox_security_audit.md` §1), and the emulator is remote. Packet capture from
inside the container is impossible. Do not plan for pcap.

**Feasible design — ADB-side socket observation.** Poll `/proc/net/tcp`,
`/proc/net/tcp6`, and `/proc/net/udp` over `adb shell` across the run window,
decode the hex address/port pairs, and attribute sockets to the sample's UID
(obtainable from `pm list packages -U`). This yields real connection attempts
*with process attribution*, requires no tooling absent from the image, and works
identically on QEMU and redroid. It is a genuine upgrade over logcat regex
matching, which only sees connections the app happens to log.

**What must NOT change.** The three behaviour booleans — `sms_access`,
`accessibility_abuse`, `overlay_detected` — stay exactly as computed today by
`_parse_logcat:254-284`. Those are the "dynamic malware detection logic" that is
out of scope. Phase 5 adds an observation source; it does not re-decide verdicts.

**The escalation.** Per §3, `network_calls` length *is* an ML feature. Landing
thirty real observed connections where the baseline landed zero to two will move
classifier scores, which violates D3. So Phase 5 must not be merged until one of
these is chosen — and this is a decision to bring back, not to make:

- **(a) Split the field.** Keep `network_calls` as the ML-facing contract at its
  current fidelity, and persist rich observations in a new column consumed only
  by the UI and analysts. Scores stay bit-identical. Most conservative; adds a
  column.
- **(b) Cap the ML-facing count.** Feed a clamped or bucketed value to
  `featurize`, leaving the raw list for display. Still perturbs the feature
  unless the cap matches baseline behaviour.
- **(c) Accept the score movement.** Simplest code, but it is a scoring change
  and contradicts D3.

Note that under (a) or (b) there is a latent finding worth raising separately:
`dyn_network_calls` is currently fed a fabricated `2.0` by
`_run_simulated:199-202` into a feature the model saw only as zero
(`train_real.py:182`). Phase 5 does not fix that; Phase 2 does, by making
simulate opt-in.

**Test gate:** new `test_network_observation.py` with recorded `/proc/net/*`
fixtures — pure parsing tests, no ADB. Plus an explicit assertion that the three
behaviour booleans are unchanged for a fixed logcat fixture.
**Revert boundary:** `network_capture.py` rewrite plus the `_run_live` call site.

### Phase 6 — Infrastructure hardening

**Why last among the code phases:** it changes the runtime topology, so it should
land only after the application logic that runs inside that topology is correct.

`infra/docker-compose.yml`, in order of severity:

1. **Flower on `*:5555`, unauthenticated** (`:190-191`). Runtime-proven exposed —
   `sandbox_security_audit.md` §12.4 shows `com.docke` listening on `*:5555`.
   Flower permits task invocation. Bind to `127.0.0.1` and add `--basic-auth`.
2. **No network segmentation.** There is no `networks:` key anywhere in the file,
   so `worker-dynamic` shares the default bridge with `postgres`, `rabbitmq`,
   `redis`, `backend`, `beat`, and `flower`. Introduce explicit networks and place
   `worker-dynamic` so it can reach the broker and DB but not the wider bridge.
3. **`worker-dynamic` can pivot to the host.** Runtime-proven — §12.5 reached
   `host.docker.internal:8000/health` from inside the container. `extra_hosts` at
   `:162-163` is required for ADB, so the host gateway cannot simply be removed;
   restrict what is reachable through it instead.
4. **No container restrictions on `worker-dynamic`.** Add `cap_drop`,
   `security_opt: no-new-privileges`, and CPU/memory limits. `read_only` needs
   care — the worker writes to `tempfile.mkdtemp` in
   `dynamic_analysis_service.py:44`, so it requires a writable `/tmp` tmpfs.
5. **Credentials in version control.** `JWT_SECRET` at `:27`,
   `fraudshield:fraudshield` at `:24` and `:56-57`, rabbitmq `guest:guest` with
   its management UI published at `:74`, redis unauthenticated at `:84-85`. Move
   to `.env` with documented `.env.example` entries. Note the trap already
   documented in the file's own header comment at `:9-14`: `FOO: ${FOO:-}`
   resolves from the *shell*, not `.env`, and that is exactly how
   `VIRUSTOTAL_API_KEY` became empty. Do not repeat it.
6. **`SANDBOX_MODE: live` in the shared anchor** at `:32`, so it applies to
   `backend`, `worker-static`, `beat`, and `flower` too — none of which have
   `SANDBOX_ADB_HOST` or the `emulator` binary, so any `SandboxManager` built
   there degrades. Move it to `worker-dynamic` only, where `:143` already sets it.
7. **`SANDBOX_ADB_HOST` hardcoded** to `host.docker.internal:5555` at `:146`.
   Under D1 this must be configurable so the same compose file drives QEMU (5555)
   or the redroid tunnel (5556, per `adb-tunnel.sh:25`). Note that
   `environment:` beats `env_file:`, which is why `adb-tunnel.sh:116-117`'s
   printed instructions are currently inert.

**Test gate:** `docker compose config` validates; stack boots; `pytest` unchanged;
re-run the §12.4 and §12.5 probes and confirm both now fail.
**Revert boundary:** one file, but it is the riskiest phase for breaking a working
stack. Land it alone, verify boot, and keep the previous file recoverable.

### Phase 7 — Pipeline integrity

**Why separate:** unrelated to the sandbox, but it is a data-integrity defect
found during the audit and it is a two-line fix.

`backend/app/workers/tasks/static_task.py` calls `_try_advance_pipeline` at `:95`
on success **and again at `:113` from inside its `except` handler**, commented
"Even on failure, try to advance the pipeline if dynamic is done and a
static_findings row was persisted." A static analysis that raised can therefore
push the submission into scoring. Combined with the existence-only join probe at
`:53-62` (`SELECT 1 ... LIMIT 1`), row *presence* is treated as completion while
row *quality* is never checked.

Scope this narrowly: do not redesign the join. Either remove the
exception-handler advance, or require that the persisted row be complete before
advancing.

**Test gate:** extend `backend/app/tests/test_analysis_stages.py`.
**Revert boundary:** one file.

---

## 5. File-by-file change list

`M` = modify, `C` = create, `R` = rename. Line anchors are against baseline
`2a8f865` and were each re-verified against source while writing this plan.

### Backend — application

| # | Ph | Op | File | Change | Compat risk |
|---|----|----|------|--------|-------------|
| 1 | 1 | C | `backend/alembic/versions/0007_dynamic_finding_provenance.py` | Add `mode` (String(16), nullable, indexed) + `containment_verified` (Boolean, nullable) to `dynamic_findings`. `down_revision = 'fc3b3e1b0973'` | None — additive, both nullable |
| 2 | 1 | M | `backend/app/models/dynamic_finding.py` | Add both columns after `:40`. Fix stale "full Frida log" docstring at `:39` | None. Use `String`/`Boolean` — SQLite-safe for `create_all` |
| 3 | 1 | M | `backend/app/services/dynamic_analysis_service.py` | `_persist:94-98` — pass `mode` and `containment_verified` through. Value already arrives in `result`; `analyze:55` already logs it | None |
| 4 | 1 | M | `backend/app/schemas/submission_schema.py` | `DynamicFindingOut:73-80` — add both as `Optional[...] = None` | None — optional with default |
| 5 | 2 | M | `backend/app/dynamic_analysis/sandbox_manager.py` | `:57` `if`→`elif`; live failure re-raises instead of falling through at `:60-61`; gate fabricated `c2-sink.mobsf` at `:73`; `_run_simulated:199-202` reachable only on explicit request | **Behaviour change by design.** Runs that showed green will show failures |
| 6 | 2 | M | `backend/app/workers/tasks/dynamic_task.py` | Align dead `simulate` default at `:55`; verify `error_message` at `:116-118` is sanitised | Low |
| 7 | 3 | C | `backend/app/dynamic_analysis/containment.py` | `harden_and_verify(serial) -> ContainmentReport`, `ContainmentError`. Four probes + regex shared with `setup-oracle-host.sh:176-181`. Blocked / inconclusive distinction | New module |
| 8 | 3 | M | `backend/app/dynamic_analysis/emulator_pool.py` | `_harden_network:189-196` returns a report instead of logging success unconditionally; `_connect_remote:116` propagates failure past the blanket `except` at `:120` | **Behaviour change by design** |
| 9 | 4 | M | `backend/app/dynamic_analysis/emulator_pool.py` | `release:204-211` — remote reset path; `:41` `SANDBOX_ADB_HOST` module constant → lazy read | Low; same file as #8 |
| 10 | 5 | M | `backend/app/dynamic_analysis/network_capture.py` | Replace the unreachable container-loopback DNS sink (`:69`, `SINK_HOST`/`SINK_PORT`) with `/proc/net/{tcp,tcp6,udp}` polling over ADB + UID attribution. Retire duplicate `_CONN_RE:33-34` | Gated on the §3 escalation |
| 11 | 5 | M | `backend/app/dynamic_analysis/sandbox_manager.py` | Wire capture into `_run_live:130-145`. Leave `_parse_logcat:254-284` behaviour booleans untouched | Gated on the §3 escalation |
| 12 | 7 | M | `backend/app/workers/tasks/static_task.py` | Remove or condition the exception-handler advance at `:113` | Low |

### Backend — build

| # | Ph | Op | File | Change | Compat risk |
|---|----|----|------|--------|-------------|
| 13 | 0 | M | `backend/Dockerfile` | Delete key bake at `:40-42`; add `RUN mkdir -p /home/appuser/.android && chown appuser:appuser` so the read-only mount target exists correctly owned | Low — real keys arrive via mount at compose `:160-161` |
| 14 | 0 | M | `backend/.dockerignore` | Add `adb_keys/` — closes the implicit second copy via `COPY . .` at `Dockerfile:33` | None |
| 15 | 0 | R | `backend/test_sandbox.py` → `backend/scripts/manual_sandbox_check.py` | Not a pytest test; currently executes `_run_simulated` + a storage upload as an import side effect during collection | None |

### Frontend

| # | Ph | Op | File | Change | Compat risk |
|---|----|----|------|--------|-------------|
| 16 | 1 | M | `frontend/src/types/index.ts` | `DynamicFindingOut:78-85` — add `mode?: string` and `containment_verified?: boolean \| null` | None |
| 17 | 1 | M | `frontend/src/components/.../ReportViewer.tsx` | `:663,670,677` — make "during dynamic analysis" conditional on `mode`. `:741-794` — separate provenance from the `sink` threat label ("Flagged destination") | Display only |
| 18 | 1 | M | `frontend/src/components/.../AnalysisCompletenessCard.tsx` | `:10-63` — `issues` currently filters only `failed`/`skipped`, so a simulated `completed` run renders green "Analysis Complete". Add a degraded/unverified state | Display only |

### Infrastructure

| # | Ph | Op | File | Change | Compat risk |
|---|----|----|------|--------|-------------|
| 19 | 6 | M | `infra/docker-compose.yml` | Flower `:190-191` → `127.0.0.1` + `--basic-auth`; add `networks:`; `cap_drop`/`no-new-privileges`/limits + writable `/tmp` tmpfs on `worker-dynamic`; secrets at `:24,27,56-57,74,84-85` → `.env`; move `SANDBOX_MODE` out of the shared anchor at `:32`; make `SANDBOX_ADB_HOST:146` configurable | **Highest risk of breaking a working stack.** Land alone |
| 20 | 6 | M | `.env.example` | Document `SANDBOX_ADB_HOST`, `SANDBOX_MODE`, `SANDBOX_EGRESS_BLOCKED_EXTERNALLY`, `JWT_SECRET`, DB/broker credentials. `.env` currently has none of the first three | None |
| 21 | 3 | M | `infra/redroid/setup-oracle-host.sh` | Only if the probe definitions at `:176-181` need factoring into a shared form. Prefer leaving this file untouched — it is the one verified-good artifact | Prefer none |

### Tests

| # | Ph | Op | File | Purpose |
|---|----|----|------|---------|
| 22 | 1 | C | `backend/app/tests/test_dynamic_provenance.py` | `mode` and `containment_verified` survive persist → schema → API. Null for legacy rows |
| 23 | 2 | C | `backend/app/tests/test_sandbox_fail_closed.py` | Live failure raises; `mobsf` no longer falls through to `live`; explicit `simulate` still works |
| 24 | 3 | C | `backend/app/tests/test_containment.py` | Mocked `subprocess.run`: all-blocked, one-leaking, inconclusive-shell. No real ADB |
| 25 | 4 | C | `backend/app/tests/test_emulator_pool.py` | Remote release resets state; `SANDBOX_ADB_HOST` read at call time |
| 26 | 5 | C | `backend/app/tests/test_network_observation.py` | `/proc/net/*` fixture parsing; behaviour booleans unchanged for a fixed logcat fixture |
| 27 | 7 | M | `backend/app/tests/test_analysis_stages.py` | Failed static no longer advances to scoring |

**Explicitly NOT modified:** `backend/app/ml/**` (including `model.pkl`,
`feature_spec.py`, `train_real.py`, `train.py`), `backend/app/services/scoring_service.py`,
`backend/app/services/clustering_service.py`, `backend/adb_keys/**`. Total: 21
source files touched, 6 test files added or modified, across 8 phases.

---

## 6. Stop gates

You asked me to stop if a security assumption cannot be verified. These are the
specific points where that applies. Each one halts the phase it belongs to rather
than the whole plan.

**G0 — Test baseline unknown.** The suite has never been run this session, so
"the tests pass" is an assumption. There is no `pytest.ini`, `pyproject.toml`, or
`setup.cfg` anywhere in the repo, so there is no configured rootdir, testpaths, or
marker set — pytest runs on defaults. Before any code change, run the suite and
record the result. If it is already red, that must be understood first, because
otherwise every later phase inherits an unexplained failure and we cannot tell
our regressions from pre-existing ones. **Blocks: everything.**

**G1 — Probe conclusiveness (Phase 3).** As described in Phase 3, `/dev/tcp` and
`/dev/udp` are shell features whose availability under Android's mksh is not
guaranteed. If probes 2–4 cannot be made to return a *conclusive* result on the
actual target, then TCP and UDP egress remain unverified and only ICMP is proven.
In that case: do not report `containment_verified = True` on ICMP alone. Stop and
report which paths are actually verifiable. Claiming verified containment we have
not demonstrated would be worse than the current unconditional log line, because
it would carry false authority. **Blocks: Phase 3 completion.**

**G2 — redroid deployment unverified.** `infra/redroid/` is committed but there is
no evidence it has ever run. `.env` contains neither `SANDBOX_ADB_HOST` nor
`SANDBOX_EGRESS_BLOCKED_EXTERNALLY`. Under D1 the code is target-agnostic, so this
does **not** block Phases 0–7 — but the redroid half of D1 stays theoretical until
the VM exists and `setup-oracle-host.sh` completes with all four probes blocked.
Do not describe redroid containment as verified before then. **Blocks: nothing;
constrains claims.**

**G3 — ML feature contract (Phase 5).** The §3 escalation. Phase 5 must not merge
until (a), (b), or (c) is chosen, because every option either changes scores or
changes the schema. **Blocks: Phase 5.**

**G4 — Has live mode ever succeeded? CLEARED / YES (2026-08-16).** Live mode has
demonstrably executed on this machine. Full evidence in
`docs/g4-live-mode-evidence.md`; the load-bearing findings:

- A read-only probe of the Docker volume `fraudshield_apk_storage` found 46
  persisted sandbox blobs, of which **14 contain `"mode": "live"`** (32 are
  `simulate`, 0 `mobsf`).
- That stamp is written at exactly one place, `sandbox_manager.py:161`, at the
  **end** of `_run_live`, so it cannot be a configuration label. Each live blob
  therefore proves live execution reached the end of `_run_live()`, including a
  successful ADB connect, an authorized and fully booted device
  (`sys.boot_completed == 1`), and an `adb install` that returned 0.
- **Sample launch, observation/telemetry, and network containment are NOT proven**
  by this evidence. The `monkey` launch returncode is unchecked (`:122-127`);
  logcat may legitimately have captured nothing; and `_harden_network:189-196`
  never checks either `svc disable` returncode yet logs
  `emulator.network_hardened` unconditionally, so **egress containment during
  those 14 runs is UNKNOWN**, per the standing constraint on containment claims.
- All 14 recorded live blobs are **older than 2026-08-10 17:43**, so every one of
  them predates the current live configuration introduced by `761aa92` at
  2026-08-11 22:19 and shipped by `2a8f865`. **No dynamic run has ever been
  recorded under the current configuration**, so current-config live health is a
  **Phase 2 pre-flight concern**, not a settled fact.

*Correction to this plan:* the method previously proposed here — grepping
historical worker logs for `sandbox.live_failed_simulate` versus
`emulator.remote_ready` — is **unexecutable**. The project persists no application
logs at all (`app/core/logging.py` uses structlog `PrintLoggerFactory` → stdout
only; compose declares no `logging:` driver), so absence of those log lines proves
nothing. The mode-stamped artifact blobs are the correct evidence source.

**Blocks: nothing; sets expectations, and adds one Phase 2 pre-flight check.**

**G5 — Emulator image unpinned.** Neither the Android API level nor the system
image is specified anywhere in the repo (`sandbox_security_audit.md` §8 lists both
as UNKNOWN; re-verified). Behavioural results are therefore not reproducible across
machines. Not a blocker, but containment behaviour can legitimately differ between
API levels, so record what was actually tested against. **Blocks: nothing.**

---

## 7. Test strategy

**Before Phase 0:** record the baseline. Tests live in `backend/app/tests/`
(15 files, ~2,500 lines) and run against in-memory SQLite via
`create_engine("sqlite://")` with `StaticPool`, using FastAPI dependency
overrides — no Postgres, Redis, or RabbitMQ needed
(`test_dynamic_cluster_exposure.py:33-40`). `conftest.py` has one autouse fixture
that redirects `emit_fallback` away from live Redis; note its docstring warns that
a plain host `pytest` run can otherwise write into the *production* `ti:fallback_events`
list, since compose publishes Redis on host port 6379. Run in-container or with
the stack down.

**Per phase:** each phase's own gate from §4, plus the full suite. A phase is not
done until both are green.

**Two regression invariants that must hold across every phase:**

1. **API backward compatibility.** `test_dynamic_cluster_exposure.py` asserts the
   pre-existing `DynamicFindingOut` field set and must keep passing *unmodified*.
   If it needs editing to accommodate a change, that change broke compatibility.
2. **Score stability.** Under D3, risk scores must not move. Because
   `scoring_service._fetch_dynamic:301-307` reads an explicit column list, adding
   `mode` cannot perturb it — but this should be asserted, not assumed. A fixed
   static+dynamic fixture scored before and after each phase, compared exactly,
   is the cheapest way to prove the ML path is untouched.

**Not covered by the suite and requiring live verification:** actual ADB
connectivity, real containment probes against a booted emulator, compose topology
changes, and anything in `infra/redroid/`. These need manual runs and should be
recorded in this document as they are completed.

---

## 8. Recommended landing order

Phases 0 → 1 → 2 → 3 → 4 are the security core and should land in that order;
each depends on the previous one's observability or error handling. Phase 7 is
independent and can land any time. Phase 6 should land alone, after 0–4, because
it is the most likely to break a working stack. Phase 5 is blocked on G3 and
should be treated as a separate piece of work rather than a continuation.

The single highest-value change is **Phase 1**, and it carries almost no risk:
`mode` is already computed and already logged, and is discarded at exactly one
line. Everything else in this plan is easier to reason about once provenance is
visible in the database.
