# Phase 0 — Test Baseline Record

**Baseline commit:** `2a8f865 chore: checkpoint before sandbox security hardening`
**Date:** 2026-08-16
**Status:** ✅ **BASELINE ESTABLISHED — gate G0 CLEARED.** `221 passed, 0 failed,
0 errors, 0 skipped` on the rebuilt image. §7.2 records the first, incomplete run
(171 items, stale image) and §7.6 the authoritative one. Both are kept
deliberately: the discrepancy between them is the evidence for §7.5 item 3.
**Production code modified:** none during baselining.

---

## 1. `backend/test_sandbox.py` — EXCLUDED from the baseline

**Verdict: exclude.** Confirmed import-time side effects that perform real
sandbox execution and a real storage write.

The file has no test functions. Everything is at module level, so `pytest`
executes it during **collection**:

| Line | Statement | Effect |
|---|---|---|
| `:9` | `manager = SandboxManager(mode="simulate")` | Constructs the sandbox orchestrator |
| `:13` | `manager._run_simulated(...)` | Runs the simulate path |
| → | `_run_simulated` → `_store_log` (`sandbox_manager.py:218-227`) | → `storage.upload_artifact(...)` |

`storage` is a **module-level singleton** built by
`file_storage._build_storage()`, which returns `S3Storage` whenever
`STORAGE_KEY` **and** `STORAGE_SECRET` are both set. `.env` defines both keys.

- **Current risk:** both values are presently **empty**, so the singleton falls
  back to `LocalStorage` and the write lands in `/tmp/fraudshield-storage`
  (a named Docker volume in-container). Contained, but still a real write, and
  still a fabricated simulate run executed on every `pytest` invocation.
- **Latent risk:** the moment real storage credentials are populated in `.env`,
  collecting this file performs a live `put_object` against the production
  object store. `STORAGE_REGION: us-east-005` indicates Backblaze B2.

Because the baseline targets `app/tests`, this file is outside the target path
anyway. `--ignore=test_sandbox.py` is included regardless, so the exclusion is
explicit rather than incidental.

Per the plan, Phase 0 will rename it to `backend/scripts/manual_sandbox_check.py`.
**Not done yet** — that is a code change and this run is read-only.

---

## 2. Static collection inventory (no dependencies required)

Produced by AST parsing, so this is what a healthy run *should* collect.
It is a reference for the real run, **not** a substitute for it.

| File | Tests | Lines |
|---|---:|---:|
| `test_analysis_stages.py` | 6 | 180 |
| `test_app_classification.py` | 33 | 440 |
| `test_clustering.py` | 4 | 117 |
| `test_dynamic_cluster_exposure.py` | 5 | 193 |
| `test_sanitization.py` | 5 | 100 |
| `test_submissions.py` | 8 | 176 |
| `test_threat_intelligence.py` | 2 | 20 |
| `test_ti_bazaar_otx.py` | 8 | 194 |
| `test_ti_deduplicator.py` | 11 | 183 |
| `test_ti_normalizer.py` | 17 | 165 |
| `test_ti_pipeline_integration.py` | 21 | 388 |
| `test_ti_validator.py` | 34 | 267 |
| `test_virustotal_service.py` | 4 | 60 |
| **TOTAL** | **158** | **2,483** |

> **CORRECTION (post-run, 2026-08-16).** The paragraph that originally stood here
> claimed "No `@pytest.mark.parametrize` anywhere, so collected count should be
> exactly **158**." **That claim was wrong.** There are 12 `parametrize`
> decorators across three files (`test_sanitization.py` ×2,
> `test_ti_validator.py` ×7, `test_virustotal_service.py` ×3). The table above
> therefore counts test *functions*, not collected *items*, and 158 was never the
> right target. Corrected expectations:
>
> | File | Functions | Collected items |
> |---|---:|---:|
> | `test_sanitization.py` | 5 | **32** |
> | `test_ti_validator.py` | 34 | **57** |
> | `test_virustotal_service.py` | 4 | **17** |
> | all other 10 files | 115 | 115 |
> | **TOTAL** | **158** | **221** |
>
> The lesson worth keeping: a function-count inventory cannot validate a
> collected-item count. What it *can* still do is verify that every expected
> **file** appears in the run — and that is exactly the check that caught the
> defect in §7.3.

**Module-level statements that execute at collection time** — all three are
SQLite-local and safe:

- `test_analysis_stages.py` — `Base.metadata.create_all(engine)`, `TestClient(app)`
- `test_dynamic_cluster_exposure.py` — `Base.metadata.create_all(_engine)`, `_make_lead_user()`, `TestClient(app)`
- `test_submissions.py` — `Base.metadata.create_all(engine)`, `TestClient(app)`

No network, no Postgres, no Redis. All use `create_engine("sqlite://")` with
`StaticPool` and FastAPI dependency overrides.

---

## 3. Test-isolation properties verified from source

- **No pytest configuration exists anywhere in the repo.** No `pytest.ini`,
  `pyproject.toml`, `setup.cfg`, or `tox.ini` (verified via `git ls-files`).
  So there is no configured rootdir, `testpaths`, markers, or filterwarnings —
  pytest runs entirely on defaults. This is itself worth knowing: nothing pins
  test discovery, which is why `backend/test_sandbox.py` gets collected at all.
- **`conftest.py` has one autouse fixture** that redirects `emit_fallback` across
  four call-site modules to an in-memory list. Its own docstring documents why:
  without it, `test_ti_normalizer.py::test_unknown_tactic_defaults_to_reconnaissance`
  and `test_ti_bazaar_otx.py::test_fetcher_skips_when_no_api_key` write real
  events into the live `ti:fallback_events` Redis list that the admin TI Pipeline
  dashboard reads — because `infra/docker-compose.yml:84-85` publishes Redis on
  host port 6379. **This is the specific reason not to run a bare `pytest` on the
  host while the stack is up.**
- **Storage during tests** resolves to `LocalStorage` at `/tmp/fraudshield-storage`
  (credentials empty), which is a named volume in-container. No host writes.

---

## 4. Environment probed

| Property | Agent VM (where I run) | Backend container (target) | Host venv |
|---|---|---|---|
| Platform | Linux aarch64 | `python:3.11-slim` | macOS / homebrew |
| Python | 3.10.12 | 3.11 | 3.12.13 |
| PyPI reachable | **No** — proxy 403 Forbidden | yes at build time | n/a |
| Docker daemon | **absent** | n/a | present |
| pytest present | no | **yes** — `Dockerfile:30` installs full `requirements.txt`, which pins `pytest==8.2.2` | yes |
| Tests present | via mount | **yes** — `Dockerfile:33` `COPY . .` | yes |

Network isolation of the agent VM was explicitly probed and confirmed:
`127.0.0.1:6379` → `ConnectionRefusedError`, `127.0.0.1:5433` →
`ConnectionRefusedError`, `host.docker.internal:8000` → `gaierror`. The VM
cannot reach the host's Redis or Postgres.

---

## 5. Why the baseline could not be executed

Three independent blockers, all environmental:

1. **PyPI is blocked** from the agent VM — `uv pip install` failed with
   `Tunnel connection failed: 403 Forbidden` via the `http://localhost:3128`
   proxy. Backend dependencies cannot be installed here.
2. **No Docker daemon** in the agent VM, so I cannot exec into or run the
   backend container, which is the environment the plan (and your instruction)
   designates as correct.
3. **`backend/venv` is a macOS venv** — `pyvenv.cfg` points at
   `/opt/homebrew/...python@3.12`, and extensions are
   `cpython-312-darwin.so`. Unusable on Linux aarch64.

Per stop gate **G0**, the baseline stays unestablished rather than
approximated. An assumed baseline is worse than an absent one, because every
later phase would inherit unattributed failures.

---

## 6. Exact command to establish the baseline

Run from the **repo root on the host**. `--no-deps` keeps Postgres, RabbitMQ,
and Redis from starting, so nothing production-adjacent is touched. `worker-static`
is chosen only because it derives from the backend image; `run` overrides its
command.

```bash
docker compose -f infra/docker-compose.yml run --rm --no-deps \
  -e REDIS_URL=redis://127.0.0.1:6399/0 \
  worker-static \
  pytest app/tests -v --tb=short -rA \
         -p no:cacheprovider \
         --ignore=test_sandbox.py \
  2>&1 | tee phase0-baseline-raw.txt
```

Flag rationale:

- `--no-deps` — no broker, DB, or cache started. The tests need none of them.
- `-e REDIS_URL=redis://127.0.0.1:6399/0` — belt and braces. `conftest.py`
  already patches `emit_fallback`, but this points any unpatched Redis write at
  a dead port *inside* the container so it cannot reach the compose Redis either.
- `-p no:cacheprovider` — prevents `.pytest_cache/` being written into `/app`
  (`appuser` owns `/app` per `Dockerfile:36`, so it otherwise would).
- `--ignore=test_sandbox.py` — the §1 exclusion, stated explicitly.
- `-rA --tb=short` — full per-test summary plus readable tracebacks.
- `PYTHONDONTWRITEBYTECODE=1` is already set in the image at `Dockerfile:19`, so
  no `__pycache__` is written.
- The image builds automatically on first `run` if it does not exist yet.

If the image is stale relative to the checkpoint, prepend a build:

```bash
docker compose -f infra/docker-compose.yml build worker-static
```

> **This build step was omitted on the first run, and the image *was* stale.**
> That is the whole of the §7.3 defect. The corrected, authoritative command is
> §7.4 — use that one, not this section.

---

## 7. Results

### 7.1 Exact command executed

Run by the operator from the repo root on the host, 2026-08-16:

```bash
docker compose -f infra/docker-compose.yml run --rm --no-deps \
  -e REDIS_URL=redis://127.0.0.1:6399/0 \
  worker-static \
  pytest app/tests -v --tb=short -rA -p no:cacheprovider --ignore=test_sandbox.py \
  2>&1 | tee phase0-baseline-raw.txt
```

The `build` step in §6 was **not** prepended. That omission is the cause of §7.3.

Raw output preserved at `phase0-baseline-raw.txt` (repo root, untracked).

### 7.2 Counts and environment

| Field | Value |
|---|---|
| Collected | **171 items** |
| Passed | **171** |
| Failed | **0** |
| Errors | **0** |
| Skipped | **0** |
| xfail / xpass | 0 |
| Collection errors | **none** |
| Warnings | 1 |
| Wall time | 155.26 s (2:35) |
| Platform | linux, Python **3.11.15** |
| pytest | **8.2.2**, pluggy 1.6.0 |
| Plugins | `asyncio-0.23.7`, `anyio-4.14.2` |
| asyncio mode | STRICT |
| rootdir | `/app` (no config file — as predicted in §3) |

The single warning is third-party and not actionable here:
`passlib/utils/__init__.py:854: DeprecationWarning: 'crypt' is deprecated and
slated for removal in Python 3.13`.

**Pre-existing failures: none.** Every one of the 171 collected tests passed, so
there is no red baseline to attribute later. This is the good news, and it is
real as far as it goes — see §7.3 for how far that is.

### 7.3 DEFECT IN THE RUN — two test files never executed

The run collected 11 files. **13 are tracked at `2a8f865`.** Missing:

| File | Functions | Expected items |
|---|---:|---:|
| `test_app_classification.py` | 33 | 33 |
| `test_virustotal_service.py` | 4 | 17 |
| **Unrun total** | **37** | **50** |

`171 + 50 = 221`, matching the corrected §2 projection exactly — which is
consistent with these two files being the *only* thing absent.

**Cause: a stale container image.** Established, not guessed:

1. Both files exist on disk **and** are tracked at HEAD
   (`git ls-files backend/app/tests/` lists all 13). So this is not a missing-file
   problem.
2. `infra/docker-compose.yml` contains **no source bind-mount** — the only
   `volumes:` entries are `apk_storage`, `pgdata`, and the two read-only ADB key
   mounts at `:160-161`. Backend code therefore reaches the container **only**
   via `COPY . .` at `backend/Dockerfile:33`, frozen at image build time.
3. `backend/.dockerignore` excludes only `__pycache__`, `*.py[cod]`, egg-info,
   caches, venvs, `.env*`, `*.log`, and editor dirs. **It does not exclude
   tests.** So the exclusion is not deliberate, and a rebuild will pick them up.
4. Both missing files carry mtime **Aug 11 23:21** — the newest test files in the
   tree by three days. Every file the run *did* collect predates them. The image
   was built before that timestamp.

Ruled out: collection error (pytest reported none, and would have said
`ERROR`), deselection (nothing deselects; no config file exists), and
`--ignore` (targets only `test_sandbox.py`).

**Safety of including them in the re-run — checked, both are clean:**

- `test_app_classification.py` — no module-level executable statements at all
  beyond a `if __name__ == "__main__":` guard. No `TestClient`, no `create_all`
  at import, no `requests`/`httpx`/LLM client construction anywhere; the LLM path
  is `unittest.mock.patch`ed. Its docstring's "no Postgres, no Celery, no LLM API
  key required" is accurate.
- `test_virustotal_service.py` — imports `_CACHEABLE`, `_VT_KEY_RE`,
  `_clean_secret` only. `virustotal_service` holds `_redis = None` at module
  level and builds the client lazily in `_get_redis()`, so **import touches no
  Redis**. `VT_URL` is an unused string constant in these tests. Pure regex and
  set assertions.

### 7.4 Command to complete the baseline

Identical to §7.1 with the build restored:

```bash
docker compose -f infra/docker-compose.yml build worker-static && \
docker compose -f infra/docker-compose.yml run --rm --no-deps \
  -e REDIS_URL=redis://127.0.0.1:6399/0 \
  worker-static \
  pytest app/tests -v --tb=short -rA -p no:cacheprovider --ignore=test_sandbox.py \
  2>&1 | tee phase0-baseline-raw.txt
```

**Acceptance criterion: `collected 221 items`.** Any other number means the
image is still not at `2a8f865` and the count must be reconciled before Phase 1.

### 7.5 Environmental issues observed

**1. The 155 s wall time is ~97% Redis retry backoff, not test work.** Four
`test_submissions.py` tests each stalled ~38 s in two ~19 s blocks. Cause chain,
all benign and all a direct consequence of the intentional dead-port
`REDIS_URL`:

- `app/api/v1/submissions.py:54-59` wraps `run_static_analysis.delay()` in
  `try/except Exception` and logs `enqueue.static_failed`. Its own docstring at
  `:51` states the intent: *"enqueue is best-effort so a missing broker (local
  dev) never fails the upload."*
- Before that except fires, Celery's redis **result backend** burns its full
  retry policy: `Connection to Redis lost: Retry (0..19/20)` at 1 s each, then
  `Retry limit exceeded`. Twice per test — once for static, once for the dynamic
  `send_task` at `:62-65`.

So the tests pass *because* enqueue failure is swallowed by design. **This is not
a masked test failure and must not be "fixed" as one.** Recommendation: keep the
dead-port override and accept the three minutes. Safety outweighs speed, and the
alternative (`task_always_eager`) would *execute* analysis tasks, which is
strictly worse.

Worth noting for the record, though out of scope: this best-effort-enqueue
pattern is the same *class* of silent degradation as the sandbox live→simulate
fallback this project exists to remove — a submission can be created, return
`201`, and never be analysed, with only a `warning` emitted. Logged as an
observation; not in the plan, not being changed.

**2. `phase0-baseline-raw.txt` was written to the repo root**, where it shows as
untracked. Move it under `docs/` or add it to `.gitignore` before committing.

**3. Stale-image risk is structural, not a one-off.** Because no source is
bind-mounted, *every* in-container test run silently tests whatever the image was
last built from. Every later phase in this plan must prepend
`docker compose build` or it will validate stale code. This belongs in the
per-phase test procedure.

### 7.6 AUTHORITATIVE BASELINE — re-run with rebuild (G0 CLEARED)

Executed 2026-08-16 17:28 with `build` prepended, exactly as §7.4 specifies.

| Field | Value |
|---|---|
| Collected | **221 items** — matches the §2 projection exactly |
| Passed | **221** |
| Failed | **0** |
| Errors | **0** |
| Skipped | **0** |
| Collection errors | **none** |
| Warnings | 1 (same `passlib`/`crypt` deprecation) |
| Wall time | 156.95 s (2:36) |

**This is the baseline of record for every subsequent phase.**

`171 + 33 + 17 = 221` confirmed against the run: `test_app_classification.py`
contributed its 33 tests and `test_virustotal_service.py` its 17 parametrized
items, and **nothing else changed**. Every one of the 171 previously-passing tests
passed again. The two previously-unrun files were green on first execution, so:

**Pre-existing failures at `2a8f865`: none, across all 13 test files.** There is
no red to inherit, and any failure appearing in Phase 1 onward is ours.

Notable only as confirmation the code path is exercised, not as a problem: the
`test_virustotal_service.py` cases emit
`vt.key_had_inline_comment  hint=Stripped a trailing '# ...' comment from
VIRUSTOTAL_API_KEY` on stdout. That is the assertion under test firing, in-process,
against a synthetic `"a"*64` key. No real secret and no network involved.

Two consequences worth carrying forward:

1. The `--ignore=test_sandbox.py` flag becomes unnecessary once Phase 0 item 4
   renames that file out of `test_*.py` shape. Until then, keep it.
2. `collected 221 items` is now the regression tripwire. A phase that changes this
   number must say why — additions from the plan's new test files are expected and
   should be stated explicitly per phase (Phase 1 adds
   `test_dynamic_provenance.py`, and so on).

---

## 8. Baseline status

**Verdict: G0 CLEARED. 221/221 green at `2a8f865`, all 13 test files executed.**

What is trustworthy:

- 221 of 221 collected items pass, in the correct environment (the backend image,
  Python 3.11.15, pytest 8.2.2), with zero failures, errors, collection errors, or
  skips. **No pre-existing red exists anywhere in the suite.**
- The collected count was predicted to the item before the run and matched, so
  we know nothing was silently absent — which is precisely the failure mode that
  spoiled the first attempt.
- Isolation held on both runs. No Postgres, RabbitMQ, or Redis was started
  (`--no-deps`); the only Redis contact attempts went to the dead port `6399`
  *inside* the container; storage resolved to `LocalStorage` in a named volume; no
  `.pytest_cache` or `__pycache__` was written into `/app`. Nothing
  production-adjacent was touched, and no application code was modified to get
  here.

What remains explicitly unverified — recorded so it is never mistaken for covered:

- Real ADB connectivity, live containment probes against a booted emulator,
  compose topology behaviour, and everything under `infra/redroid/`. The suite
  touches none of it (see plan §7). Gates G2 and G5 stay open.
- Whether `live` sandbox mode has ever succeeded on this machine (gate G4). Not a
  test question; needs a worker-log grep before Phase 2.

The 158-item prediction in §2 was wrong in a way that is worth naming: it
under-counted by ignoring parametrization *and* over-counted by including two
files the image lacked, and those two errors partially cancelled. Had the run
returned 158 it would have looked like a match while concealing both faults. The
per-*file* cross-check is what surfaced it, which is why §7.4 pins an exact
expected count rather than a "looks about right" range.

---

## 9. Confirmation of read-only conduct

No application code, migration, Docker Compose, frontend, or infrastructure file
was modified during Phase 0. No test was "fixed". The ML scoring path was not
touched. `git log` still shows `2a8f865` as HEAD.

Files created this phase are documentation and captured output only:

- `docs/sandbox-hardening-plan.md`
- `docs/phase0-test-baseline.md`
- `phase0-baseline-raw.txt` — raw pytest output at repo root; see §7.5 item 2

Remaining Phase 0 items from the plan (§4, Phase 0, steps 2–4) were implemented
**after** the baseline was established, so they are attributable and revertable
independently of it:

- `backend/Dockerfile` — removed the `adb_keys` bake (`:38-42`); replaced with
  `RUN mkdir -p /home/appuser/.android && chown appuser:appuser ...` after
  `useradd`, so the compose read-only mount target (`:160-161`) pre-exists
  correctly owned. No functional change for `worker-dynamic`, which already
  received the real keypair via that mount and whose mount already shadowed the
  baked copy.
- `backend/.dockerignore` — added `adb_keys/`, closing the implicit second copy
  via `COPY . .` at `Dockerfile:33`. Note these two edits must land **together**:
  ignoring the directory while an explicit `COPY adb_keys/...` remains would fail
  the build.
- `backend/test_sandbox.py` → `backend/scripts/manual_sandbox_check.py` via
  `git mv` (recorded as `R`, history preserved). Rewrote the `sys.path` hop for
  the extra directory level and moved all execution behind
  `if __name__ == "__main__":`, verified by AST inspection to leave **no
  module-level side effects**. The name no longer matches `test_*.py`, so pytest
  cannot collect it, and `--ignore=test_sandbox.py` is now redundant.

`backend/adb_keys/` was already in `.gitignore:6` and has never been tracked, so
the "not in Git" half of that constraint was already satisfied; only the image
bake needed removing.

A throwaway virtualenv was created outside the repository tree and is empty
because the dependency install failed. Nothing was written into the repo.
