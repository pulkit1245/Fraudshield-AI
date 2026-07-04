# FraudShield AI — Backend (Member A)

Backend Lead slice: **Auth · Submissions · Static Analysis · Verdicts & Dashboard**
Branch: `feat/m1-backend-static-analysis`

## Run locally

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # fill in secrets

# bring up Postgres + Redis + RabbitMQ (Member D's infra/docker-compose.yml), then:
alembic upgrade head            # creates users, apk_submissions, static_findings, risk_verdicts, audit_logs
uvicorn app.main:app --reload   # API on http://localhost:8000  (/docs, /health)

# static-analysis worker
celery -A app.workers.tasks.static_task worker -Q static_queue -l info
```

## Tests

```bash
PYTHONPATH=. pytest app/tests/ -v   # runs on in-memory SQLite, no DB needed
```

## What's implemented

| Area | Endpoints / modules |
|------|--------------------|
| Auth | `POST /auth/register·login·refresh`, `GET /auth/me` — bcrypt + HS256 JWT (15m access / 7d refresh), `require_role` RBAC |
| Submissions | `POST/GET /submissions`, `GET /submissions/{id}`, `/status`, `DELETE` — magic-byte APK validation, SHA-256, object storage, duplicate-hash idempotency, pipeline enqueue |
| Static analysis | Androguard / Apktool / JADX wrappers, obfuscation heuristic, `StaticAnalysisService`, Celery `run_static_analysis` task |
| Verdicts | `GET /verdict`, `PATCH /verdict/override` (audited), `POST /verdict/escalate` (IOC record) |
| Dashboard | `GET /dashboard/stats` (Redis-cached 60s), `GET /dashboard/queue` |
| Cross-cutting | structlog JSON logging + `request_id`, standard error envelope, login rate-limiter |

## Contracts

`shared/schemas/auth.json` and `shared/schemas/submission.json` are the source of
truth the frontend (Member D) codes against.

## Integration notes for teammates

- **Member B** (scoring/LLM): the static task calls `run_scoring` by name once
  static + dynamic both finish; add `app.workers.tasks.scoring_task.run_scoring`.
- **Member C** (dynamic/infra): drop in `app/workers/celery_app.py` and the
  `dynamic_findings` migration (0002); `static_task` picks up the shared app
  automatically and advances status to `scoring` when a dynamic row exists.
- All models share `app.core.database.Base` and the portable types in
  `app.core.types` (native UUID/JSONB on Postgres).
