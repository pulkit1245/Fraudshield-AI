# FraudShield AI

GenAI-based automated analysis & risk scoring of fraudulent Android APKs.
Analysts upload a suspicious APK; a queue-driven pipeline runs static + dynamic
analysis in parallel, screens every extracted string through an adversarial
**sanitization layer**, scores it with an ML ensemble + Claude reasoning, and
returns a plain-English report with a 0–100 risk verdict, TTP mapping and
campaign clustering.

> CyberShield Hackathon · 4-member team · 48-hour build.
> Full architecture: [`fraudshield_architecture.html`](../fraudshield_architecture.html).

## Architecture

```
React (Vercel) ──HTTPS/JWT──▶ FastAPI (Railway)
                                  │ enqueue
                    ┌─────────────┴─────────────┐
              Celery: static_queue         Celery: dynamic_queue
              Androguard/Apktool/JADX      Frida + AVD (zero egress)
                    └─────────────┬─────────────┘
                          Sanitization layer  (strips prompt-injection)
                                  │
                    ML ensemble (XGBoost + autoencoder + SHAP)
                                  │
                    Claude API (agentic, RAG over fraud-TTP KB)
                                  │
                    Risk verdict + report + campaign clustering
              PostgreSQL + pgvector · Redis · RabbitMQ · S3-compatible storage
```

## Tech stack

React 18 + TS + Vite + Tailwind + Recharts · FastAPI + Pydantic v2 · Celery /
RabbitMQ / Redis · PostgreSQL 15 + pgvector · XGBoost / PyTorch / SHAP · Claude
API · Docker · GitHub Actions · Railway + Vercel.

## Quick start (Docker)

```bash
cp .env.example .env          # fill in JWT_SECRET, CLAUDE_API_KEY, etc.
docker compose -f infra/docker-compose.yml up --build
```

- Frontend → http://localhost:5173
- API docs → http://localhost:8000/docs
- Health → http://localhost:8000/health
- Flower (queues) → http://localhost:5555
- RabbitMQ UI → http://localhost:15672

## Local dev (without Docker)

**Backend**
```bash
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
celery -A app.workers.celery_app worker -Q static_queue -l info
celery -A app.workers.celery_app worker -Q dynamic_queue -c 1 -l info
```

**Frontend**
```bash
cd frontend && npm install
npm run dev          # http://localhost:5173
```

## Tests

```bash
cd backend && pytest app/tests -q      # 42 tests: auth, submissions, sanitization, clustering
cd frontend && npm run test -- --run   # Vitest + React Testing Library
```

## Team & ownership

| Member | Area | Branch |
|--------|------|--------|
| A | Backend lead · auth, submissions, static analysis, verdicts | `feat/m1-backend-static-analysis` |
| B | AI/ML · sanitization, scoring, LLM orchestration, chat | `feat/m2-ai-ml-pipeline` |
| C | Dynamic analysis & data infra · sandbox, clustering, VirusTotal, Celery | `feat/m3-dynamic-analysis-infra` |
| D | Frontend & DevOps/integration | `feat/m4-frontend-devops` |

## Contracts

API request/response shapes are defined in [`shared/API_CONTRACTS.md`](../shared/API_CONTRACTS.md)
and [`shared/schemas/`](../shared/schemas). The frontend types mirror them in
`frontend/src/types/index.ts`.

## Demo

- Live demo: _add Vercel URL before submission_
- Demo video: _add link_
- Release tag: `v1.0.0-submission`
