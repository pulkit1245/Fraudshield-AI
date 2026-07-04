# FraudShield AI — API Contracts (source of truth)

All request/response shapes live as JSON Schema in [`shared/schemas/`](./schemas).
Change a schema and the API_CONTRACTS entry in the **same PR** (§9 Git Workflow).
CI validates every `shared/schemas/*.json` on each PR.

- **Base URL:** `${VITE_API_BASE_URL}` (local `http://localhost:8000`)
- **Prefix:** `/api/v1`
- **Auth:** `Authorization: Bearer <access_token>` (15-min access, 7-day refresh)
- **Error envelope (all non-2xx):**
  ```json
  { "error": { "code": "string", "message": "string|object", "request_id": "string" } }
  ```

## Endpoint map → owner → schema

| Group | Endpoints | Owner | Schema |
|-------|-----------|-------|--------|
| Auth | `POST /auth/register·login·refresh`, `GET /auth/me` | A | [auth.json](./schemas/auth.json) |
| Submissions | `POST/GET /submissions`, `GET /submissions/{id}`, `/status`, `DELETE` | A | [submission.json](./schemas/submission.json) |
| Verdicts | `GET /submissions/{id}/verdict`, `PATCH …/override`, `POST …/escalate` | A | submission.json |
| Dashboard | `GET /dashboard/stats`, `GET /dashboard/queue` | A | submission.json |
| ML / Report | `GET /submissions/{id}/ml-score`, `/report` | B | — |
| Chat | `POST /submissions/{id}/chat` | B | [chat.json](./schemas/chat.json) |
| Clusters | `GET /clusters`, `GET /clusters/{id}`, `POST /clusters/recompute` | C | [cluster.json](./schemas/cluster.json) |
| VirusTotal | `GET /submissions/{id}/virustotal` | C | cluster.json |

## Pipeline status values

`queued → static_running → dynamic_running → scoring → completed` (or `failed`).
The frontend polls `GET /submissions/{id}/status` every 3s until `completed`.

## Severity bands & actions

`severity_band ∈ {low, medium, high, critical}` ·
`recommended_action ∈ {monitor, alert_customers, block_hash, escalate_cert_in}`

## Environment variables (owner)

| Variable | Owner | Description |
|----------|-------|-------------|
| DATABASE_URL | A | Postgres connection string |
| JWT_SECRET | A | HS256 signing secret |
| STORAGE_BUCKET / STORAGE_KEY / STORAGE_SECRET | A | S3-compatible object storage |
| REDIS_URL | C | Cache + Celery result backend |
| RABBITMQ_URL | C | Celery broker |
| VIRUSTOTAL_API_KEY | C | Hash cross-check |
| CLAUDE_API_KEY | B | LLM orchestration |
| VITE_API_BASE_URL | D | Frontend → backend base URL |

## Frontend types

TypeScript mirrors of these contracts live in
[`frontend/src/types/index.ts`](../frontend/src/types/index.ts) and must be kept
in lockstep with the schemas above.
