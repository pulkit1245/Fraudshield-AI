# Threat intelligence rule engine

FraudShield stores production TTPs and static-analysis markers in Postgres. The
seed data is deliberately conservative: a sensitive permission or one API call
is evidence, not a verdict. The scoring layer only raises the rule signal for a
TTP when independent markers corroborate it.

Apply the migration before starting workers:

```powershell
docker compose -f infra/docker-compose.yml up --build -d
docker compose -f infra/docker-compose.yml exec backend alembic upgrade head
```

All endpoints below require an `admin` access token:

- `GET /api/v1/admin/threat-intelligence/ttps`
- `POST /api/v1/admin/threat-intelligence/ttps`
- `PUT /api/v1/admin/threat-intelligence/ttps/{ttp_id}`
- `GET /api/v1/admin/threat-intelligence/markers`
- `POST /api/v1/admin/threat-intelligence/markers`
- `PUT /api/v1/admin/threat-intelligence/markers/{marker_id}`
- `PATCH /api/v1/admin/threat-intelligence/markers/{marker_id}/active`

Every write is recorded in `audit_logs`. Do not add generic UI or framework
methods such as `addView`, `WindowManager`, or `loadClass` as standalone rules.
New rules should include a source/reference, be tested against labelled benign
and malicious APKs, and be disabled immediately if they breach the agreed
false-positive threshold.
