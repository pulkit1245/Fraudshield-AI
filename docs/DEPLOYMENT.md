# FraudShield AI — Deployment Guide

**Target:** Render.com (free tier) + Local Emulator on Mac  
**Time:** ~45 minutes (most of it is waiting for first Docker builds)

---

## Prerequisites

- GitHub account (to push this repo)
- Render.com account → [render.com](https://render.com)
- CloudAMQP account → [cloudamqp.com](https://cloudamqp.com)
- Backblaze account → [backblaze.com](https://backblaze.com/b2)
- Android emulator already configured locally (`Medium_Phone` AVD)

---

## Step 1 — Backblaze B2 (APK Storage)

1. Log in → **B2 Cloud Storage** → **Create a Bucket**
   - Bucket Name: `fraudshield-apks`
   - Files in Bucket: **Private**
   - Default Encryption: **Disable**
   - Click **Create a Bucket**

2. Go to **App Keys** → **Add a New Application Key**
   - Name: `fraudshield-render`
   - Bucket: `fraudshield-apks`
   - Type: **Read and Write**
   - Click **Create New Key** → **copy both values immediately** (shown only once)

3. Note down:
   ```
   STORAGE_KEY=<keyID>
   STORAGE_SECRET=<applicationKey>
   STORAGE_ENDPOINT_URL=https://s3.<region>.backblazeb2.com
   STORAGE_REGION=<region>          # shown in bucket details, e.g. us-west-004
   ```

---

## Step 2 — CloudAMQP (RabbitMQ)

1. Log in → **Create New Instance**
   - Name: `fraudshield`
   - Plan: **Little Lemur** (Free)
   - Region: pick closest to your Render region (US Oregon = us-west)
   - Click **Create Instance**

2. Click on the instance → copy **AMQP URL**
   ```
   RABBITMQ_URL=amqps://user:pass@...rmq.cloudamqp.com/vhost
   ```

---

## Step 3 — Push to GitHub

```bash
# From your repo root
git add infra/render.yaml infra/docker-compose.local-dynamic.yml \
        infra/.env.local-dynamic.example .gitignore
git commit -m "chore: add Render deployment config and local dynamic worker"
git push origin main
```

---

## Step 4 — Deploy on Render

1. Go to [dashboard.render.com](https://dashboard.render.com) → **New** → **Blueprint**
2. Connect your GitHub account → select this repo
3. Render detects `infra/render.yaml` → click **Apply**
4. Render asks for `sync: false` env vars — fill them in:

   | Key | Value |
   |-----|-------|
   | `RABBITMQ_URL` | From CloudAMQP Step 2 |
   | `STORAGE_KEY` | From Backblaze Step 1 |
   | `STORAGE_SECRET` | From Backblaze Step 1 |
   | `STORAGE_ENDPOINT_URL` | From Backblaze Step 1 |
   | `GROQ_API_KEY` | Your existing Groq key |
   | `GROQ_API_KEY_2` | Your existing Groq key 2 |
   | `VITE_API_BASE_URL` | Leave blank for now |

5. Click **Apply** → wait ~10-15 minutes for all services to build and start

---

## Step 5 — Post-Deploy: Update Frontend URL

Once backend is live:

1. Render Dashboard → `fraudshield-backend` → copy its URL  
   e.g. `https://fraudshield-backend-xxxx.onrender.com`

2. Go to `fraudshield-frontend` service → **Environment** tab → edit:
   ```
   VITE_API_BASE_URL = https://fraudshield-backend-xxxx.onrender.com
   ```

3. Go to `fraudshield-backend` service → **Environment** tab → edit:
   ```
   CORS_ORIGINS = https://fraudshield-frontend-xxxx.onrender.com,http://localhost:5173
   ```
   (Also update the same in `fraudshield-worker-static` and `fraudshield-beat`)

4. Trigger a **Manual Deploy** on the frontend service to rebuild with the correct API URL.

---

## Step 6 — Local Dynamic Worker

Run this on your Mac to enable live sandbox analysis:

### 6a. Create env file
```bash
cp infra/.env.local-dynamic.example infra/.env.local-dynamic
```

Fill in `infra/.env.local-dynamic` with:
- `DATABASE_URL` — from Render → fraudshield-db → External Connection String
- `REDIS_URL` — from Render → fraudshield-redis → External Connection String
- `RABBITMQ_URL` — same as Step 2
- `JWT_SECRET` — from Render → fraudshield-backend → Environment → JWT_SECRET
- `STORAGE_*` — same as Step 1
- `GROQ_API_KEY` / `GROQ_API_KEY_2` — your Groq keys

### 6b. Start the emulator
```bash
~/Library/Android/sdk/platform-tools/adb -a nodaemon server start &
~/Library/Android/sdk/emulator/emulator @Medium_Phone -dns-server 8.8.8.8
```

### 6c. Start the dynamic worker
```bash
docker compose -f infra/docker-compose.local-dynamic.yml up --build
```

The worker will now:
1. Poll the remote CloudAMQP RabbitMQ for dynamic analysis jobs
2. Download APKs from Backblaze B2
3. Run them in your local Android emulator
4. Upload results back to Backblaze
5. Update results in the remote PostgreSQL database

---

## Verification

```bash
# 1. Check backend health
curl https://fraudshield-backend-xxxx.onrender.com/health

# 2. Check local dynamic worker connected
docker logs fraudshield-local-dynamic-worker-dynamic-1 | grep "celery@"

# 3. Submit a test APK via the deployed frontend URL and watch analysis complete
```

---

## Costs Summary

| Service | Cost |
|---------|------|
| Render (backend + workers + frontend + postgres + redis) | **\$0** |
| CloudAMQP | **\$0** |
| Backblaze B2 (up to 10GB) | **\$0** |
| Android Emulator (Mac) | **\$0** |
| **Total** | **\$0/month** |

> **Note:** Render free PostgreSQL expires after **90 days**. After that, upgrade to \$7/mo or export and migrate data.

---

## Troubleshooting

### Backend shows 502 after deploy
- Free tier services sleep after 15 min. First request after sleep = ~30s cold start. Refresh and wait.

### Dynamic worker can't reach RabbitMQ
- Check `RABBITMQ_URL` in `infra/.env.local-dynamic` — must use `amqps://` (not `amqp://`) for CloudAMQP free tier.

### APK upload fails
- Verify Backblaze bucket is named exactly `fraudshield-apks` and the app key has read+write access.

### Emulator not detected by local worker
```bash
# Make sure ADB is listening on all interfaces
~/Library/Android/sdk/platform-tools/adb -a nodaemon server start
# Verify emulator is online
~/Library/Android/sdk/platform-tools/adb devices
```
