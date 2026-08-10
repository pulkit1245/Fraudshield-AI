# FraudShield AI — backend image (FastAPI + Celery workers share this image).
# Multi-stage: build wheels in a fat image, run in a slim one.
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# Build deps for psycopg2 / androguard etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# Runtime libs only (libpq for psycopg2; adb for live sandbox analysis).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    android-tools-adb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY . .

# Non-root runtime user.
RUN useradd --create-home --uid 1000 appuser && chown -R appuser /app

# Bake the host ADB keypair in so the dynamic worker can authenticate to
# the Android emulator over host.docker.internal:5555 without manual setup.
COPY --chown=appuser:appuser adb_keys/adbkey     /home/appuser/.android/adbkey
COPY --chown=appuser:appuser adb_keys/adbkey.pub /home/appuser/.android/adbkey.pub
RUN chmod 600 /home/appuser/.android/adbkey



USER appuser

# Re-serialize the classifier against the container's exact XGBoost version.
# model.pkl (trained on real CICMalDroid2020 data, ROC-AUC 0.955) is the primary
# artifact. We re-dump it via joblib so there's no cross-version pickle warning.
# If the CSV training data is present we can retrain from scratch with train_real.py.
RUN PYTHONPATH=/app python3 -c "\
import joblib, warnings; \
warnings.filterwarnings('ignore', category=UserWarning, module='xgboost'); \
b = joblib.load('app/ml/classifier/model.pkl'); \
joblib.dump(b, 'app/ml/classifier/model.pkl'); \
print('model.pkl re-serialized:', b.get('model_version'))"

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:8000/health'); sys.exit(0)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
