#!/bin/bash
# no set -e — we want uvicorn to start even if Tailscale setup fails

echo "========================================="
echo "  RanScanAI Backend Startup"
echo "========================================="

# ── Start FastAPI ─────────────────────────────────────────────────────────────
echo "[3/3] Starting main.py..."
echo "      DATABASE_URL: ${DATABASE_URL:0:40}..."
echo "      MODEL_SERVICE_URL: $CNN_MODEL_SERVICE_URL"
echo "      ENVIRONMENT: $ENVIRONMENT"

cd "${APP_PATH:-/home/site/wwwroot}"

# Oryx sets $VIRTUAL_ENV from oryx-manifest.toml on every startup.
# Fall back to the known default venv name if not set.
VENV="${VIRTUAL_ENV:-/home/site/wwwroot/antenv}"
echo "      VIRTUAL_ENV=$VENV"

GUNICORN="$VENV/bin/gunicorn"
if [ ! -f "$GUNICORN" ]; then
    echo "[ERROR] $GUNICORN not found — venv was not built."
    echo "        The .deployment file should have forced a build. Check deployment logs."
    exit 1
fi

echo "      Using: $GUNICORN"
exec "$GUNICORN" -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 main:app
