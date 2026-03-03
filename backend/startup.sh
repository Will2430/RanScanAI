#!/bin/bash
set -e

echo "========================================="
echo "  RanScanAI Backend Startup"
echo "========================================="

# ── Install & connect Tailscale ───────────────────────────────────────────────
if [ -n "$TAILSCALE_AUTHKEY" ]; then
    echo "[1/3] Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh

    echo "[2/3] Connecting to Tailscale network..."
    tailscale up \
        --authkey="$TAILSCALE_AUTHKEY" \
        --hostname=ranscan-cloud \
        --accept-routes \
        --shields-up=false

    echo "      Tailscale IP: $(tailscale ip)"
else
    echo "[!] TAILSCALE_AUTHKEY not set — skipping Tailscale (local mode)"
fi

# ── Start FastAPI ─────────────────────────────────────────────────────────────
echo "[3/3] Starting main.py..."
echo "      DATABASE_URL: ${DATABASE_URL:0:40}..."
echo "      MODEL_SERVICE_URL: $MODEL_SERVICE_URL"
echo "      ENVIRONMENT: $ENVIRONMENT"

cd /home/site/wwwroot

uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --log-level info
