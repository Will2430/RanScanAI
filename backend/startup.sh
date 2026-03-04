#!/bin/bash
# no set -e — we want uvicorn to start even if Tailscale setup fails

echo "========================================="
echo "  RanScanAI Backend Startup"
echo "========================================="

# ── Install & connect Tailscale ───────────────────────────────────────────────
if [ -n "$TAILSCALE_AUTHKEY" ]; then
    echo "[1/3] Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh

    echo "      Starting tailscaled daemon (userspace networking — no /dev/net/tun needed)..."
    tailscaled \
        --tun=userspace-networking \
        --state=/tmp/tailscaled.state &
    sleep 3

    echo "[2/3] Connecting to Tailscale network..."
    # timeout 30s — if tailscale up hangs, continue anyway; daemon is already
    # running in the background and will finish authenticating on its own.
    timeout 30 tailscale up \
        --authkey="$TAILSCALE_AUTHKEY" \
        --hostname=ranscan-cloud \
        --accept-routes \
        --shields-up=false \
        --timeout=25s || echo "[!] tailscale up timed out — daemon still running in background"

    echo "      Tailscale IP: $(tailscale ip 2>/dev/null || echo 'pending...')"

    # Route outbound Python traffic through the Tailscale SOCKS5 proxy.
    # NO_PROXY excludes Azure-internal services (PostgreSQL, etc.) that are
    # reachable directly without going through Tailscale.
    export NO_PROXY=localhost,127.0.0.1,ranscanai-server.postgres.database.azure.com,.postgres.database.azure.com,.azure.com,.windows.net
    echo "      Proxy set: ALL_PROXY=socks5://localhost:1055"
else
    echo "[!] TAILSCALE_AUTHKEY not set — skipping Tailscale (local mode)"
fi

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
