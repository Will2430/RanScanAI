# 🚀 Backend Deployment Guide

Universal deployment configuration for RanScanAI backend. Works with **Railway**, **Render**, **Fly.io**, **Google Cloud Run**, **AWS**, **Azure**, and more.

## 📁 Files Included

**In `backend/` folder:**
- **`Dockerfile`** - Container configuration (works everywhere)
- **`.dockerignore`** - Excludes unnecessary files from Docker builds
- **`Procfile`** - Fallback for platforms that don't use Docker by default
- **`runtime.txt`** - Python version specification
- **`.env.example`** - Environment variables template

**In repo root:**
- **`railway.json`** - Railway configuration (tells it to build from backend/ subfolder)

---

## 🌐 Quick Deploy Options

### Option 1: Railway (Easiest)

**Important:** Railway needs `railway.json` at repo root to find the backend folder.

```bash
# 1. Install Railway CLI
npm i -g @railway/cli

# 2. Login
railway login

# 3. Initialize from REPO ROOT (not backend folder)
railway init

# 4. Set environment variables
railway variables set DATABASE_URL=your_database_url
railway variables set VIRUSTOTAL_API_KEY=your_key

# 5. Deploy (Railway will use railway.json config)
railway up
```

**Or via Dashboard:**
1. Go to [railway.app](https://railway.app) → New Project
2. Deploy from GitHub repo → Select RanScanAI
3. Railway auto-detects `railway.json` and builds from `backend/`
4. Add environment variables in Variables tab
5. Deploy!

### Option 2: Render
```bash
# 1. Push to GitHub
# 2. Go to render.com → New → Web Service
# 3. Connect your repo
# 4. Settings:
#    - Root Directory: backend
#    - Build Command: (leave empty, uses Dockerfile)
#    - Start Command: (leave empty, uses Dockerfile)
# 5. Add environment variables in dashboard
# 6. Deploy
```

### Option 3: Fly.io
```bash
# 1. Install Fly CLI
curl -L https://fly.io/install.sh | sh

# 2. Login
fly auth login

# 3. From backend directory
cd backend
fly launch

# 4. Set secrets
fly secrets set DATABASE_URL=your_database_url
fly secrets set VIRUSTOTAL_API_KEY=your_key

# 5. Deploy
fly deploy
```

### Option 4: Google Cloud Run
```bash
# 1. Install gcloud CLI
# 2. Login
gcloud auth login

# 3. Build and push container
cd backend
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/ranscanai-backend

# 4. Deploy
gcloud run deploy ranscanai-backend \
  --image gcr.io/YOUR_PROJECT_ID/ranscanai-backend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars DATABASE_URL=your_url

# 5. Set additional env vars in Cloud Run console
```

---

## 🔧 Local Docker Testing

Test the Docker build locally before deploying:

```bash
# Build
cd backend
docker build -t ranscanai-backend .

# Run (with environment variables)
docker run -p 8000:8000 \
  -e DATABASE_URL=your_database_url \
  -e VIRUSTOTAL_API_KEY=your_key \
  ranscanai-backend

# Visit http://localhost:8000/docs
```

---

## 📋 Required Environment Variables

Set these in your deployment platform:

### Essential
- `DATABASE_URL` - PostgreSQL connection string
- `PORT` - Auto-set by most platforms (defaults to 8000)

### Optional but Recommended
- `VIRUSTOTAL_API_KEY` - For threat enrichment (can work without)
- `ALLOWED_ORIGINS` - CORS configuration (e.g., `https://yourdomain.com`)
- `MAX_FILE_SIZE_MB` - Max upload size (default: 100)

### Database Alternatives (pick one)
**Option A:** Full connection string
```
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname
```

**Option B:** Individual components (backend will construct URL)
```
DB_HOST=your-server.postgres.database.azure.com
DB_NAME=ranscanai
DB_USER=admin
DB_PASSWORD=your_password
DB_PORT=5432
```

---

## 📦 Model Files Handling

**Issue:** ML models are large (6-20 MB each, 70+ MB total)

### Solutions:

**For Testing (Small Scale):**
- Include models in repo (already done)
- Dockerfile copies them automatically

**For Production (Recommended):**
```dockerfile
# Add to Dockerfile before CMD:
RUN wget https://your-storage.com/models.tar.gz && \
    tar -xzf models.tar.gz -C /app/ && \
    rm models.tar.gz
```

**Or mount as volume:**
- Railway: Use Railway Volumes
- Render: Use Render Disks
- AWS: Use EFS or S3
- GCP: Use Cloud Storage FUSE

---

## 🗄️ Database Setup

Most platforms offer managed PostgreSQL:

**Railway:**
```bash
railway add postgresql
# Automatically sets DATABASE_URL
```

**Render:**
- Create PostgreSQL database from dashboard
- Copy connection string to environment variables

**Fly.io:**
```bash
fly postgres create
fly postgres attach --app your-app-name
```

**After deploying database:**
1. Run migrations (init DB schema)
2. Backend will auto-create tables on first run via `db_manager.py`

---

## 🔍 Health Checks

All platforms support health checks. Endpoint: `/health`

**Example (Fly.io `fly.toml`):**
```toml
[http_service]
  internal_port = 8000
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  [http_service.checks]
    [http_service.checks.status]
      grace_period = "10s"
      interval = "30s"
      method = "GET"
      timeout = "5s"
      path = "/health"
```

---

## 🐛 Troubleshooting

### Railway: "Script start.sh not found" or "could not determine how to build"
- **Fix:** Ensure `railway.json` exists at repo root (not in backend folder)
- Railway needs this file to locate backend subfolder
- Redeploy after adding the file

### Build fails with "No module named..."
- Check `requirements.txt` includes all dependencies
- Run `pip freeze > requirements.txt` locally to update

### Port binding errors
- Ensure `CMD` uses `${PORT:-8000}` (reads PORT env var)
- Platform sets PORT automatically

### Models not loading
- Check paths in `.env` (relative to backend directory)
- Verify models exist: `ls -lh models/`
- Check logs for file path errors

### Database connection fails
- Verify `DATABASE_URL` format: `postgresql+asyncpg://...`
- Check firewall allows platform IP ranges
- For Azure: Enable "Allow Azure services"

### CORS errors
- Set `ALLOWED_ORIGINS` in environment variables
- Add your frontend domain: `https://your-frontend.vercel.app`

---

## 💰 Cost Estimates (Free Tiers)

| Platform | Free Tier Limits |
|----------|-----------------|
| **Railway** | $5 credit/month, ~500 hrs |
| **Render** | 750 hrs/month (1 instance) |
| **Fly.io** | 3 shared CPUs, 256MB RAM |
| **Google Cloud Run** | 2M requests/month |

**Recommendation for testing:** Start with Railway or Render (easiest setup)

---

## 🎯 Next Steps

1. Choose a platform above
2. Create database (PostgreSQL)
3. Set environment variables
4. Deploy using platform's method
5. Test at `https://your-app-url.com/docs`
6. Connect browser extension to deployed API

---

## 📚 Additional Resources

- [Railway Docs](https://docs.railway.app/)
- [Render Docs](https://render.com/docs)
- [Fly.io Docs](https://fly.io/docs/)
- [FastAPI Deployment](https://fastapi.tiangolo.com/deployment/)
