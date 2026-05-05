# RanScanAI

RanScanAI is a research platform for lightweight ransomware detection that combines static and dynamic analysis with human-in-the-loop model governance. The goal is to deliver evasion-resistant detection without enterprise sandbox infrastructure while keeping model updates auditable and controlled.

## Research objectives

- Lightweight hybrid ensemble that reduces false negatives (1D CNN for API sequences + XGBoost for PE features, fused with soft voting).
- Open, reproducible Frida-based dynamic instrumentation pipeline for Windows API call extraction.
- Human-in-the-loop governance workflow to handle low-confidence detections and concept drift.

## System overview

- Static branch: XGBoost over PE header and structural features.
- Dynamic branch: 1D CNN over tokenized API call sequences captured with Frida.
- Ensemble: soft-voting fusion with an FNR-aware decision threshold.
- Governance: low-confidence samples routed through VirusTotal lookup and admin verification before retraining.

## Repository layout

- backend/ - FastAPI API, detection routes, reporting, retraining workflow.
- Frontend/ - React dashboard for detections, governance, and reports.
- models/ - Trained model artifacts and metadata.
- browser-extension/ - Legacy extension (kept for reference, not the primary UI).
- ideas/REVISED_OBJECTIVES.md - Full research framing and examiner Q&A.

## Quick start (local dev)

### Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
```

### Frontend

```bash
cd Frontend
npm install
npm start
```

## Configuration

Set environment variables as needed:

- DATABASE_URL - PostgreSQL connection string (required for persistence).
- VIRUSTOTAL_API_KEY - Optional enrichment for low-confidence samples.
- ALLOWED_ORIGINS - Optional CORS configuration for the frontend.
- CNN_MODEL_SERVICE_URL - Optional external CNN inference service endpoint.

See backend/DEPLOYMENT.md for Docker and hosted deployment options.

## Scope and constraints

- Windows PE executables (EXE) only.
- Dynamic analysis runs in a controlled Windows VM with Frida injection.
- Research validation platform, not an enterprise endpoint security product.

## Documentation

- ideas/REVISED_OBJECTIVES.md
- backend/DEPLOYMENT.md
- TESTING_STRATEGY.md
- MODEL_VALIDATION_CLARIFICATION.md
- README_CNN.md
- TRANSFER_GUIDE.md

