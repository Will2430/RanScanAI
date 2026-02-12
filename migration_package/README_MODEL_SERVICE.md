# SecureGuard Model Service Setup Guide

## Architecture Overview

```
┌─────────────────────────────────────────┐
│  Main Project (Python 3.14)             │
│  ├─ main.py (FastAPI)                  │
│  ├─ Uses CNNModelClient                │
│  └─ No TensorFlow imports              │
└───────────────┬─────────────────────────┘
                │ HTTP (port 8001)
                ▼
┌─────────────────────────────────────────┐
│  Model Service (Python 3.10 Conda)      │
│  ├─ model_service.py                   │
│  ├─ Loads TensorFlow/Keras model       │
│  └─ Serves predictions via REST API    │
└─────────────────────────────────────────┘
```

## Setup Steps

### 1. Install Dependencies in Model Service Environment

**In your Python 3.10 conda environment:**

```bash
# Activate conda environment
conda activate base  # or your environment name

# Navigate to migration_package
cd C:\Users\User\OneDrive\Test\K\migration_package

# Install required packages
pip install fastapi uvicorn tensorflow scikit-learn joblib numpy pandas
```

### 2. Save Scaler (Optional but Recommended)

**Add this to your training notebook after training:**

```python
# After trainer.load_and_prepare_data()
import joblib
scaler_path = "C:/Users/User/OneDrive/Test/K/models/scaler.pkl"
joblib.dump(trainer.scaler, scaler_path)
print(f"Scaler saved to {scaler_path}")
```

### 3. Start the Model Service

**Option A: Using batch file (Windows)**
```bash
# Double-click or run:
start_model_service.bat
```

**Option B: Manual start**
```bash
# Activate conda environment
conda activate base

# Run service
cd C:\Users\User\OneDrive\Test\K\migration_package
python model_service.py
```

The service will start on **http://127.0.0.1:8001**

### 4. Update Your Main Project

**In your main project (Python 3.14):**

```bash
# Install only the HTTP client (no TensorFlow needed!)
pip install requests

# Set environment variable to use CNN
set USE_CNN_MODEL=true

# Start your main API
python main.py
```

The main API will run on **http://127.0.0.1:8000**

## Usage

### Testing the Model Service Directly

```bash
# Health check
curl http://127.0.0.1:8001/health

# Upload file for scanning
curl -X POST -F "file=@path/to/file.exe" http://127.0.0.1:8001/predict/bytes
```

### Testing via Main API

```bash
# Your main API now proxies to model service
curl -X POST http://127.0.0.1:8000/scan -H "Content-Type: application/json" -d "{\"file_path\": \"C:/path/to/file.exe\"}"
```

## Environment Variables

### Main Project (main.py)
```bash
# Enable CNN model
set USE_CNN_MODEL=true

# Set model service URL (default: http://127.0.0.1:8001)
set CNN_MODEL_SERVICE_URL=http://127.0.0.1:8001
```

## Troubleshooting

### Model Service Won't Start

1. **Check conda environment:**
   ```bash
   conda activate base
   python --version  # Should be 3.10.x
   ```

2. **Verify TensorFlow:**
   ```bash
   python -c "import tensorflow; print(tensorflow.__version__)"
   ```

3. **Check model path:**
   - Ensure trained model exists in `C:/Users/User/OneDrive/Test/K/models/`
   - Look for files like `cnn_zenodo_YYYYMMDD_HHMMSS.keras`

### Main API Can't Connect to Model Service

1. **Verify service is running:**
   ```bash
   curl http://127.0.0.1:8001/health
   ```

2. **Check firewall:** Ensure port 8001 is not blocked

3. **View logs:** Check model_service.py output for errors

### Port Already in Use

Change the port in `model_service.py`:
```python
# At the bottom of model_service.py
uvicorn.run(
    "model_service:app",
    host="127.0.0.1",
    port=8002,  # Change this
    reload=True,
    log_level="info"
)
```

Then update `CNN_MODEL_SERVICE_URL` in main project:
```bash
set CNN_MODEL_SERVICE_URL=http://127.0.0.1:8002
```

## Benefits of This Architecture

✅ **No dependency conflicts** - Each service runs in its own Python environment  
✅ **Easy updates** - Update model without touching main app  
✅ **Scalability** - Can deploy model service on different machine  
✅ **Language agnostic** - Any language can call the REST API  
✅ **Multiple models** - Can run multiple model versions simultaneously  
✅ **Production ready** - Standard microservices pattern

## File Structure

```
migration_package/
├── model_service.py           # TensorFlow model serving (Python 3.10)
├── cnn_client.py             # HTTP client for main.py (Python 3.14)
├── cnn_model.py              # Original model code (reference)
├── main.py                   # Modified to use cnn_client
├── start_model_service.bat   # Windows startup script
└── README_MODEL_SERVICE.md   # This file

models/
├── cnn_zenodo_*.keras        # Trained model
├── scaler.pkl                # Feature scaler (optional)
└── cnn_model_metadata.json   # Model metrics
```

## Next Steps

1. ✅ Train model in notebook (Python 3.10)
2. ✅ Start model service: `python model_service.py`
3. ✅ Set environment: `set USE_CNN_MODEL=true`
4. ✅ Start main API: `python main.py`
5. ✅ Test scanning!
