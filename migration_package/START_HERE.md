# Quick Start Guide - CNN Model Service

## ✅ Setup Complete!

All dependencies have been installed in your `torch-gpu` conda environment.

## 🚀 How to Run

### Step 1: Start Model Service (Terminal 1)

```powershell
# Use the torch-gpu Python directly
& "C:\Users\User\anaconda3\envs\torch-gpu\python.exe" model_service.py
```

**Expected output:**
```
🚀 Starting CNN Model Service...
Loading model from C:/Users/User/OneDrive/Test/K/models/cnn_zenodo_*.keras
✓ Model loaded successfully
✅ CNN Model Service ready!
```

Service will run on: **http://127.0.0.1:8001**

### Step 2: Start Main API (Terminal 2)

```powershell
# Set environment variable to use CNN
$env:USE_CNN_MODEL = "true"

# Run main API (Python 3.14)
python main.py
```

**Expected output:**
```
🚀 Starting SecureGuard Backend...
Connecting to CNN model service...
✓ Connected to CNN model service at http://127.0.0.1:8001
✅ SecureGuard Backend ready!
```

Main API will run on: **http://127.0.0.1:8000**

## 🧪 Test It

### Test Model Service Directly

```powershell
# Health check
curl http://127.0.0.1:8001/health

# Test prediction (upload a file)
curl -X POST -F "file=@C:\path\to\your\file.exe" http://127.0.0.1:8001/predict/bytes
```

### Test Main API

```powershell
# Scan a file
curl -X POST http://127.0.0.1:8000/scan `
  -H "Content-Type: application/json" `
  -d '{\"file_path\": \"C:/path/to/file.exe\"}'
```

## 📋 Architecture

```
Python 3.14                          Python 3.10 (torch-gpu)
┌──────────────┐                    ┌────────────────────┐
│  main.py     │  HTTP Request      │  model_service.py  │
│  (Port 8000) │ ──────────────────>│  (Port 8001)       │
│              │                    │                    │
│ CNNClient    │ <──────────────────│  TensorFlow Model  │
│              │  HTTP Response     │                    │
└──────────────┘                    └────────────────────┘
```

## 🔧 Troubleshooting

### Model Service Won't Start

**Check if model exists:**
```powershell
dir C:\Users\User\OneDrive\Test\K\models\cnn_zenodo_*.keras
```

**Verify Python version:**
```powershell
& "C:\Users\User\anaconda3\envs\torch-gpu\python.exe" --version
# Should show: Python 3.10.x
```

**Test TensorFlow:**
```powershell
& "C:\Users\User\anaconda3\envs\torch-gpu\python.exe" -c "import tensorflow; print(tensorflow.__version__)"
```

### Main API Can't Connect

**Check if model service is running:**
```powershell
curl http://127.0.0.1:8001/health
```

**Verify environment variable:**
```powershell
echo $env:USE_CNN_MODEL
# Should output: true
```

### Port Already in Use

**Change model service port** in `model_service.py`:
```python
uvicorn.run(
    "model_service:app",
    port=8002,  # Change this
    # ...
)
```

Then update main API:
```powershell
$env:CNN_MODEL_SERVICE_URL = "http://127.0.0.1:8002"
```

## 📝 Important Notes

- ✅ **NO need to activate conda** - we use the full Python path
- ✅ **Both services must run** - start model service first
- ✅ **Different Python versions** - no conflicts!
- ✅ **Keep both terminals open** while using the system

## 🎯 Next Steps

1. ✅ Dependencies installed
2. ▶️ Start model service (Terminal 1)
3. ▶️ Start main API (Terminal 2)
4. 🧪 Test with a file
5. 🎉 Enjoy zero dependency conflicts!
