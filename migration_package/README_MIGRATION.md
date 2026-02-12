# SecureGuard CNN - Migration Package

**Created:** 2026-02-05 02:00:59

## What's Included

This package contains everything needed to train the CNN model on a GPU-enabled machine:

### Training Scripts
- `train_cnn_zenodo.py` - Main training script
- `check_ready.py` - Pre-training verification

### Model Code  
- `Iteration_1/backend/ml_model_cnn.py` - CNN detector implementation

### Configuration
- `requirements_cnn.txt` - Python dependencies

### Documentation
- `README_CNN.md` - Full documentation
- `QUICKSTART_CNN.md` - Quick start guide
- `INSTALL_GPU_GUIDE.md` - GPU setup instructions

### Dataset
- `Dataset/Zenedo.csv` - Training data (~22K samples)

## Transfer Instructions

### Option 1: USB Drive / Network Share
1. Copy entire `migration_package` folder to USB drive
2. Transfer to target machine
3. Continue with "Setup on New Machine" below

### Option 2: Cloud Storage (Google Drive, OneDrive, etc.)
1. Compress migration_package folder:
   - Windows: Right-click → Send to → Compressed folder
   - Linux/Mac: `tar -czf migration_package.tar.gz migration_package/`
2. Upload to cloud storage
3. Download on target machine
4. Extract and continue with setup

### Option 3: Git Repository
```bash
# On current machine
cd migration_package
git init
git add .
git commit -m "CNN training package"
git remote add origin <your-repo-url>
git push -u origin main

# On new machine
git clone <your-repo-url>
cd <repo-name>
```

## Setup on New Machine

### Requirements
- Python 3.8 or higher
- NVIDIA GPU (for GPU acceleration)
- Updated NVIDIA drivers
- 10+ GB free disk space
- 8+ GB RAM

### Quick Setup (5 minutes)

```bash
# Navigate to package directory
cd migration_package

# Run automated setup
python setup_gpu_environment.py
```

This will:
- Create virtual environment
- Install all dependencies (including TensorFlow with GPU support)
- Verify GPU detection
- Check dataset

### Manual Setup

If automated setup fails:

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/Mac)
source .venv/bin/activate

# Install dependencies
pip install -r requirements_cnn.txt

# Or install manually
pip install tensorflow[and-cuda] numpy pandas scikit-learn matplotlib seaborn keras
```

### Verify GPU Setup

```bash
python -c "import tensorflow as tf; print('GPU:', tf.config.list_physical_devices('GPU'))"
```

**Expected with GPU:**
```
GPU: [PhysicalDevice(name='/physical_device:GPU:0', device_type='GPU')]
```

### Check Readiness

```bash
python check_ready.py
```

Should show all checks passed.

## Training

### Start Training

```bash
python train_cnn_zenodo.py
```

### Expected Performance

**With GPU:**
- Training time: 10-15 minutes
- Memory usage: ~4-6 GB GPU RAM
- Model accuracy: 95-98%

**Without GPU (CPU):**
- Training time: 30-60 minutes  
- Memory usage: ~4-8 GB RAM
- Model accuracy: 95-98% (same)

### Monitor Training

Watch for:
- Validation accuracy increasing
- Validation loss decreasing
- Early stopping trigger (when no improvement)

Output will show progress:
```
Epoch 1/50
272/272 [======] - 45s - loss: 0.3245 - accuracy: 0.8876 - val_accuracy: 0.9234
Epoch 2/50
...
```

### Training Complete

After training finishes, you'll find:
- `models/cnn_zenodo_YYYYMMDD_HHMMSS.keras` - Trained model
- `models/cnn_model_metadata.json` - Performance metrics
- `models/training_history.png` - Training curves

## Bringing Model Back

### Option 1: Copy Model Files

Copy these files back to original machine:
- `models/cnn_zenodo_*.keras` (trained model)
- `models/cnn_model_metadata.json` (metrics)
- `models/training_history.png` (plots)

### Option 2: Cloud Sync

Upload trained model to cloud storage, download on original machine.

### Option 3: Git

```bash
# On GPU machine (after training)
git add models/
git commit -m "Trained CNN model"
git push

# On original machine
git pull
```

## Using Trained Model

Place model file in original project:
```
K/
├── models/
│   └── cnn_zenodo_20260205_123456.keras
└── Iteration_1/backend/
    ├── ml_model_cnn.py
    └── main.py
```

Enable in backend:
```bash
$env:USE_CNN_MODEL="true"
$env:CNN_MODEL_PATH="C:/Users/User/OneDrive/Test/K/models/cnn_zenodo.keras"

cd Iteration_1/backend
python main.py
```

## Troubleshooting

### "No GPU detected"
- Check: `nvidia-smi` shows GPU
- Update NVIDIA drivers
- Reinstall TensorFlow: `pip install tensorflow[and-cuda]`

### "Out of memory"
Edit `train_cnn_zenodo.py`:
```python
batch_size = 32  # Reduce from 64
max_bytes = 50000  # Reduce from 100000
```

### "Dataset not found"
Make sure `Dataset/Zenedo.csv` is in the package directory.

## Support

See full documentation in:
- `README_CNN.md` - Complete guide
- `QUICKSTART_CNN.md` - Quick reference
- `INSTALL_GPU_GUIDE.md` - GPU setup help

---

**Package Contents:** 7 files
**Package Size:** Check folder properties
**Ready to transfer and train!** 🚀
