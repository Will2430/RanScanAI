"""
Migration Package Creator for CNN Training
Creates a portable package with all necessary files for GPU training
"""

import shutil
from pathlib import Path
import json
from datetime import datetime

print("="*80)
print("SecureGuard CNN - Migration Package Creator")
print("="*80)

# Define what to migrate
MIGRATION_PACKAGE = {
    'training_scripts': [
        'train_cnn_zenodo.py',
        'check_ready.py',
    ],
    'model_code': [
        'Iteration_1\\backend\\ml_model_cnn.py',
    ],
    'config_files': [
        'requirements_cnn.txt',
    ],
    'documentation': [
        'README_CNN.md',
        'QUICKSTART_CNN.md',
        'INSTALL_GPU_GUIDE.md',
    ],
    'dataset': [
        'Dataset\\Zenedo.csv',
    ]
}

# Create migration package directory
package_dir = Path("migration_package")
package_dir.mkdir(exist_ok=True)

print(f"\nCreating migration package in: {package_dir.absolute()}\n")

files_copied = 0
files_missing = []

# Copy files
for category, files in MIGRATION_PACKAGE.items():
    print(f"[{category.upper()}]")
    category_dir = package_dir / category
    category_dir.mkdir(exist_ok=True)
    
    for file_path in files:
        source = Path(file_path)
        
        if source.exists():
            # Preserve directory structure for nested files
            if '/' in file_path:
                dest = package_dir / file_path
                dest.parent.mkdir(parents=True, exist_ok=True)
            else:
                dest = category_dir / source.name
            
            shutil.copy2(source, dest)
            size = source.stat().st_size / 1024  # KB
            print(f"  ✓ {file_path} ({size:.1f} KB)")
            files_copied += 1
        else:
            print(f"  ✗ {file_path} (NOT FOUND)")
            files_missing.append(file_path)

# Create setup script for new environment
setup_script = """#!/usr/bin/env python3
\"\"\"
Setup Script for GPU Training Environment
Run this on the new machine after transferring files
\"\"\"

import subprocess
import sys
from pathlib import Path

print("="*80)
print("SecureGuard CNN - GPU Environment Setup")
print("="*80)

# Check Python version
print(f"\\nPython version: {sys.version}")
if sys.version_info < (3, 8):
    print("❌ Python 3.8+ required")
    sys.exit(1)
print("✓ Python version OK")

# Create virtual environment
print("\\n[1] Creating virtual environment...")
subprocess.run([sys.executable, "-m", "venv", ".venv"], check=True)
print("✓ Virtual environment created")

# Determine pip path
if sys.platform == "win32":
    pip_path = Path(".venv/Scripts/pip.exe")
    python_path = Path(".venv/Scripts/python.exe")
else:
    pip_path = Path(".venv/bin/pip")
    python_path = Path(".venv/bin/python")

# Upgrade pip
print("\\n[2] Upgrading pip...")
subprocess.run([str(python_path), "-m", "pip", "install", "--upgrade", "pip"], check=True)
print("✓ Pip upgraded")

# Install dependencies
print("\\n[3] Installing dependencies (this may take 5-10 minutes)...")
requirements_file = Path("requirements_cnn.txt")
if requirements_file.exists():
    subprocess.run([str(pip_path), "install", "-r", str(requirements_file)], check=True)
else:
    # Fallback - install core packages
    packages = [
        "tensorflow[and-cuda]",  # GPU support
        "numpy",
        "pandas",
        "scikit-learn",
        "matplotlib",
        "seaborn",
        "keras"
    ]
    for pkg in packages:
        print(f"  Installing {pkg}...")
        subprocess.run([str(pip_path), "install", pkg], check=True)

print("✓ Dependencies installed")

# Verify TensorFlow GPU
print("\\n[4] Verifying GPU support...")
result = subprocess.run(
    [str(python_path), "-c", 
     "import tensorflow as tf; print('TensorFlow:', tf.__version__); "
     "gpus = tf.config.list_physical_devices('GPU'); "
     "print('GPU Available:', len(gpus) > 0); "
     "print('GPU Devices:', gpus)"],
    capture_output=True,
    text=True
)
print(result.stdout)
if "GPU Available: True" in result.stdout:
    print("✅ GPU DETECTED! Training will be fast (~10-15 min)")
else:
    print("⚠️  No GPU detected - will use CPU (slower, ~30-60 min)")

# Check dataset
print("\\n[5] Checking dataset...")
dataset_path = Path("Dataset/Zenedo.csv")
if dataset_path.exists():
    import pandas as pd
    df = pd.read_csv(dataset_path)
    print(f"✓ Dataset found: {len(df):,} samples")
else:
    print("❌ Dataset not found!")
    print("   Make sure Dataset/Zenedo.csv is in the package")

print("\\n" + "="*80)
print("✅ SETUP COMPLETE!")
print("="*80)

print("\\nNext steps:")
print("  1. Activate environment:")
if sys.platform == "win32":
    print("     .venv\\\\Scripts\\\\activate")
else:
    print("     source .venv/bin/activate")
print("  2. Verify setup:")
print("     python check_ready.py")
print("  3. Start training:")
print("     python train_cnn_zenodo.py")
print()
"""

setup_script_path = package_dir / "setup_gpu_environment.py"
with open(setup_script_path, 'w', encoding='utf-8') as f:
    f.write(setup_script)
print(f"\n[SETUP SCRIPT]")
print(f"  ✓ setup_gpu_environment.py")
files_copied += 1

# Create README for migration
migration_readme = f"""# SecureGuard CNN - Migration Package

**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

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
.venv\\Scripts\\activate

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

**Package Contents:** {files_copied} files
**Package Size:** Check folder properties
**Ready to transfer and train!** 🚀
"""

readme_path = package_dir / "README_MIGRATION.md"
with open(readme_path, 'w', encoding='utf-8') as f:
    f.write(migration_readme)
print(f"  ✓ README_MIGRATION.md")

# Create manifest
manifest = {
    'created': datetime.now().isoformat(),
    'files_included': files_copied,
    'files_missing': files_missing,
    'package_contents': MIGRATION_PACKAGE
}

manifest_path = package_dir / "manifest.json"
with open(manifest_path, 'w') as f:
    json.dump(manifest, f, indent=2)
print(f"  ✓ manifest.json")

# Summary
print("\n" + "="*80)
print("PACKAGE CREATION COMPLETE")
print("="*80)

total_size = sum(f.stat().st_size for f in package_dir.rglob('*') if f.is_file())
total_size_mb = total_size / (1024 * 1024)

print(f"\n📦 Package Details:")
print(f"   Location: {package_dir.absolute()}")
print(f"   Files: {files_copied}")
print(f"   Size: {total_size_mb:.1f} MB")

if files_missing:
    print(f"\n⚠️  Missing files ({len(files_missing)}):")
    for f in files_missing:
        print(f"   - {f}")

print(f"\n✅ Next Steps:")
print(f"   1. Transfer 'migration_package' folder to GPU machine")
print(f"   2. On GPU machine, run: python setup_gpu_environment.py")
print(f"   3. Train model: python train_cnn_zenodo.py")
print(f"   4. Copy trained model back from models/ folder")

print(f"\n💡 Transfer Options:")
print(f"   • USB drive: Copy entire folder")
print(f"   • Cloud: Zip folder, upload to Drive/OneDrive")
print(f"   • Network: Use shared folder or SCP")
print(f"   • Git: Initialize repo and push")

print(f"\n📖 See migration_package/README_MIGRATION.md for detailed instructions")
print()
