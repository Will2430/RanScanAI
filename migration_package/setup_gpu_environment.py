#!/usr/bin/env python3
"""
Setup Script for GPU Training Environment
Run this on the new machine after transferring files
"""

import subprocess
import sys
from pathlib import Path

print("="*80)
print("SecureGuard CNN - GPU Environment Setup")
print("="*80)

# Check Python version
print(f"\nPython version: {sys.version}")
if sys.version_info < (3, 8):
    print("❌ Python 3.8+ required")
    sys.exit(1)
print("✓ Python version OK")

# Create virtual environment
print("\n[1] Creating virtual environment...")
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
print("\n[2] Upgrading pip...")
subprocess.run([str(python_path), "-m", "pip", "install", "--upgrade", "pip"], check=True)
print("✓ Pip upgraded")

# Install dependencies
print("\n[3] Installing dependencies (this may take 5-10 minutes)...")
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
print("\n[4] Verifying GPU support...")
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
print("\n[5] Checking dataset...")
dataset_path = Path("Dataset/Zenedo.csv")
if dataset_path.exists():
    import pandas as pd
    df = pd.read_csv(dataset_path)
    print(f"✓ Dataset found: {len(df):,} samples")
else:
    print("❌ Dataset not found!")
    print("   Make sure Dataset/Zenedo.csv is in the package")

print("\n" + "="*80)
print("✅ SETUP COMPLETE!")
print("="*80)

print("\nNext steps:")
print("  1. Activate environment:")
if sys.platform == "win32":
    print("     .venv\\Scripts\\activate")
else:
    print("     source .venv/bin/activate")
print("  2. Verify setup:")
print("     python check_ready.py")
print("  3. Start training:")
print("     python train_cnn_zenodo.py")
print()
