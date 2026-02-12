"""
Pre-Training Checklist - Verify everything is ready
Run this before training the CNN model
"""

import sys
from pathlib import Path

print("="*80)
print("SecureGuard CNN - Pre-Training Checklist")
print("="*80)

checks_passed = 0
checks_total = 0

# Check 1: Python version
print("\n[1] Checking Python version...")
checks_total += 1
if sys.version_info >= (3, 8):
    print(f"  ✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    checks_passed += 1
else:
    print(f"  ❌ Python {sys.version_info.major}.{sys.version_info.minor} (need 3.8+)")

# Check 2: TensorFlow
print("\n[2] Checking TensorFlow...")
checks_total += 1
try:
    import tensorflow as tf
    print(f"  ✅ TensorFlow {tf.__version__} installed")
    
    # Check if GPU available
    gpus = tf.config.list_physical_devices('GPU')
    if gpus:
        print(f"  🚀 GPU detected: {len(gpus)} device(s)")
        print("     Training will be ~10x faster!")
    else:
        print("  💻 CPU only (no GPU)")
        print("     Training will take 30-60 minutes")
    
    checks_passed += 1
except ImportError:
    print("  ❌ TensorFlow not installed")
    print("     Install with: pip install tensorflow")

# Check 3: Other dependencies
print("\n[3] Checking other dependencies...")
checks_total += 1
missing = []
required = {
    'numpy': 'numpy',
    'pandas': 'pandas', 
    'sklearn': 'scikit-learn',
    'matplotlib': 'matplotlib',
    'seaborn': 'seaborn'
}

for module, package in required.items():
    try:
        __import__(module)
    except ImportError:
        missing.append(package)

if not missing:
    print(f"  ✅ All dependencies installed")
    checks_passed += 1
else:
    print(f"  ❌ Missing: {', '.join(missing)}")
    print(f"     Install with: pip install {' '.join(missing)}")

# Check 4: Dataset
print("\n[4] Checking Zenodo dataset...")
checks_total += 1
dataset_path = Path("Dataset/Zenedo.csv")

if dataset_path.exists():
    try:
        import pandas as pd
        df = pd.read_csv(dataset_path)
        n_samples = len(df)
        n_features = len(df.columns)
        
        print(f"  ✅ Dataset found: {dataset_path}")
        print(f"     Samples: {n_samples:,}")
        print(f"     Features: {n_features}")
        
        if n_samples >= 10000:
            print(f"     Size assessment: {'EXCELLENT' if n_samples > 20000 else 'GOOD'} for CNN training")
            checks_passed += 1
        else:
            print(f"     ⚠️ Warning: <10K samples may not be enough")
            
    except Exception as e:
        print(f"  ❌ Error reading dataset: {e}")
else:
    print(f"  ❌ Dataset not found at {dataset_path}")
    print(f"     Check the path in train_cnn_zenodo.py")

# Check 5: Output directory
print("\n[5] Checking output directory...")
checks_total += 1
output_dir = Path("models")

if output_dir.exists():
    print(f"  ✅ Output directory exists: {output_dir}")
    checks_passed += 1
else:
    print(f"  ⚠️ Creating output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"  ✅ Created")
    checks_passed += 1

# Check 6: Disk space
print("\n[6] Checking disk space...")
checks_total += 1
try:
    import shutil
    total, used, free = shutil.disk_usage(Path.cwd())
    free_gb = free / (1024**3)
    
    if free_gb >= 5:
        print(f"  ✅ Free space: {free_gb:.1f} GB")
        checks_passed += 1
    else:
        print(f"  ⚠️ Low disk space: {free_gb:.1f} GB")
        print(f"     Recommended: 5+ GB free")
except:
    print(f"  ⚠️ Could not check disk space")

# Check 7: Memory
print("\n[7] Checking available memory...")
checks_total += 1
try:
    import psutil
    mem = psutil.virtual_memory()
    available_gb = mem.available / (1024**3)
    
    if available_gb >= 4:
        print(f"  ✅ Available RAM: {available_gb:.1f} GB")
        checks_passed += 1
    else:
        print(f"  ⚠️ Low memory: {available_gb:.1f} GB")
        print(f"     Recommended: 4+ GB available")
        print(f"     Tip: Close other applications or reduce batch_size")
except ImportError:
    print(f"  ⚠️ psutil not installed (optional check)")
    print(f"     Install with: pip install psutil")

# Summary
print("\n" + "="*80)
print("CHECKLIST SUMMARY")
print("="*80)

print(f"\nPassed: {checks_passed}/{checks_total} checks")

if checks_passed >= checks_total - 1:
    print("\n✅ READY TO TRAIN!")
    print("\nNext steps:")
    print("  1. Run: python train_cnn_zenodo.py")
    print("  2. Wait ~30-60 minutes (CPU) or ~10 minutes (GPU)")
    print("  3. Check models/ directory for trained model")
    print("\nExpected output:")
    print("  • Accuracy: 95-98%")
    print("  • AUC-ROC: >0.97")
    print("  • False Positive Rate: <5%")
    
elif checks_passed >= 4:
    print("\n⚠️ ALMOST READY")
    print("\nMissing some optional components, but training should work.")
    print("Install missing packages for best results:")
    print("  pip install -r requirements_cnn.txt")
    
else:
    print("\n❌ NOT READY")
    print("\nCritical components missing. Please install:")
    print("  pip install tensorflow numpy pandas scikit-learn matplotlib seaborn")

print("\n" + "="*80)

# Detailed recommendations
if 'tensorflow' in str(missing):
    print("\n💡 TIP: TensorFlow is required")
    print("   Install: pip install tensorflow")
    print("   This is the most important dependency!")

if checks_passed >= checks_total - 1:
    print("\n💡 TRAINING TIPS:")
    print("   • Training takes 30-60 min on CPU, 10-15 min on GPU")
    print("   • Watch for validation accuracy plateau (early stopping)")
    print("   • Model saved automatically to models/ directory")
    print("   • Training plots generated in models/training_history.png")
    print("   • You can stop training anytime (Ctrl+C) - best model is saved")

print()
