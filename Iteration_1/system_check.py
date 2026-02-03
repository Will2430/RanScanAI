"""
SecureGuard System Check
Verifies all components are correctly installed
"""

import sys
from pathlib import Path
import importlib.util

def check_file(path, description):
    """Check if a file exists"""
    if Path(path).exists():
        print(f"✓ {description}")
        return True
    else:
        print(f"✗ {description} - MISSING: {path}")
        return False

def check_package(package_name):
    """Check if a Python package is installed"""
    spec = importlib.util.find_spec(package_name)
    if spec is not None:
        print(f"✓ {package_name} installed")
        return True
    else:
        print(f"✗ {package_name} NOT installed")
        return False

def main():
    print("="*70)
    print("SecureGuard System Check")
    print("="*70)
    print()
    
    all_good = True
    
    # Check browser extension files
    print("1. Checking Browser Extension Files...")
    print("-" * 70)
    ext_files = [
        ("browser-extension/manifest.json", "Extension manifest"),
        ("browser-extension/popup.html", "Dashboard UI"),
        ("browser-extension/popup.js", "Frontend logic"),
        ("browser-extension/background.js", "Service worker"),
        ("browser-extension/styles.css", "Styles"),
    ]
    
    for path, desc in ext_files:
        if not check_file(path, desc):
            all_good = False
    print()
    
    # Check backend files
    print("2. Checking Backend Files...")
    print("-" * 70)
    backend_files = [
        ("backend/main.py", "FastAPI server"),
        ("backend/ml_model.py", "ML model integration"),
        ("backend/vt_integration.py", "VirusTotal integration"),
        ("backend/requirements.txt", "Dependencies list"),
    ]
    
    for path, desc in backend_files:
        if not check_file(path, desc):
            all_good = False
    print()
    
    # Check model files
    print("3. Checking ML Model Files...")
    print("-" * 70)
    model_files = [
        ("malware_detector_zenodo_v1.pkl", "Trained ML model"),
        ("zenodo_model_metadata.json", "Model metadata"),
    ]
    
    for path, desc in model_files:
        if not check_file(path, desc):
            all_good = False
            print("   → Run: python train_zenodo_model.py")
    print()
    
    # Check documentation
    print("4. Checking Documentation...")
    print("-" * 70)
    doc_files = [
        ("README_SECUREGUARD.md", "Full documentation"),
        ("QUICKSTART.md", "Quick start guide"),
        ("PROJECT_SUMMARY.md", "Project summary"),
    ]
    
    for path, desc in doc_files:
        if not check_file(path, desc):
            all_good = False
    print()
    
    # Check Python packages
    print("5. Checking Python Dependencies...")
    print("-" * 70)
    required_packages = [
        "fastapi",
        "uvicorn",
        "pandas",
        "sklearn",
        "joblib",
        "requests",
    ]
    
    for package in required_packages:
        if not check_package(package):
            all_good = False
            print(f"   → Install: pip install {package}")
    print()
    
    # Check Python version
    print("6. Checking Python Version...")
    print("-" * 70)
    version = sys.version_info
    print(f"Python {version.major}.{version.minor}.{version.micro}")
    if version.major >= 3 and version.minor >= 8:
        print("✓ Python version OK (3.8+)")
    else:
        print("✗ Python version too old (need 3.8+)")
        all_good = False
    print()
    
    # Check startup scripts
    print("7. Checking Startup Scripts...")
    print("-" * 70)
    startup_files = [
        ("start_backend.bat", "Windows startup script"),
        ("start_backend.sh", "macOS/Linux startup script"),
        ("demo_secureguard.py", "Demo script"),
    ]
    
    for path, desc in startup_files:
        if not check_file(path, desc):
            all_good = False
    print()
    
    # Summary
    print("="*70)
    if all_good:
        print("✓✓✓ ALL CHECKS PASSED! ✓✓✓")
        print()
        print("Your SecureGuard system is ready to run!")
        print()
        print("Next steps:")
        print("  1. Start backend: start_backend.bat")
        print("  2. Install extension: Load browser-extension/ in Chrome")
        print("  3. Run demo: python demo_secureguard.py")
    else:
        print("✗✗✗ SOME CHECKS FAILED ✗✗✗")
        print()
        print("Please fix the issues above before proceeding.")
        print()
        print("Common fixes:")
        print("  • Missing packages: pip install -r backend/requirements.txt")
        print("  • Missing model: python train_zenodo_model.py")
    print("="*70)

if __name__ == "__main__":
    main()
