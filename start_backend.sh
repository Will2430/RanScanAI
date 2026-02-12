# SecureGuard Quick Start Script (macOS/Linux)
#!/bin/bash

echo "============================================================"
echo "  SecureGuard - Privacy-First Malware Detection Backend"
echo "============================================================"
echo ""

# Check Python
echo "[1/3] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.8+ from python.org"
    exit 1
fi
python3 --version
echo ""

# Check dependencies
echo "[2/3] Checking dependencies..."
if ! python3 -c "import fastapi" &> /dev/null; then
    echo "Installing dependencies..."
    pip3 install -r backend/requirements.txt
else
    echo "Dependencies OK"
fi
echo ""

# Check model
echo "[3/3] Checking model files..."
if [ ! -f "malware_detector_zenodo_v1.pkl" ]; then
    echo "WARNING: Model file not found!"
    echo "Please run: python3 train_zenodo_model.py"
    exit 1
fi
echo "Model file found"
echo ""

echo "============================================================"
echo "  Starting SecureGuard Backend on http://localhost:8000"
echo "============================================================"
echo ""
echo "Keep this terminal open while using the extension!"
echo "Press Ctrl+C to stop the server"
echo ""

# Start server
cd backend
python3 main.py
