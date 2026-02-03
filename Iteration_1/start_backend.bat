@echo off
REM SecureGuard Startup Script
REM Starts the FastAPI backend service

echo ============================================================
echo   SecureGuard - Privacy-First Malware Detection Backend
echo ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo [1/3] Checking Python installation...
python --version
echo.

REM Check if dependencies are installed
echo [2/3] Checking dependencies...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r backend\requirements.txt
) else (
    echo Dependencies OK
)
echo.

REM Check if model exists
echo [3/3] Checking model files...
if not exist "malware_detector_zenodo_v1.pkl" (
    echo WARNING: Model file not found!
    echo Please run: python train_zenodo_model.py
    echo.
    pause
    exit /b 1
)
echo Model file found
echo.

echo ============================================================
echo   Starting SecureGuard Backend on http://localhost:8000
echo ============================================================
echo.
echo Keep this window open while using the extension!
echo Press Ctrl+C to stop the server
echo.

REM Start the server
cd backend
python main.py

pause
