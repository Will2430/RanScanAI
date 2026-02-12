@echo off
REM Start CNN Model Service in Python 3.10 Conda Environment
REM This service must run BEFORE starting main.py

echo ====================================
echo SecureGuard CNN Model Service
echo ====================================
echo.
echo Environment: Python 3.10 (Conda)
echo Port: 8001
echo.

REM Activate conda environment (adjust name if different)
call conda activate base

REM Navigate to migration_package directory
cd /d "%~dp0"

echo Starting model service...
echo.
python model_service.py

pause
