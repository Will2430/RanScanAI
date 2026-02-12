@echo off
REM Quick environment activation script for SecureGuard project

echo.
echo ================================================
echo SecureGuard Malware Detection - Environment Setup
echo ================================================
echo.
echo Select environment to activate:
echo.
echo [1] Python 3.14 (Main Application)
echo [2] Conda Base (TensorFlow)
echo [3] Conda tensorflow-gpu (if created)
echo [4] Conda torch-gpu
echo [5] Exit
echo.

set /p choice="Enter choice (1-5): "

if "%choice%"=="1" (
    echo.
    echo Activating Python 3.14...
    cmd /k "C:\Python314\python.exe -c "import sys; print(f'Python {sys.version}')""
) else if "%choice%"=="2" (
    echo.
    echo Activating Conda Base...
    cmd /k "conda activate base && python --version"
) else if "%choice%"=="3" (
    echo.
    echo Activating Conda tensorflow-gpu...
    cmd /k "conda activate tensorflow-gpu && python --version"
) else if "%choice%"=="4" (
    echo.
    echo Activating Conda torch-gpu...
    cmd /k "conda activate torch-gpu && python --version"
) else if "%choice%"=="5" (
    echo.
    echo Exiting...
    exit
) else (
    echo.
    echo Invalid choice!
    pause
    goto :eof
)
