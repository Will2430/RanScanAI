@echo off
REM Build Ransomware Simulator as Standalone EXE
REM =============================================

echo.
echo ============================================
echo Building Ransomware Simulator EXE
echo ============================================
echo.

REM Use the virtual environment Python
set PYTHON_EXE=C:\Users\willi\OneDrive\Test\K\.venv\Scripts\python.exe

REM Check if pyinstaller is installed
%PYTHON_EXE% -c "import PyInstaller" 2>nul
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    %PYTHON_EXE% -m pip install pyinstaller
)

echo.
echo Cleaning old build files...
echo.

REM Check if the exe is still running
tasklist /FI "IMAGENAME eq RansomwareSimulator.exe" 2>NUL | find /I /N "RansomwareSimulator.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo WARNING: RansomwareSimulator.exe is still running!
    echo Please close it before building.
    echo.
    echo Attempting to kill the process...
    taskkill /F /IM RansomwareSimulator.exe 2>nul
    timeout /t 2 >nul
)

REM Manually delete old build/dist folders (PyInstaller --clean can fail with locked files)
if exist "build" (
    echo Removing build folder...
    rmdir /s /q build 2>nul
    if exist "build" (
        echo Warning: Could not fully remove build folder - trying to continue...
    )
)

if exist "dist" (
    echo Removing dist folder...
    rmdir /s /q dist 2>nul
    if exist "dist" (
        echo Warning: Could not fully remove dist folder - trying to continue...
    )
)

REM Remove old spec file
if exist "RansomwareSimulator.spec" (
    echo Removing old spec file...
    del /f /q RansomwareSimulator.spec 2>nul
    timeout /t 1 >nul
)

REM Wait for OneDrive sync to release file locks
echo Waiting for file locks to release...
timeout /t 2 >nul

echo.
echo Building executable...
echo.

REM Build the EXE with PyInstaller using absolute path to avoid OneDrive issues
set SCRIPT_PATH=%CD%\ransomware_simulator.py
%PYTHON_EXE% -m PyInstaller --onefile ^
    --name RansomwareSimulator ^
    --clean ^
    "%SCRIPT_PATH%"

if errorlevel 1 (
    echo.
    echo ============================================
    echo Build FAILED!
    echo ============================================
    echo Check error messages above
    pause
    exit /b 1
)

if not exist "dist\RansomwareSimulator.exe" (
    echo.
    echo ============================================
    echo Build FAILED - EXE not found!
    echo ============================================
    pause
    exit /b 1
)

echo.
echo ============================================
echo Build Complete!
echo ============================================
echo.
echo Executable location: dist\RansomwareSimulator.exe
echo.
for %%A in (dist\RansomwareSimulator.exe) do (
    echo File size: %%~zA bytes
)
echo.
echo Next steps:
echo 1. Test the EXE: dist\RansomwareSimulator.exe
echo 2. Extract PE features from the EXE
echo 3. Run through your ML model
echo.

pause
