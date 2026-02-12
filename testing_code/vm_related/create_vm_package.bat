@echo off
REM ================================================
REM Create VM Testing Package
REM ================================================
REM Bundles all files needed to run behavioral
REM monitoring test in a VM
REM ================================================

echo.
echo ============================================
echo Creating VM Testing Package
echo ============================================
echo.

set VM_PACKAGE=VM_Testing_Package
set TIMESTAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set PACKAGE_NAME=%VM_PACKAGE%_%TIMESTAMP%

REM Create package directory
if exist "%PACKAGE_NAME%" rmdir /s /q "%PACKAGE_NAME%"
mkdir "%PACKAGE_NAME%"

echo Creating package directory: %PACKAGE_NAME%
echo.

REM Copy behavioral monitor
echo [1/7] Copying behavioral monitor...
copy "vm_behavioral_monitor.py" "%PACKAGE_NAME%\" >nul
if errorlevel 1 (
    echo ERROR: Failed to copy vm_behavioral_monitor.py
    pause
    exit /b 1
)

REM Copy ransomware simulator
echo [2/7] Copying ransomware simulator...
copy "ransomware_simulator.py" "%PACKAGE_NAME%\" >nul
if errorlevel 1 (
    echo ERROR: Failed to copy ransomware_simulator.py
    pause
    exit /b 1
)

REM Copy setup script
echo [3/7] Copying test environment setup...
copy "setup_test_environment.py" "%PACKAGE_NAME%\" >nul
if errorlevel 1 (
    echo WARNING: setup_test_environment.py not found
)

REM Copy converter script
echo [4/7] Copying VM data converter...
copy "host_analyze_vm_data.py" "%PACKAGE_NAME%\" >nul
if errorlevel 1 (
    echo WARNING: host_analyze_vm_data.py not found (optional)
)

REM Copy .exe if it exists
echo [5/7] Copying compiled executable...
if exist "dist\RansomwareSimulator.exe" (
    if not exist "%PACKAGE_NAME%\dist" mkdir "%PACKAGE_NAME%\dist"
    copy "dist\RansomwareSimulator.exe" "%PACKAGE_NAME%\dist\" >nul
    echo   Found: RansomwareSimulator.exe
) else (
    echo   Not found: dist\RansomwareSimulator.exe (will need to run .py version)
)

REM Create requirements.txt
echo [6/7] Creating requirements.txt...
(
echo psutil
echo cryptography
echo pywin32
) > "%PACKAGE_NAME%\requirements.txt"

REM Create VM setup instructions
echo [7/7] Creating VM_SETUP_INSTRUCTIONS.txt...
(
echo ================================================================
echo VM BEHAVIORAL MONITORING SETUP
echo ================================================================
echo.
echo OVERVIEW:
echo This package contains everything needed to run behavioral
echo monitoring tests on ransomware simulation in a VM.
echo.
echo ================================================================
echo STEP 1: VM SETUP
echo ================================================================
echo 1. Create a Windows VM ^(VirtualBox/VMware/Hyper-V^)
echo    - OS: Windows 10/11
echo    - RAM: 4GB minimum
echo    - Disk: 50GB
echo    - Snapshot: Take clean snapshot BEFORE testing
echo.
echo 2. Install Python 3.10+ in VM:
echo    Download: https://www.python.org/downloads/
echo    During install: Check "Add Python to PATH"
echo.
echo 3. Transfer this entire folder to VM:
echo    - USB drive
echo    - Shared folder
echo    - Network share
echo.
echo ================================================================
echo STEP 2: INSTALL DEPENDENCIES
echo ================================================================
echo Open PowerShell in this folder and run:
echo.
echo    pip install -r requirements.txt
echo.
echo This installs:
echo - psutil ^(process monitoring^)
echo - cryptography ^(encryption simulation^)
echo - pywin32 ^(Windows API access^)
echo.
echo ================================================================
echo STEP 3: RUN BEHAVIORAL MONITORING
echo ================================================================
echo.
echo Option A: Monitor Python Script
echo --------------------------------
echo 1. Create test folder:
echo    python setup_test_environment.py
echo.
echo 2. Run behavioral monitor:
echo    python vm_behavioral_monitor.py ransomware_simulator.py C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER
echo.
echo.
echo Option B: Monitor Compiled .exe
echo --------------------------------
echo 1. Create test folder:
echo    python setup_test_environment.py
echo.
echo 2. Run behavioral monitor on exe:
echo    python vm_behavioral_monitor.py dist\RansomwareSimulator.exe C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER
echo.
echo.
echo ================================================================
echo STEP 4: COLLECT RESULTS
echo ================================================================
echo After execution completes, you'll find:
echo.
echo   behavioral_data.json  - Runtime behavioral data
echo.
echo Copy this file back to your host machine for analysis.
echo.
echo ================================================================
echo STEP 5: CLEANUP
echo ================================================================
echo 1. Revert VM to clean snapshot
echo    ^(Important: Don't keep ransomware artifacts^)
echo.
echo 2. Delete test folder:
echo    rmdir /s /q C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER
echo.
echo 3. Delete registry entries:
echo    reg delete "HKCU\Software\TestRansomware" /f
echo    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestRansomware /f
echo.
echo ================================================================
echo BEHAVIORAL DATA CAPTURED:
echo ================================================================
echo - Registry writes: 200+ operations
echo - Network activity: 50+ DNS queries, 15+ connections
echo - Process spawning: 10+ child processes
echo - DLL loading: 7+ system libraries
echo - File operations: Created, deleted, encrypted
echo.
echo ================================================================
echo EXPECTED RESULTS:
echo ================================================================
echo Registry:
echo   Writes: 200+  ^(massive tracking/persistence^)
echo   Deletes: 0-5
echo.
echo Network:
echo   DNS queries: 50+  ^(C2 server lookups^)
echo   Connections: 15+  ^(C2 connection attempts^)
echo.
echo Processes:
echo   Created: 10+  ^(cmd.exe, powershell, wmic^)
echo.
echo Files:
echo   Created: 1-10  ^(.locked files + ransom note^)
echo   Deleted: 1-10  ^(original files^)
echo   Encrypted: 1-10
echo.
echo DLLs:
echo   Loaded: 7+  ^(bcrypt.dll, advapi32.dll, etc.^)
echo.
echo ================================================================
echo SAFETY NOTES:
echo ================================================================
echo - This is a SIMULATION - safe for testing
echo - Only affects C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER
echo - Registry writes are HKCU only ^(user-level, removable^)
echo - Network attempts will fail ^(fake domains^)
echo - Run in VM only for isolation
echo - Take snapshot before testing
echo - Revert snapshot after testing
echo.
echo ================================================================
echo TROUBLESHOOTING:
echo ================================================================
echo "Module not found" errors:
echo   pip install psutil cryptography pywin32
echo.
echo "Test folder not found":
echo   python setup_test_environment.py
echo.
echo "Permission denied":
echo   Run PowerShell as Administrator
echo.
echo behavioral_data.json not created:
echo   Check for errors in monitor output
echo   Verify target exe/script ran successfully
echo.
echo ================================================================
) > "%PACKAGE_NAME%\VM_SETUP_INSTRUCTIONS.txt"

REM Create quick start script for VM
(
echo @echo off
echo echo ============================================
echo echo Quick Start: Behavioral Monitoring Test
echo echo ============================================
echo echo.
echo echo This will:
echo echo 1. Create test folder with dummy files
echo echo 2. Run ransomware simulator with behavioral monitoring
echo echo 3. Generate behavioral_data.json
echo echo.
echo pause
echo.
echo echo [1/2] Creating test environment...
echo python setup_test_environment.py
echo.
echo echo [2/2] Running behavioral monitor...
echo python vm_behavioral_monitor.py ransomware_simulator.py C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER
echo.
echo echo ============================================
echo echo Done! Check behavioral_data.json
echo echo ============================================
echo pause
) > "%PACKAGE_NAME%\QUICK_START.bat"

REM Copy cleanup script
echo [7.5/7] Copying cleanup script...
copy "cleanup_vm.bat" "%PACKAGE_NAME%\" >nul
if errorlevel 1 (
    echo WARNING: cleanup_vm.bat not found (optional)
)

REM Create ZIP if possible
echo.
echo ============================================
echo Package created: %PACKAGE_NAME%
echo ============================================
echo.
echo Contents:
dir /b "%PACKAGE_NAME%"
echo.
echo Transfer this folder to your VM to run tests.
echo See VM_SETUP_INSTRUCTIONS.txt for full guide.
echo.
pause
