@echo off
REM ================================================
REM VM Cleanup Script
REM ================================================
REM Removes all ransomware simulation artifacts
REM Run this AFTER collecting behavioral_data.json
REM ================================================

echo ============================================
echo VM Cleanup - Remove Ransomware Artifacts
echo ============================================
echo.
echo This will remove:
echo - Test folder and all files
echo - Registry entries (200+ values)
echo - Startup persistence entries
echo.
echo Press Ctrl+C to cancel, or
pause

echo.
echo [1/3] Deleting test folder...
if exist "C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER" (
    rmdir /s /q "C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER" 2>nul
    if exist "C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER" (
        echo   ERROR: Could not delete folder
    ) else (
        echo   OK: Test folder deleted
    )
) else (
    echo   OK: Test folder doesn't exist
)

echo.
echo [2/3] Deleting registry entries...
reg delete "HKCU\Software\TestRansomware" /f 2>nul
if errorlevel 1 (
    echo   OK: TestRansomware key doesn't exist
) else (
    echo   OK: TestRansomware registry key deleted (200+ values removed)
)

echo.
echo [3/3] Removing startup persistence...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestRansomware /f 2>nul
if errorlevel 1 (
    echo   OK: No startup entry found
) else (
    echo   OK: Startup entry removed
)

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestRansomwareBackup /f 2>nul 2>nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v TestRansomware /f 2>nul 2>nul

echo.
echo ============================================
echo Cleanup Complete!
echo ============================================
echo.
echo VM is clean. You can now:
echo - Revert to clean snapshot (recommended)
echo - Run another test
echo.
pause
