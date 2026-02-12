@echo off
echo ============================================
echo Quick Start: Behavioral Monitoring Test
echo ============================================
echo.
echo This will:
echo 1. Create test folder with dummy files
echo 2. Run ransomware simulator with behavioral monitoring
echo 3. Generate behavioral_data.json
echo.
pause

echo [1/2] Creating test environment...
python setup_test_environment.py

echo [2/2] Running behavioral monitor...
python vm_behavioral_monitor.py ransomware_simulator.py C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER

echo ============================================
echo Done! Check behavioral_data.json
echo ============================================
pause
