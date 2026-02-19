# Setup Windows Task Scheduler for Adaptive Learning
# Run this script as Administrator in PowerShell

Write-Host "="*70
Write-Host "ADAPTIVE LEARNING - SCHEDULER SETUP"
Write-Host "="*70
Write-Host ""

# Get Python executable path
$pythonPath = (Get-Command python).Source
Write-Host "Python executable: $pythonPath"

# Get project root
$projectRoot = (Get-Location).Path
Write-Host "Project root: $projectRoot"

$backendPath = Join-Path $projectRoot "iteration_1\backend"
$schedulersPath = Join-Path $backendPath "schedulers"

Write-Host ""
Write-Host "Creating scheduled tasks..."
Write-Host ""

# Task 1: VT Upload Scheduler (Daily at midnight)
Write-Host "[1/3] VT Upload Scheduler (Daily at 00:00)"
$vtSchedulerScript = Join-Path $schedulersPath "vt_upload_scheduler.py"

schtasks /create /tn "SecureGuard_VT_Upload" `
    /tr "`"$pythonPath`" `"$vtSchedulerScript`"" `
    /sc daily `
    /st 00:00 `
    /f `
    /rl HIGHEST

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Created successfully" -ForegroundColor Green
} else {
    Write-Host "  ✗ Failed to create task" -ForegroundColor Red
}

Write-Host ""

# Task 2: Retraining Scheduler (Weekly on Sunday at 02:00)
Write-Host "[2/3] Retraining Scheduler (Weekly Sunday at 02:00)"
$retrainingScript = Join-Path $schedulersPath "retraining_scheduler.py"

schtasks /create /tn "SecureGuard_Retraining_Check" `
    /tr "`"$pythonPath`" `"$retrainingScript`"" `
    /sc weekly `
    /d SUN `
    /st 02:00 `
    /f `
    /rl HIGHEST

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Created successfully" -ForegroundColor Green
} else {
    Write-Host "  ✗ Failed to create task" -ForegroundColor Red
}

Write-Host ""

# Task 3: Cleanup Job (Weekly on Sunday at 03:00)
Write-Host "[3/3] Cleanup Job (Weekly Sunday at 03:00)"
$cleanupScript = Join-Path $schedulersPath "cleanup_queued_files.py"

schtasks /create /tn "SecureGuard_Cleanup_Files" `
    /tr "`"$pythonPath`" `"$cleanupScript`"" `
    /sc weekly `
    /d SUN `
    /st 03:00 `
    /f `
    /rl HIGHEST

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Created successfully" -ForegroundColor Green
} else {
    Write-Host "  ✗ Failed to create task" -ForegroundColor Red
}

Write-Host ""
Write-Host "="*70
Write-Host "SETUP COMPLETE"
Write-Host "="*70
Write-Host ""
Write-Host "Created tasks:"
Write-Host "  1. SecureGuard_VT_Upload - Daily at 00:00"
Write-Host "  2. SecureGuard_Retraining_Check - Weekly Sunday at 02:00"
Write-Host "  3. SecureGuard_Cleanup_Files - Weekly Sunday at 03:00"
Write-Host ""
Write-Host "To view tasks:"
Write-Host "  schtasks /query /tn SecureGuard_VT_Upload /v"
Write-Host ""
Write-Host "To run task manually:"
Write-Host "  schtasks /run /tn SecureGuard_VT_Upload"
Write-Host ""
Write-Host "To delete tasks:"
Write-Host "  schtasks /delete /tn SecureGuard_VT_Upload /f"
Write-Host ""
