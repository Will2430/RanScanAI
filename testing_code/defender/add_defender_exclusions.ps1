# ================================================
# Add Windows Defender Exclusions for Testing
# ================================================
# Run as Administrator

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Adding Defender Exclusions for Testing" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Must run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Right-click this file -> Run with PowerShell (as Admin)" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "[1/4] Adding exclusion for Testing_Code folder..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath "C:\Users\User\OneDrive\Test\K\Testing_Code"
    Write-Host "  [OK] Testing_Code excluded" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Already excluded or failed: $_" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[2/4] Adding exclusion for package destination..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath "C:\Users\User\OneDrive\Test\K\Testing_Code\VM_Testing_Package*"
    Write-Host "  [OK] Package folders excluded" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Already excluded or failed: $_" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[3/4] Adding exclusion for Python script pattern..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath "C:\Users\User\OneDrive\Test\K\Testing_Code\*.py"
    Write-Host "  [OK] Python scripts excluded" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Already excluded or failed: $_" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[4/4] Checking current exclusions..." -ForegroundColor Yellow
$exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Write-Host ""
Write-Host "Current exclusions:" -ForegroundColor Cyan
foreach ($path in $exclusions) {
    if ($path -like "*Testing_Code*" -or $path -like "*VM_Testing*") {
        Write-Host "  - $path" -ForegroundColor Green
    } else {
        Write-Host "  - $path" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Optional: Temporarily Disable Real-Time Protection" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "This will disable scanning for 10 minutes to copy files." -ForegroundColor White
Write-Host "It will auto-enable after 10 minutes." -ForegroundColor White
Write-Host ""
Write-Host "Disable real-time protection? (y/n): " -NoNewline
$response = Read-Host

if ($response -eq 'y') {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true
        Write-Host ""
        Write-Host "[OK] Real-time protection DISABLED" -ForegroundColor Yellow
        Write-Host "Run your packaging script now!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Re-enable with:" -ForegroundColor White
        Write-Host "  Set-MpPreference -DisableRealtimeMonitoring `$false" -ForegroundColor Gray
    } catch {
        Write-Host ""
        Write-Host "[FAILED] Could not disable: $_" -ForegroundColor Red
        Write-Host "Try: Windows Security -> Virus & threat protection -> Manage settings -> Turn OFF Real-time protection" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Done! Try running create_vm_package.bat now." -ForegroundColor Green
Write-Host ""
pause
