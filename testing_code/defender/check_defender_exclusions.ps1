# ================================================
# Check Windows Defender Exclusions
# ================================================
# Run this as Administrator to verify exclusions

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Windows Defender Exclusion Checker" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Not running as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "[OK] Running as Administrator" -ForegroundColor Green
Write-Host ""

# Get current exclusion paths
Write-Host "Current Exclusion Paths:" -ForegroundColor Yellow
$exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

if ($exclusions) {
    foreach ($path in $exclusions) {
        Write-Host "  - $path" -ForegroundColor White
    }
} else {
    Write-Host "  (none)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Current Working Directory:" -ForegroundColor Yellow
Write-Host "  $PWD" -ForegroundColor White
Write-Host ""

# Check if Testing_Code folder is excluded
$testingCodePath = "C:\Users\User\OneDrive\Test\K\Testing_Code"
$isExcluded = $exclusions -contains $testingCodePath

Write-Host "Is Testing_Code excluded? " -NoNewline
if ($isExcluded) {
    Write-Host "YES" -ForegroundColor Green
} else {
    Write-Host "NO" -ForegroundColor Red
    Write-Host ""
    Write-Host "Adding exclusion now..." -ForegroundColor Yellow
    try {
        Add-MpPreference -ExclusionPath $testingCodePath
        Write-Host "[OK] Exclusion added!" -ForegroundColor Green
    } catch {
        Write-Host "[FAILED] Could not add exclusion: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Checking Quarantine" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan

# Check quarantined items
$threats = Get-MpThreatDetection | Where-Object { 
    $_.Resources -like "*ransomware*" -or 
    $_.Resources -like "*Testing_Code*" 
}

if ($threats) {
    Write-Host ""
    Write-Host "Found quarantined items related to your code:" -ForegroundColor Red
    $threats | ForEach-Object {
        Write-Host "  Threat: $($_.ThreatName)" -ForegroundColor Yellow
        Write-Host "  File: $($_.Resources)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Would you like to restore and allow these files? (y/n): " -NoNewline
    $response = Read-Host
    if ($response -eq 'y') {
        Write-Host "Restoring files..." -ForegroundColor Yellow
        $threats | ForEach-Object {
            Remove-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue
        }
        Write-Host "[OK] Files restored (if possible)" -ForegroundColor Green
    }
} else {
    Write-Host "[OK] No related items in quarantine" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Recommended Actions:" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "1. Add exclusion for source folder:" -ForegroundColor White
Write-Host "   Add-MpPreference -ExclusionPath 'C:\Users\User\OneDrive\Test\K\Testing_Code'" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Add exclusion for destination folder:" -ForegroundColor White
Write-Host "   Add-MpPreference -ExclusionPath 'C:\Users\User\OneDrive\Test\K\Testing_Code\VM_Testing_Package*'" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Disable real-time protection temporarily:" -ForegroundColor White
Write-Host "   Set-MpPreference -DisableRealtimeMonitoring `$true" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Re-enable after packaging:" -ForegroundColor White
Write-Host "   Set-MpPreference -DisableRealtimeMonitoring `$false" -ForegroundColor Gray
Write-Host ""

pause
