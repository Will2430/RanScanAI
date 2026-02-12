# ================================================
# Restore Quarantined Files & Add Exclusions
# ================================================
# Run as Administrator

param(
    [switch]$Force
)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Restore Quarantined Ransomware Simulator" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Must run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Right-click PowerShell -> Run as Administrator, then:" -ForegroundColor Yellow
    Write-Host "  cd C:\Users\User\OneDrive\Test\K\Testing_Code" -ForegroundColor Gray
    Write-Host "  .\restore_quarantine.ps1" -ForegroundColor Gray
    pause
    exit 1
}

# Step 1: Add exclusions FIRST (before restoring)
Write-Host "[Step 1/4] Adding Defender exclusions..." -ForegroundColor Yellow
Write-Host ""

$exclusions = @(
    "C:\Users\User\OneDrive\Test\K\Testing_Code",
    "C:\Users\User\OneDrive\Test\K\Testing_Code\VM_Testing_Package*",
    "C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER"
)

foreach ($path in $exclusions) {
    try {
        Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
        Write-Host "  [OK] Excluded: $path" -ForegroundColor Green
    } catch {
        Write-Host "  [SKIP] $path (already exists)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "[Step 2/4] Checking quarantined threats..." -ForegroundColor Yellow
Write-Host ""

# Get all threats
$allThreats = Get-MpThreatDetection

if (-not $allThreats) {
    Write-Host "  No threats in quarantine!" -ForegroundColor Green
    Write-Host ""
    Write-Host "The file might have been manually deleted." -ForegroundColor Yellow
    Write-Host "You'll need to recreate it from git or backup." -ForegroundColor Yellow
    pause
    exit 0
}

# Find ransomware_simulator threats
$ourThreats = $allThreats | Where-Object { 
    $_.Resources -like "*ransomware_simulator*" -or 
    $_.Resources -like "*Testing_Code*"
}

if ($ourThreats) {
    Write-Host "Found quarantined files:" -ForegroundColor Red
    foreach ($threat in $ourThreats) {
        Write-Host "  Threat: $($threat.ThreatName)" -ForegroundColor Yellow
        foreach ($resource in $threat.Resources) {
            Write-Host "    File: $resource" -ForegroundColor White
        }
    }
} else {
    Write-Host "  No matching threats found in quarantine" -ForegroundColor Gray
    Write-Host "  The file was likely deleted permanently" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[Step 3/4] Removing threats from quarantine..." -ForegroundColor Yellow
Write-Host ""

if ($ourThreats) {
    foreach ($threat in $ourThreats) {
        try {
            # Remove threat (this "allows" it)
            Remove-MpThreat -ThreatID $threat.ThreatID -ErrorAction Stop
            Write-Host "  [OK] Removed threat: $($threat.ThreatName)" -ForegroundColor Green
        } catch {
            Write-Host "  [FAILED] Could not remove: $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  Nothing to restore" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[Step 4/4] Checking if file exists..." -ForegroundColor Yellow
Write-Host ""

$filePath = "C:\Users\User\OneDrive\Test\K\Testing_Code\ransomware_simulator.py"
if (Test-Path $filePath) {
    Write-Host "  [OK] File exists: $filePath" -ForegroundColor Green
    Write-Host "  Size: $((Get-Item $filePath).Length) bytes" -ForegroundColor White
} else {
    Write-Host "  [NOT FOUND] File does not exist: $filePath" -ForegroundColor Red
    Write-Host ""
    Write-Host "  The file was permanently deleted by Defender." -ForegroundColor Yellow
    Write-Host "  You need to recreate it:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Option A: Restore from git" -ForegroundColor White
    Write-Host "    git checkout ransomware_simulator.py" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Option B: Undo last change in VS Code" -ForegroundColor White
    Write-Host "    Ctrl+Z until file is back" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Option C: Copy from backup/another location" -ForegroundColor White
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Current Defender Exclusions:" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan
$currentExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
foreach ($ex in $currentExclusions) {
    if ($ex -like "*Testing_Code*" -or $ex -like "*RANSOMWARE*") {
        Write-Host "  $ex" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "1. If file exists, try packaging again:" -ForegroundColor White
Write-Host "   .\create_vm_package.bat" -ForegroundColor Gray
Write-Host ""
Write-Host "2. If file missing, restore from git:" -ForegroundColor White
Write-Host "   git status" -ForegroundColor Gray
Write-Host "   git checkout ransomware_simulator.py" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Exclusions are now active - file won't be blocked again" -ForegroundColor White
Write-Host ""

pause
