# SecureGuard Native Messaging Host Uninstaller
# Run as Administrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " SecureGuard Native Host Uninstaller" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Must run as Administrator!" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "Removing native messaging host..." -ForegroundColor Yellow
Write-Host ""

# Remove registry keys
Write-Host "[1/3] Removing Chrome registry entries..." -ForegroundColor Yellow
$chromeReg = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.secureguard.host"
if (Test-Path $chromeReg) {
    Remove-Item -Path $chromeReg -Force
    Write-Host "  Removed Chrome registry key" -ForegroundColor Green
} else {
    Write-Host "  Chrome registry key not found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[2/3] Removing Edge registry entries..." -ForegroundColor Yellow
$edgeReg = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.secureguard.host"
if (Test-Path $edgeReg) {
    Remove-Item -Path $edgeReg -Force
    Write-Host "  Removed Edge registry key" -ForegroundColor Green
} else {
    Write-Host "  Edge registry key not found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[3/3] Removing host files..." -ForegroundColor Yellow

$choice = Read-Host "Do you want to delete quarantined files too? (y/N)"

$installDir = "$env:LOCALAPPDATA\SecureGuard"

if ($choice -eq 'y' -or $choice -eq 'Y') {
    if (Test-Path $installDir) {
        Remove-Item -Path $installDir -Recurse -Force
        Write-Host "  Removed all files including quarantine" -ForegroundColor Green
    }
} else {
    # Remove only host files, keep quarantine
    $filesToRemove = @(
        "$installDir\secureguard_host.py",
        "$installDir\secureguard_host.bat",
        "$installDir\com.secureguard.host.json"
    )
    
    foreach ($file in $filesToRemove) {
        if (Test-Path $file) {
            Remove-Item -Path $file -Force
            Write-Host "  Removed $(Split-Path $file -Leaf)" -ForegroundColor Green
        }
    }
    
    Write-Host "  Kept quarantine directory: $installDir\Quarantine" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Uninstallation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

pause
