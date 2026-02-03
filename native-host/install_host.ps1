# SecureGuard Native Messaging Host Installer
# Run this script as Administrator to install the native messaging host

param(
    [string]$ExtensionId = ""
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " SecureGuard Native Host Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To run as Administrator:" -ForegroundColor Yellow
    Write-Host "  1. Right-click PowerShell" -ForegroundColor Yellow
    Write-Host "  2. Select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host "  3. Run this script again" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "[1/6] Checking Python installation..." -ForegroundColor Yellow

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Python not found!" -ForegroundColor Red
    Write-Host "  Please install Python 3.7+ from https://www.python.org/" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host ""
Write-Host "[2/6] Creating installation directory..." -ForegroundColor Yellow

# Create installation directory
$installDir = "$env:LOCALAPPDATA\SecureGuard"
$hostDir = "$installDir"

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Write-Host "  Created: $installDir" -ForegroundColor Green
} else {
    Write-Host "  Already exists: $installDir" -ForegroundColor Green
}

Write-Host ""
Write-Host "[3/6] Copying host files..." -ForegroundColor Yellow

# Copy Python script
$scriptPath = Join-Path $PSScriptRoot "secureguard_host.py"
$destScriptPath = Join-Path $hostDir "secureguard_host.py"

if (Test-Path $scriptPath) {
    Copy-Item -Path $scriptPath -Destination $destScriptPath -Force
    Write-Host "  Copied: secureguard_host.py" -ForegroundColor Green
} else {
    Write-Host "  ERROR: secureguard_host.py not found!" -ForegroundColor Red
    pause
    exit 1
}

# Create Python launcher (EXE wrapper)
$launcherPath = Join-Path $hostDir "secureguard_host.bat"
$launcherContent = "@echo off`npython `"%~dp0secureguard_host.py`" %*"
Set-Content -Path $launcherPath -Value $launcherContent -Force
Write-Host "  Created: secureguard_host.bat" -ForegroundColor Green

Write-Host ""
Write-Host "[4/6] Getting Extension ID..." -ForegroundColor Yellow

if ([string]::IsNullOrEmpty($ExtensionId)) {
    Write-Host ""
    Write-Host "  Please enter your Chrome Extension ID:" -ForegroundColor Cyan
    Write-Host "  (Found at chrome://extensions/ - looks like: abcdefghijklmnopqrstuvwxyz123456)" -ForegroundColor Gray
    Write-Host ""
    $ExtensionId = Read-Host "  Extension ID"
}

if ([string]::IsNullOrEmpty($ExtensionId)) {
    Write-Host "  ERROR: Extension ID is required!" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "  Using Extension ID: $ExtensionId" -ForegroundColor Green

Write-Host ""
Write-Host "[5/6] Creating host manifest..." -ForegroundColor Yellow

# Create manifest JSON
$manifestPath = Join-Path $hostDir "com.secureguard.host.json"
$manifest = @{
    name = "com.secureguard.host"
    description = "SecureGuard Native Messaging Host"
    path = $launcherPath
    type = "stdio"
    allowed_origins = @(
        "chrome-extension://$ExtensionId/"
    )
} | ConvertTo-Json

Set-Content -Path $manifestPath -Value $manifest -Force
Write-Host "  Created: com.secureguard.host.json" -ForegroundColor Green

Write-Host ""
Write-Host "[6/6] Registering with Chrome..." -ForegroundColor Yellow

# Register with Chrome via registry
$registryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.secureguard.host"

try {
    # Create registry key
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    
    # Set manifest path
    Set-ItemProperty -Path $registryPath -Name "(Default)" -Value $manifestPath -Force
    
    Write-Host "  Registered with Chrome" -ForegroundColor Green
    
} catch {
    Write-Host "  ERROR: Failed to register with Chrome: $_" -ForegroundColor Red
    pause
    exit 1
}

# Also register with Edge (if installed)
$edgeRegistryPath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.secureguard.host"
try {
    if (-not (Test-Path $edgeRegistryPath)) {
        New-Item -Path $edgeRegistryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $edgeRegistryPath -Name "(Default)" -Value $manifestPath -Force
    Write-Host "  Registered with Edge" -ForegroundColor Green
} catch {
    Write-Host "  Edge not found (OK if not installed)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Installation Details:" -ForegroundColor Cyan
Write-Host "  Host Location: $hostDir" -ForegroundColor Gray
Write-Host "  Manifest: $manifestPath" -ForegroundColor Gray
Write-Host "  Extension ID: $ExtensionId" -ForegroundColor Gray
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Restart Chrome/Edge browser" -ForegroundColor White
Write-Host "  2. Reload your SecureGuard extension" -ForegroundColor White
Write-Host "  3. Test quarantine functionality" -ForegroundColor White
Write-Host ""
Write-Host "To test the installation:" -ForegroundColor Cyan
Write-Host "  Open your extension and check the settings page" -ForegroundColor White
Write-Host "  It should show 'Native Host: Connected'" -ForegroundColor White
Write-Host ""

pause
