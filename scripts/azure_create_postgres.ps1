<#
Azure provisioning script for RanScanAI (Flexible Server - PostgreSQL)

What it does:
- Creates a resource group
- Creates an Azure Database for PostgreSQL Flexible Server (small dev SKU)
- Creates the database
- Adds a firewall rule for your current public IP
- Attempts to create an application DB role if `psql` is available

Security NOTES:
- This script contains generated passwords for convenience. Treat it as sensitive and delete or move passwords to Azure Key Vault after use.
- You can run this in Azure Cloud Shell (recommended) or locally with Azure CLI installed and logged in.

Usage (Cloud Shell):
  1. Open https://shell.azure.com and paste this script or upload and run it
  2. The script prints connection information at the end

#>

param(
    [string]$ResourceGroup = "ranscanai-rg",
    [string]$Location = "eastus",
    [string]$ServerName = "ranscanai-server",
    [string]$AdminUser = "ranscan_admin",
    [string]$DatabaseName = "ranscanai",
    [string]$SkuName = "Standard_B1ms"
)

# Credentials: prefer environment variables for automation/CI (AZ_PG_ADMIN_PW, AZ_PG_APP_PW)
$AppUser = "ranscan_app"

# Admin password: use env var if present, otherwise prompt interactively (not stored)
if ($env:AZ_PG_ADMIN_PW) {
    $AdminPassword = $env:AZ_PG_ADMIN_PW
    Write-Host "Using admin password from AZ_PG_ADMIN_PW environment variable"
} else {
    Write-Host "No AZ_PG_ADMIN_PW environment variable found. You will be prompted to enter an admin password (this will not be saved to disk)."
    $secure = Read-Host -Prompt 'Enter admin password' -AsSecureString
    $AdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

# Application password: use env var if present, otherwise prompt
if ($env:AZ_PG_APP_PW) {
    $AppPassword = $env:AZ_PG_APP_PW
    Write-Host "Using app password from AZ_PG_APP_PW environment variable"
} else {
    Write-Host "No AZ_PG_APP_PW environment variable found. You will be prompted to enter an application user password (this will not be saved to disk)."
    $secureApp = Read-Host -Prompt 'Enter app user password' -AsSecureString
    $AppPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApp))
}

Write-Host "Using values: ResourceGroup=$ResourceGroup, Location=$Location, Server=$ServerName, AdminUser=$AdminUser, DB=$DatabaseName"

# Ensure Azure CLI is available
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI (az) not found. Please install or use Cloud Shell: https://shell.azure.com"
    exit 1
}

# Ensure user is logged in
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "You are not logged in. Running 'az login'..."
    az login | Out-Null
}

# Create resource group
Write-Host "Creating resource group '$ResourceGroup' in $Location..."
az group create --name $ResourceGroup --location $Location | Out-Null

# Try to create server; if name conflict, append a short random suffix
function Create-FlexibleServer($name) {
    try {
        Write-Host "Creating PostgreSQL Flexible Server '$name' (this can take a few minutes)..."
        az postgres flexible-server create `
            --resource-group $ResourceGroup `
            --name $name `
            --location $Location `
            --admin-user $AdminUser `
            --admin-password $AdminPassword `
            --sku-name $SkuName `
            --version 15 `
            --yes | Out-Null
        return $true
    } catch {
        Write-Warning "Failed to create server '$name' - $_"
        return $false
    }
}

$created = Create-FlexibleServer -name $ServerName
if (-not $created) {
    # generate a suffix and retry
    $suffix = -join ((48..57) + (97..122) | Get-Random -Count 4 | ForEach-Object {[char]$_})
    $newName = "$ServerName-$suffix"
    Write-Host "Retrying with server name: $newName"
    $created = Create-FlexibleServer -name $newName
    if ($created) { $ServerName = $newName } else { Write-Error "Could not create a server. Aborting."; exit 1 }
}

# Create database
Write-Host "Creating database '$DatabaseName' on server '$ServerName'..."
az postgres flexible-server db create --resource-group $ResourceGroup --name $ServerName --database-name $DatabaseName | Out-Null

# Get public IP and add firewall rule
try {
    $myIp = (Invoke-RestMethod -Uri 'https://ifconfig.me' -UseBasicParsing).Trim()
} catch {
    Write-Warning "Could not determine public IP automatically. Please provide an IP or run the firewall command manually."
    $myIp = Read-Host 'Enter your public IP (e.g. 1.2.3.4)'
}

Write-Host "Adding firewall rule to allow $myIp..."
az postgres flexible-server firewall-rule create --resource-group $ResourceGroup --name $ServerName --rule-name AllowMyIP --start-ip-address $myIp --end-ip-address $myIp | Out-Null

# Print connection info
$Fqdn = "$ServerName.postgres.database.azure.com"
Write-Host "\n=== Azure Postgres Provisioned ==="
Write-Host "Server FQDN: $Fqdn"
Write-Host "Admin user: $AdminUser@$ServerName"
Write-Host "Database: $DatabaseName"
Write-Host "Application user recommended: $AppUser"
Write-Host "\nIMPORTANT: The script did not print passwords for security reasons. If you provided passwords interactively, keep them secure and rotate them after provisioning. Consider storing secrets in Azure Key Vault and using Key Vault references in automation.\n"

# Print SQL snippet to create application role (run this as the admin user via psql/Azure Data Studio if you did not run automatic SQL)
Write-Host "--- SQL to create application role (run as admin) ---"
Write-Host "CREATE ROLE $AppUser LOGIN PASSWORD '<APP_PASSWORD_HERE>' NOINHERIT;"
Write-Host "GRANT CONNECT ON DATABASE $DatabaseName TO $AppUser;"
Write-Host "\c $DatabaseName"
Write-Host "GRANT USAGE ON SCHEMA public TO $AppUser;"
Write-Host "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO $AppUser;"
Write-Host "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO $AppUser;"

Write-Host "\nScript finished. Store credentials securely (Azure Key Vault recommended). Do not commit passwords to version control." 
