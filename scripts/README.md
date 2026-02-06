Azure provisioning scripts for RanScanAI

Files:
- azure_create_postgres.ps1  - PowerShell script to create an Azure Flexible Server (Postgres), a database, firewall rule for your IP, and an app user.

Usage:
1. Open Azure Cloud Shell (https://shell.azure.com) or use a local machine with Azure CLI logged in.
2. Run the script in Cloud Shell (recommended):
   - Upload the script or paste it into Cloud Shell.
   - Example: pwsh ./azure_create_postgres.ps1
3. The script will prompt for admin and application passwords interactively unless you provide them via environment variables `AZ_PG_ADMIN_PW` and `AZ_PG_APP_PW` (useful for automation/CI). The script does NOT store or print passwords to the repo for security.
4. After provisioning, run the init SQL in `../db-init/init-db.sql` (use `psql` or Azure Data Studio) to create tables.
5. Use `.env.example` at the repo root as a template for your app's environment variables. Do NOT commit real credentials to Git.

Security:
- The script currently includes generated passwords for convenience. Replace or rotate them and store secrets in Key Vault.
- For production, use a private endpoint or VNet rules and avoid public access.
 - The script prompts for passwords or reads them from environment variables but does not store them in the repo.
 - Always rotate generated or provisioned passwords and store secrets in Azure Key Vault or your team's secret manager.

Next steps after provisioning:
- Run the init SQL in `db-init/init-db.sql` (use psql or Azure Data Studio) to create tables.
- Update your app `DATABASE_URL` to point at the new server.
- Use Alembic for migrations going forward.
