# IntuneComplianceMaintainer

Automatically maintain Microsoft Intune Compliance and App Protection policies with the latest supported minimum OS versions, ensuring devices access is restricted based on up-to-date device security.

## Overview

IntuneComplianceMaintainer is a PowerShell automation script that keeps your Intune compliance and app-protection policies up-to-date with the latest OS version requirements across all major platforms. By leveraging the [endoflife.date API](https://endoflife.date/docs/api/v1/) and [Microsoft Graph Windows Update Catalog](https://learn.microsoft.com/en-us/graph/api/windowsupdates-catalog-list-entries?view=graph-rest-beta&tabs=http) data sources, it ensures your organisation maintains security posture while respecting configurable cadence periods for gradual rollout.

## Features

- **Multi-Platform Support**: iOS, iPadOS, macOS, Android, and Windows
- **Dual Policy Types**: Updates both compliance and app-protection policies
- **Flexible Authentication**: Supports Managed Identity (Azure Automation), App Registration with Certificate, or App Registration with Secret (including Azure Key Vault integration)
- **Cadence Control**: Configurable delay between update release and policy enforcement to account for update rollout schedule, with optional force-apply override
- **Android Patch Level**: Enforces minimum Android security patch level alongside OS version; targets the oldest maintained Android version for `osMinimumVersion` (so any supported release passes) and derives the monthly patch date from Android's patch schedule (1st of each month)
- **Windows Advanced Options**: Support for specific build numbers, update classifications, version ranges, and selectable app-protection target build (lowest by default)
- **Safety Features**: Optional downgrade protection and dry-run mode (downgrade check covers both OS version and patch level independently)
- **Retry Logic**: Built-in retry mechanism for API resilience
- **Comprehensive Logging**: Verbose logging with detailed result output

## Prerequisites

- PowerShell 5.1 or later
- Microsoft Graph API permissions:
  - `DeviceManagementConfiguration.ReadWrite.All` (for Compliance policies)
  - `DeviceManagementApps.ReadWrite.All` (for App Protection policies)
  - `WindowsUpdates.ReadWrite.All` (for Windows Update Catalog queries)
- For Managed Identity authentication: `Az.Accounts` module (pre-installed in Azure Automation)
- For Key Vault integration: `Az.KeyVault` module and appropriate Key Vault access
- For certificate authentication: Certificate installed in CurrentUser\My store

## Configuration

### Authentication Settings

Configure one of the following authentication modes:

#### Managed Identity
```powershell
# Managed Identity (recommended for Azure Automation)
$AuthMode = "ManagedIdentity"
$TenantId = "your-tenant-id"
# Optional: specify user-assigned managed identity client ID (leave blank for system-assigned)
$UserAssignedClientId = ""
```
For Azure Automation: 
1. Enable system-assigned or user-assigned managed identity on the Automation Account
2. Grant the identity necessary Graph API application permissions, or utilise the *Grant-ManagedIdentityGraphAppRoles.ps1* script in this repo to automate this.
3. Ensure Az.Accounts module is available (usually pre-installed in Azure Automation)

#### App Registration with Certificate
```powershell
# App Registration with Certificate
$AuthMode = "AppRegCert"
$TenantId = "your-tenant-id"
$ClientId = "your-client-id"
$CertThumbprint = "certificate-thumbprint"
```

#### App Registration with Secret
```powershell
# App Registration with Secret
$AuthMode = "AppRegSecret"
$TenantId = "your-tenant-id"
$ClientId = "your-client-id"
$ClientSecret = "your-client-secret"

# Optional: Use Key Vault
$KeyVaultName = "your-keyvault-name"
$KeyVaultSecretName = "your-secret-name"
```

### Environment Configuration

```powershell
# Cadence: days to wait after release before enforcing
$CadenceDays = 14

# Define policy IDs to update (leave empty to skip platform)
$CompliancePolicies = @{
  iOS     = @("policy-guid-1", "policy-guid-2")
  iPadOS  = @("policy-guid-3")
  macOS   = @()
  Android = @("policy-guid-4")
  Windows = @("policy-guid-5")
}

$AppProtectionPolicies = @{
  iOS     = @("policy-guid-6")
  iPadOS  = @()
  Android = @("policy-guid-7")
  Windows = @("policy-guid-8")
}
```

### Windows-Specific Settings

```powershell
# Specify Windows build numbers (e.g., 26100 for 24H2, 26200 for 25H2)
$WindowsBuildNumbers = @("26100", "26200")

# Update classification: security or nonSecurity
$WindowsUpdateClassification = "nonSecurity"

# Number of recent cumulative updates to include
$WindowsNumberOfUpdates = 1

# Allow devices on newer builds (e.g Preview Updates)
$WindowsAllowNewerBuilds = $true

# Compliance mode: Ranges or MinimumVersion
$WindowsComplianceMode = "Ranges"

# App Protection target when using Ranges: Lowest (default) or Highest build in the range
$WindowsAppProtectionTarget = "Lowest"
```

### Safety Settings

```powershell
# Prevent lowering existing minimum OS version
$AllowDowngrade = $false

# Dry run mode (report changes without applying)
$DryRun = $true

# Force apply even if cadence/effective date hasn't elapsed
$ForceApply = $false
```

## Usage

### Basic Execution

1. Configure authentication and policy IDs in the script
2. Run the script:

```powershell
.\IntuneComplianceMaintainer.ps1
```

### First Run (Recommended)

Start with dry-run mode to preview changes:

```powershell
# In script configuration:
$DryRun = $true
```

Review the output to ensure expected behavior, then disable dry-run:

```powershell
$DryRun = $false
```

### Scheduled Execution

Deploy to Azure Automation for scheduled runs:

1. Create an Automation Account with Managed Identity
2. Assign required Graph API permissions to the Managed Identity
3. Import the script as a runbook
4. Configure schedule (e.g., daily or weekly)

## How It Works

### For iOS, iPadOS, and macOS

1. Queries endoflife.date API for the latest OS version
2. Calculates effective date based on release date + cadence days
3. If effective date has passed:
   - Updates compliance policies with `osMinimumVersion`
   - Updates app-protection policies with `minimumRequiredOsVersion` (iOS/iPadOS only; macOS has no app-protection support)

### For Android

1. Queries endoflife.date API to determine all currently maintained Android versions (e.g. 14, 15, 16, 17)
2. Sets `osMinimumVersion` / `minimumRequiredOsVersion` to the **oldest** maintained version — devices running any supported Android release satisfy the version check
3. Derives the monthly security patch date from Android's fixed release schedule (1st of each month) and applies cadence from that date
4. If effective date has passed:
   - Updates compliance policies with `osMinimumVersion` and `minAndroidSecurityPatchLevel`
   - Updates app-protection policies with `minimumRequiredOsVersion` and `minimumRequiredPatchVersion`
   - Both patch level fields use `YYYY-MM-DD` format
5. Downgrade protection evaluates OS version and patch level independently — a policy with a current OS version but stale patch level will still be updated

### For Windows

1. Queries Microsoft Graph Windows Update Catalog for recent cumulative updates
2. Calculates effective date based on release date + cadence days
3. Supports two compliance modes:
  - **Ranges mode** (recommended for multiple builds): Updates `validOperatingSystemBuildRanges`. When using Ranges, app-protection targets the lowest build in the range by default; set `$WindowsAppProtectionTarget = "Highest"` to target the highest build instead.
  - **MinimumVersion mode**: Updates `osMinimumVersion` with highest build version
4. You can force updates to apply even if the cadence/effective date hasn't elapsed by setting `$ForceApply = $true` (applies to both compliance and app-protection). Use cautiously in production.

## Output

The script provides detailed logging and a summary table:

```
[2025-12-16 10:30:15][INFO] Starting run: DryRun=True; AllowDowngrade=False
[RESULT][iOS/Compliance] Compliance-iOS-Production: action=WouldUpdate; current=17.6.1; target=18.2.1; effective=2025-12-18
[RESULT][Android/Compliance] Compliance-Android-Corp: action=WouldUpdate; current=14; target=14; patch=2026-07-01; release=7/1/2026; effective=7/15/2026
[RESULT][Android/AppProtection] MAM-Android-Corp: action=WouldUpdate; current=14; target=14; patch=2026-07-01; release=7/1/2026; effective=7/15/2026
[RESULT][Windows/Compliance] Compliance-Windows-Corp: action=WouldUpdate; current=10.0.26100.2314-10.0.26100.2454; target=10.0.26100.2605-10.0.26100.9999; setting=Range

Platform  Type          Setting        Name                        Current        Target         Action        EffectiveDate
--------  ----          -------        ----                        -------        ------         ------        -------------
iOS       Compliance    MinimumVersion Compliance-iOS-Production   17.6.1         18.2.1         WouldUpdate   12/18/2025
Android   Compliance    MinimumVersion Compliance-Android-Corp     14             14             WouldUpdate   7/15/2026
Android   AppProtection MinimumVersion MAM-Android-Corp            14             14             WouldUpdate   7/15/2026
Windows   Compliance    Range          Compliance-Windows-Corp     10.0.26100...  10.0.26100...  WouldUpdate   12/17/2025
```

> **Note**: For Android, the `Current` and `Target` columns reflect `osMinimumVersion`. The `patch=` field in the verbose log shows the `minAndroidSecurityPatchLevel` / `minimumRequiredPatchVersion` value being enforced. Where the OS version is already at the target, the update still proceeds if the patch level is stale.

## Action Types

- **Updated**: Policy was successfully updated
- **WouldUpdate**: Policy would be updated (dry-run mode)
- **Skipped**: Current version meets or exceeds target (downgrade protection)
- **NotEffectiveYet**: Cadence period hasn't elapsed
- **NoData**: No version data available from API
- **Error**: Update failed (see error details in output)

## Best Practices

1. **Start with Dry-Run**: Always test with `$DryRun = $true` first
2. **Gradual Rollout**: Use appropriate `$CadenceDays` value for your environment (2-7 days recommended)
3. **Downgrade Protection**: Keep `$AllowDowngrade = $false` unless intentionally reverting
4. **Selective Updates**: Only specify policy IDs for platforms you want to automate
5. **Monitor Logs**: Enable `$VerboseLogging = $true` for troubleshooting
6. **Schedule Appropriately**: Run daily or weekly depending on your compliance requirements
7. **Test Authentication**: Verify Graph API permissions before production deployment
8. **Azure Automation**: If using Managed Identity, enable it on the Automation Account (system-assigned or set `$UserAssignedClientId`) and grant Graph app roles (`DeviceManagementConfiguration.ReadWrite.All`, `DeviceManagementApps.ReadWrite.All`, `WindowsUpdates.ReadWrite.All`).

## Platform-Specific Notes
### Windows

- Build numbers correspond to Windows versions (e.g., 26100 = 24H2)

### iOS/iPadOS
- Both compliance and app-protection policies supported
- Cadence calculated from latest patch release date

### macOS
- Supports compliance policies only
- App-protection not available for macOS

### Android
- Supports both compliance and app-protection policies
- `osMinimumVersion` is set to the oldest currently maintained Android version (e.g. 14), so devices on any supported release (14, 15, 16, 17, etc.) satisfy the compliance check; the maintained set is determined dynamically from the endoflife.date API
- Security patch level is updated monthly, aligned with Android's fixed patch release schedule (1st of each month); cadence is applied from that date
- Compliance policies: patch level written to `minAndroidSecurityPatchLevel`
- App Protection policies: patch level written to `minimumRequiredPatchVersion`
- Both patch level fields use `YYYY-MM-DD` format (e.g. `2026-07-01`)

## Troubleshooting
### Authentication Errors
- Verify Graph API permissions are granted and admin-consented
- For Managed Identity: Ensure identity is enabled and permissions assigned
- For certificate auth: Confirm certificate is in CurrentUser\My store and thumbprint is correct
- For Key Vault: Verify access policies and secret exists

### API Errors
- Check retry count and delay settings
- Verify policy IDs are correct and accessible
- Ensure token has sufficient permissions for both read and write operations

### No Data Returned
- Verify internet connectivity to endoflife.date API
- For Windows: Confirm build numbers exist in Windows Update Catalog
- Check verbose logs for API response details

## Security Considerations

- Store secrets in Azure Key Vault when using AppRegSecret mode
- Use Managed Identity for Azure Automation scenarios
- Apply least-privilege Graph API permissions
- Review audit logs for policy changes
- Test in non-production environment first

## Version History

- **v1.2** (2026-07-01): Android multi-version support (targets oldest maintained release for `osMinimumVersion`); monthly Android security patch level enforcement (`minAndroidSecurityPatchLevel` / `minimumRequiredPatchVersion`); downgrade protection now evaluates OS version and patch level independently; `Get-AzAccessToken` SecureString compatibility for Az module 12.0+
- **v1.1** (2025-12-19): Added Azure Automation managed identity support, force-apply option, Windows app protection target selection, release date tracking
- **v1.0** (2025-12-15): Initial release

## Thanks
Thanks to [Max Weber](https://intune-blog.com/) for inspiration on Windows Update Catalog Graph API usage in [this blog](https://intune-blog.com/posts/automate-valid-os-builds.html)

## License

Use at your own discretion. Review and test thoroughly before production deployment.


## Disclaimer

This script modifies production Intune policies. Always test in a non-production environment and use dry-run mode before live deployment. The author assumes no liability for unintended changes or impacts to your environment.