<#
.SYNOPSIS
  Grant Microsoft Graph API permissions to an Azure Automation Account's managed identity.

.DESCRIPTION
  This script grants the required Graph API application permissions to a managed identity
  so it can update Intune compliance and app protection policies.

.NOTES
  Run this script with an account that has:
  - Application.ReadWrite.All permission in Microsoft Graph
  - Privileged Role Administrator or Global Administrator role in Entra ID
  
  You must have the Microsoft.Graph PowerShell module installed:
  Install-Module Microsoft.Graph -Scope CurrentUser -Force

.EXAMPLE
  # For system-assigned managed identity
  .\Grant-ManagedIdentityGraphPermissions.ps1 -TenantId "your-tenant-id" -ManagedIdentityDisplayName "AutomationAccountName"
  
  # For user-assigned managed identity
  .\Grant-ManagedIdentityGraphPermissions.ps1 -TenantId "your-tenant-id" -ManagedIdentityDisplayName "YourManagedIdentityName"
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$TenantId,
  
  [Parameter(Mandatory=$true)]
  [string]$ManagedIdentityDisplayName
)

# Connect to Microsoft Graph with required permissions
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

# Get the managed identity service principal
Write-Host "Finding managed identity: $ManagedIdentityDisplayName" -ForegroundColor Cyan
$managedIdentity = Get-MgServicePrincipal -Filter "displayName eq '$ManagedIdentityDisplayName'" -ErrorAction Stop
if (-not $managedIdentity) {
  throw "Managed identity '$ManagedIdentityDisplayName' not found. For system-assigned identities, use the Automation Account name."
}
Write-Host "  Found: $($managedIdentity.DisplayName) (ObjectId: $($managedIdentity.Id))" -ForegroundColor Green

# Get Microsoft Graph service principal
Write-Host "Finding Microsoft Graph service principal..." -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
Write-Host "  Found: $($graphSp.DisplayName)" -ForegroundColor Green

# Define required permissions
$requiredPermissions = @(
  "DeviceManagementConfiguration.ReadWrite.All",
  "DeviceManagementApps.ReadWrite.All",
  "WindowsUpdates.ReadWrite.All"
)

Write-Host "`nGranting Graph API permissions..." -ForegroundColor Cyan
foreach ($permissionName in $requiredPermissions) {
  # Find the app role (permission) by value
  $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $permissionName }
  if (-not $appRole) {
    Write-Warning "Permission '$permissionName' not found in Graph API app roles"
    continue
  }
  
  # Check if permission is already assigned
  $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id |
    Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphSp.Id }
  
  if ($existingAssignment) {
    Write-Host "  [SKIP] $permissionName - already assigned" -ForegroundColor Yellow
    continue
  }
  
  # Grant the permission
  try {
    $assignment = New-MgServicePrincipalAppRoleAssignment `
      -ServicePrincipalId $managedIdentity.Id `
      -PrincipalId $managedIdentity.Id `
      -ResourceId $graphSp.Id `
      -AppRoleId $appRole.Id `
      -ErrorAction Stop
    
    Write-Host "  [SUCCESS] $permissionName - granted" -ForegroundColor Green
  }
  catch {
    Write-Host "  [ERROR] $permissionName - failed: $($_.Exception.Message)" -ForegroundColor Red
  }
}

Write-Host "`nPermission grant complete!" -ForegroundColor Green
Write-Host "The managed identity can now access Microsoft Graph API with the granted permissions." -ForegroundColor Cyan
Write-Host "`nNote: Permissions may take a few minutes to fully propagate." -ForegroundColor Yellow

Disconnect-MgGraph
