<#
.SYNOPSIS
  Automatically update Intune compliance and app-protection with supported minimum OS versions, taken from endoflife.date API and Microsoft Graph Windows Update Catalog.
  
  Supported run methods: 
    - Managed Identity
    - App Registration with Certificate
    - App Registration with Secret (optionally from Key Vault)
  
  Supported platforms: 
    - iOS (Compliance and App Protection)
    - iPadOS (Compliance and App Protection)
    - macOS (Compliance only)
    - Android (Compliance and App Protection)
    - Windows (Compliance and App Protection)

.NOTES
    Author: James Robinson | SkipToTheEndpoint | https://skiptotheendpoint.co.uk
    Link: https://stte.me/automatecompliance
    Version: v2.0
    Release Date: 2026-07-01
#>

# --------------------------- Authentication ---------------------------
# Auth mode: ManagedIdentity | AppRegCert | AppRegSecret
$AuthMode              = "<auth-mode>"
$TenantId              = "<tenant-id>"
$ClientId              = "<client-id-if-AppReg>"
$CertThumbprint        = "<thumb-if-AppRegCert>"
$ClientSecret          = "<secret-if-AppRegSecret>"
    
# Optional: clientId of user-assigned managed identity
$UserAssignedClientId  = "" 

# Optional Key Vault lookups (leave blank to skip)
$KeyVaultName          = ""
$KeyVaultSecretName    = ""

# --------------------------- Environment Configuration ---------------------------
# Cadence: days after update release before enforcing via policy
$CadenceDays           = 14

# Policy IDs to update (per platform)
# Can define multiple policies in arrays e.g. @("guid1","guid2"); leave empty to skip platform
$CompliancePolicies = @{
  iOS     = @()
  iPadOS  = @()
  macOS   = @()
  Android = @()
  Windows = @()
}
$AppProtectionPolicies = @{
  iOS     = @()
  iPadOS  = @()
  Android = @()
  Windows = @()
}

# Windows-specific settings
$WindowsBuildNumbers          = @("26100","26200")    # top-level Windows build numbers e.g. 26200 for 25H2
$WindowsUpdateClassification  = "nonSecurity"         # security | nonSecurity
$WindowsNumberOfUpdates       = 1                     # how many recent CUs to treat as compliant
$WindowsAllowNewerBuilds      = $false                # if true, highestVersion ends with .9999
$WindowsComplianceMode        = "Ranges"              # Ranges | MinimumVersion; use Ranges if multiple WindowsBuildNumbers defined
$WindowsAppProtectionTarget   = "Lowest"              # Lowest | Highest; which build to target for Windows App Protection

# --------------------------- Safety ---------------------------
# Allow lowering existing minimum (if set)? Default false
$AllowDowngrade        = $false

# Dry run (report only, no changes)
$DryRun                = $true

# Force apply even if cadence/effective date not reached
$ForceApply            = $false

# --------------------------- Script Variables ---------------------------
# Platform slugs (endoflife.date API product names)
$EolProducts = @{
  iOS     = "iOS"
  iPadOS  = "iPadOS"
  macOS   = "macOS"
  Android = "Android"
  Windows = "Windows"
}

# Retry policy
$RetryCount            = 3
$RetryDelaySeconds     = 3

# Enable verbose console logging
$VerboseLogging        = $true

# --------------------------- Helpers ---------------------------
function Get-GraphToken {
  param([string]$TenantId,[string]$ClientId,[string]$AuthMode,[string]$CertThumbprint,[string]$ClientSecret)
  $resourceScope = "https://graph.microsoft.com/.default"
  switch ($AuthMode) {
    "ManagedIdentity" {
      # Azure Automation managed identity authentication
      try {
        Import-Module Az.Accounts -ErrorAction Stop
        
        $connectParams = @{ Identity = $true; ErrorAction = 'Stop' }
        if ($UserAssignedClientId) { 
          $connectParams["AccountId"] = $UserAssignedClientId
        }
        
        $null = Connect-AzAccount @connectParams
        $tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/" -ErrorAction Stop
        
        if (-not $tokenObj -or -not $tokenObj.Token) {
          throw "Get-AzAccessToken returned no token"
        }
        
        $token = [System.Net.NetworkCredential]::new('', $tokenObj.Token).Password
      } catch {
        $errMsg = $_.Exception.Message
        throw "Managed Identity authentication failed: $errMsg. Ensure managed identity is enabled on the Automation Account and has Graph API permissions (DeviceManagementConfiguration.ReadWrite.All, DeviceManagementApps.ReadWrite.All, WindowsUpdates.ReadWrite.All)."
      }
    }
    "AppRegCert" {
      $cert = Get-ChildItem Cert:\CurrentUser\My\$CertThumbprint
      $assertion = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::WriteToken(
        (New-Object System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
          $ClientId,$resourceScope,(New-Object System.Collections.Generic.List[System.Security.Claims.Claim]),
          (Get-Date), (Get-Date).AddMinutes(10),
          (New-Object System.IdentityModel.Tokens.X509SigningCredentials($cert))))
      )
      $body = @{
        client_id             = $ClientId
        scope                 = $resourceScope
        client_assertion      = $assertion
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        grant_type            = "client_credentials"
      }
      $token = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded").access_token
    }
    "AppRegSecret" {
      if ($KeyVaultName -and $KeyVaultSecretName) {
        $ClientSecret = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretName -AsPlainText)
      }
      $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $resourceScope
        grant_type    = "client_credentials"
      }
      $token = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded").access_token
    }
    default { throw "Unsupported AuthMode $AuthMode" }
  }
  return $token
}

function Invoke-WithRetry {
  param([scriptblock]$Script,[int]$RetryCount,[int]$DelaySeconds)
  for ($i=0; $i -le $RetryCount; $i++) {
    try { return & $Script }
    catch {
      if ($i -eq $RetryCount) { throw }
      Start-Sleep -Seconds $DelaySeconds
    }
  }
}

function Write-Log {
  param([string]$Message,[string]$Level="INFO")
  if (-not $VerboseLogging) { return }
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[$ts][$Level] $Message"
}

function Write-ResultLog {
  param([psobject]$Row)
  if (-not $VerboseLogging) { return }
  $effective = $null
  if ($Row.PSObject.Properties.Name -contains "EffectiveDate") { $effective = $Row.EffectiveDate }
  $release = $null
  if ($Row.PSObject.Properties.Name -contains "ReleaseDate") { $release = $Row.ReleaseDate }
  $setting = $null
  if ($Row.PSObject.Properties.Name -contains "Setting") { $setting = $Row.Setting }
   $errorMsg = $null
   if ($Row.PSObject.Properties.Name -contains "Error") { $errorMsg = $Row.Error }
  $effText = if ($effective) { "; effective=$effective" } else { "" }
  $relText = if ($release) { "; release=$release" } else { "" }
  $settingText = if ($setting) { "; setting=$setting" } else { "" }
  $errorText = if ($errorMsg) { "; error=$errorMsg" } else { "" }
  $targetPatch = $null
  if ($Row.PSObject.Properties.Name -contains "TargetPatch") { $targetPatch = $Row.TargetPatch }
  $patchText = if ($targetPatch) { "; patch=$targetPatch" } else { "" }
  Write-Host "[RESULT][$($Row.Platform)/$($Row.Type)] $($Row.Name): action=$($Row.Action); current=$($Row.Current); target=$($Row.Target)$patchText$settingText$relText$effText$errorText"
}

function Get-CompliancePolicyInfo {
  param([string]$Token,[string]$PolicyId)
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers }
  $ranges = $null
  if ($policy.PSObject.Properties.Name -contains "validOperatingSystemBuildRanges") {
    $ranges = $policy.validOperatingSystemBuildRanges
  }
  $currentOs = $null
  if ($policy.PSObject.Properties.Name -contains "osMinimumVersion") {
    $currentOs = $policy.osMinimumVersion
  }
  $currentPatch = $null
  if ($policy.PSObject.Properties.Name -contains "minAndroidSecurityPatchLevel") {
    $currentPatch = $policy.minAndroidSecurityPatchLevel
  }
  return [pscustomobject]@{Name=$policy.displayName;Current=$currentOs;Ranges=$ranges;CurrentPatch=$currentPatch}
}

function Get-RangeText {
  param([object]$Ranges)
  if (-not $Ranges) { return "(none)" }
  $items = @()
  foreach ($r in @($Ranges)) {
    if (-not $r) { continue }
    $low = $null
    $high = $null
    if ($r.PSObject.Properties.Name -contains "lowestVersion") { $low = $r.lowestVersion }
    if ($r.PSObject.Properties.Name -contains "highestVersion") { $high = $r.highestVersion }
    if (-not $low -and ($r -is [System.Collections.IDictionary])) { $low = $r["lowestVersion"] }
    if (-not $high -and ($r -is [System.Collections.IDictionary])) { $high = $r["highestVersion"] }
    if (-not $low -or -not $high) { continue }
    $items += "$low-$high"
  }
  if ($items.Count -eq 0) { return "(none)" }
  return ($items -join ";")
}

function Get-AppProtectionPolicyInfo {
  param([string]$Token,[string]$PolicyId,[string]$Platform)
  $headers = @{Authorization = "Bearer $Token"}
  switch ($Platform) {
    "Android" { $uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections/$PolicyId" }
    "Windows" { $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections/$PolicyId" }
    "iOS"    { $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$PolicyId" }
    default   { $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$PolicyId" }
  }
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers }
  $current = $policy.minimumRequiredOsVersion
  if (-not $current -and ($policy.PSObject.Properties.Name -contains "minimumRequiredOSVersion")) {
    $current = $policy.minimumRequiredOSVersion
  }
  if (-not $current -and ($policy.PSObject.Properties.Name -contains "minimumRequiredOperatingSystem")) {
    $current = $policy.minimumRequiredOperatingSystem
  }
  $currentPatch = $null
  if ($policy.PSObject.Properties.Name -contains "minimumRequiredPatchVersion") {
    $currentPatch = $policy.minimumRequiredPatchVersion
  }
  return [pscustomobject]@{Name=$policy.displayName;Current=$current;CurrentPatch=$currentPatch}
}

function Get-LatestOsVersion {
  param([string]$ProductSlug,[int]$CadenceDays)
  $url = "https://endoflife.date/api/v1/products/$ProductSlug/releases/latest"
  $res = Invoke-RestMethod -Uri $url -Method Get
  $release = $res.result
  $targetVersion = if ($release.latest.name) { $release.latest.name } else { $release.name }
  # Use the date of the latest patch/hotfix release to drive cadence; fall back to major release date if missing.
  $dateSource = $release.latest.date
  if (-not $dateSource) { $dateSource = $release.releaseDate }
  $releaseDate = [datetime]::Parse($dateSource)
  $effectiveDate = $releaseDate.AddDays($CadenceDays)
  return [pscustomobject]@{
    Version       = $targetVersion
    ReleaseDate   = $releaseDate
    EffectiveDate = $effectiveDate
  }
}

function Get-AndroidVersionData {
  param([int]$CadenceDays)
  # Fetch all Android releases and filter to maintained (non-EOL) ones only.
  $url = "https://endoflife.date/api/v1/products/android/"
  $res = Invoke-RestMethod -Uri $url -Method Get
  $maintained = @($res.result.releases | Where-Object { $_.isMaintained -eq $true })
  if (-not $maintained -or $maintained.Count -eq 0) {
    throw "No maintained Android releases found from endoflife.date"
  }
  # Sort numerically so the oldest maintained version can be selected reliably.
  $sorted = $maintained | Sort-Object { [System.Version]"$($_.name).0" }
  $oldest = $sorted | Select-Object -First 1
  # Android releases a security patch on the 1st of every month. Use the 1st of
  # the current month as the patch release date and apply cadence from there,
  # consistent with how all other platform releases are treated.
  $today = Get-Date
  $patchReleaseDate = (Get-Date -Year $today.Year -Month $today.Month -Day 1).Date
  $effectiveDate = $patchReleaseDate.AddDays($CadenceDays)
  return [pscustomobject]@{
    Version       = $oldest.name                                    # oldest maintained → osMinimumVersion
    PatchDate     = $patchReleaseDate.ToString("yyyy-MM-dd")        # 1st of current month → patch level
    ReleaseDate   = $patchReleaseDate
    EffectiveDate = $effectiveDate
  }
}

function Get-WindowsBuildRanges {
  param(
    [string]$Token,
    [string[]]$BuildNumbers,
    [string]$Classification,
    [int]$NumberOfUpdates,
    [bool]$AllowNewerBuilds,
    [int]$CadenceDays
  )

  $headers = @{Authorization = "Bearer $Token"}
  if (-not $Classification) { $Classification = "nonSecurity" }
  if ($NumberOfUpdates -le 0) { $NumberOfUpdates = 1 }
  $filter = "`$filter=microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/qualityUpdateClassification eq '$Classification'&"
  $uri = "https://graph.microsoft.com/beta/admin/windows/updates/catalog/entries?`$select=microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/productRevisions&`$expand=microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/productRevisions&${filter}`$orderby=releaseDateTime%20desc&`$top=$NumberOfUpdates"
  $response = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
    Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
  }

  $entries = @()
  if ($response.value) { $entries = $response.value }

  $revisions = @()
  foreach ($entry in $entries) {
    $rev = $entry.'microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/productRevisions'
    if (-not $rev) { $rev = $entry.productRevisions }
    if ($rev) { $revisions += $rev }
  }

  $ranges = @()
  $effectiveDates = @()
  $releaseDates = @()

  foreach ($build in $BuildNumbers) {
    $versions = $revisions | Where-Object { ($_.'id' -match "^10\.0\.$build") -or ($_.Id -match "^10\.0\.$build") } | Sort-Object -Property releaseDateTime
    if (-not $versions) { continue }

    $highest = $versions[-1]
    $lowest = $versions[0]
    if (-not $highest -or -not $lowest) { continue }

    $releaseDate = [datetime]$highest.releaseDateTime
    $releaseDates += $releaseDate
    $effectiveDates += $releaseDate.AddDays($CadenceDays)

    $lowestId = $lowest.id; if (-not $lowestId) { $lowestId = $lowest.Id }
    $highestId = $highest.id; if (-not $highestId) { $highestId = $highest.Id }
    if (-not $lowestId -or -not $highestId) { continue }

    # Determine highest version based on AllowNewerBuilds setting
    $highestVer = if ($AllowNewerBuilds) { "10.0.$build.9999" } else { $highestId.ToString() }

    $range = @{
      "@odata.type"  = "microsoft.graph.operatingSystemVersionRange"
      "description"  = "$($highest.product) - $($highest.version)"
      "lowestVersion" = $lowestId.ToString()
      "highestVersion" = $highestVer
    }
    $ranges += $range
  }

  $effectiveDate = $null
  if ($effectiveDates.Count -gt 0) {
    $effectiveDate = ($effectiveDates | Sort-Object)[-1]
  }

  $releaseDateAll = $null
  if ($releaseDates.Count -gt 0) {
    $releaseDateAll = ($releaseDates | Sort-Object)[-1]
  }

  return [pscustomobject]@{
    Ranges        = $ranges
    ReleaseDate   = $releaseDateAll
    EffectiveDate = $effectiveDate
  }
}

function Get-WindowsTargetVersionFromRanges {
  param(
    [array]$Ranges,
    [string]$Mode # HighestHighest | HighestLowest
  )
  if (-not $Ranges -or $Ranges.Count -eq 0) { return $null }
  switch ($Mode) {
    "LowestLowest"  { return ($Ranges | ForEach-Object { $_.lowestVersion } | Sort-Object | Select-Object -First 1) }
    "HighestLowest" { return ($Ranges | ForEach-Object { $_.lowestVersion } | Sort-Object -Descending | Select-Object -First 1) }
    default         { return ($Ranges | ForEach-Object { $_.highestVersion } | Sort-Object -Descending | Select-Object -First 1) }
  }
}

function Update-CompliancePolicy {
  param([string]$Token,[string]$PolicyId,[string]$TargetVersion,[bool]$DryRun,[bool]$AllowDowngrade,[string]$Platform,[datetime]$ReleaseDate,[string]$PatchLevel)
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers }
  $name = $policy.displayName
  $current = $policy.osMinimumVersion
  $currentPatch = $policy.minAndroidSecurityPatchLevel
  $detectedPlatform = $Platform
  if (-not $detectedPlatform) {
    $rawType = $policy.'@odata.type'
    if ($rawType -match "\.([A-Za-z]+)CompliancePolicy$") { $detectedPlatform = $matches[1] }
  }
  if ($detectedPlatform -eq "macOS") { $detectedPlatform = "macOS" }
  # Skip only when both OS version and patch level (if applicable) are already current.
  $osUpToDate = $current -and ([version]$current -ge [version]$TargetVersion)
  $patchUpToDate = -not $PatchLevel -or ($currentPatch -and ($currentPatch -ge $PatchLevel))
  if (-not $AllowDowngrade -and $osUpToDate -and $patchUpToDate) {
    return [pscustomobject]@{Platform=$detectedPlatform;Type="Compliance";Setting="MinimumVersion";Name=$name;Current=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;Action="Skipped";TargetPatch=$PatchLevel;CurrentPatch=$currentPatch}
  }
  if ($DryRun) {
    return [pscustomobject]@{Platform=$detectedPlatform;Type="Compliance";Setting="MinimumVersion";Name=$name;Current=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;Action="WouldUpdate";TargetPatch=$PatchLevel;CurrentPatch=$currentPatch}
  }
  try {
    $body = @{
      "@odata.type" = $policy.'@odata.type'
      "osMinimumVersion" = "$TargetVersion"
    }
    if ($detectedPlatform -eq "Android" -and $PatchLevel) {
      $body["minAndroidSecurityPatchLevel"] = $PatchLevel
    }
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json)
    }
    return [pscustomobject]@{Platform=$detectedPlatform;Type="Compliance";Setting="MinimumVersion";Name=$name;Current=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;Action="Updated";TargetPatch=$PatchLevel;CurrentPatch=$currentPatch}
  }
  catch {
    $errMsg = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = $_.ErrorDetails.Message }
    elseif ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = $_.Exception.Response.Content }
    return [pscustomobject]@{Platform=$detectedPlatform;Type="Compliance";Setting="MinimumVersion";Name=$name;Current=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;Action="Error";Error=$errMsg;TargetPatch=$PatchLevel;CurrentPatch=$currentPatch}
  }
}

function Update-WindowsCompliancePolicy {
  param(
    [string]$Token,
    [string]$PolicyId,
    [array]$Ranges,
    [bool]$DryRun,
    [datetime]$ReleaseDate
  )
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers }
  $name = $policy.displayName
  $currentRanges = $policy.validOperatingSystemBuildRanges
  $currentText = Get-RangeText -Ranges $currentRanges
  $targetText = Get-RangeText -Ranges $Ranges

  if ($DryRun) {
    return [pscustomobject]@{Platform="Windows";Type="Compliance";Setting="Range";Name=$name;Current=$currentText;Target=$targetText;ReleaseDate=$ReleaseDate;Action="WouldUpdate"}
  }

  $body = @{
    "@odata.type" = "#microsoft.graph.windows10CompliancePolicy"
    "validOperatingSystemBuildRanges" = $Ranges
  }

  try {
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 6)
    }
    return [pscustomobject]@{Platform="Windows";Type="Compliance";Setting="Range";Name=$name;Current=$currentText;Target=$targetText;ReleaseDate=$ReleaseDate;Action="Updated"}
  }
  catch {
    $errMsg = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = $_.ErrorDetails.Message }
    elseif ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = $_.Exception.Response.Content }
    return [pscustomobject]@{Platform="Windows";Type="Compliance";Setting="Range";Name=$name;Current=$currentText;Target=$targetText;ReleaseDate=$ReleaseDate;Action="Error";Error=$errMsg}
  }
}

function Update-AppProtectionPolicy {
  param([string]$Token,[string]$PolicyId,[string]$TargetVersion,[bool]$DryRun,[bool]$AllowDowngrade,[string]$Platform,[datetime]$ReleaseDate,[datetime]$EffectiveDate,[string]$PatchLevel)
  $headers = @{Authorization = "Bearer $Token"}
  switch ($Platform) {
    "Android" { $uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections/$PolicyId" }
    "Windows" { $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections/$PolicyId" }
    default    { $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$PolicyId" }
  }
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers }
  $name = $policy.displayName
  $current = $policy.minimumRequiredOsVersion
  $currentPatch = if ($Platform -eq "Android") { $policy.minimumRequiredPatchVersion } else { $null }
  # Skip only when both OS version and patch level (if applicable) are already current.
  $osUpToDate = $current -and ([version]$current -ge [version]$TargetVersion)
  $patchUpToDate = -not $PatchLevel -or ($currentPatch -and ($currentPatch -ge $PatchLevel))
  if (-not $AllowDowngrade -and $osUpToDate -and $patchUpToDate) {
    return [pscustomobject]@{Platform=$Platform;Type="AppProtection";Setting="MinimumVersion";Name=$name;Current=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;EffectiveDate=$EffectiveDate;Action="Skipped";TargetPatch=$PatchLevel;CurrentPatch=$currentPatch}
  }
  if ($DryRun) {
    return [pscustomobject]@{Platform=$Platform;Type="AppProtection";Setting="MinimumVersion";Name=$name;Current=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;EffectiveDate=$EffectiveDate;Action="WouldUpdate";TargetPatch=$PatchLevel;CurrentPatch=$currentPatch}
  }
  try {
    $body = @{ minimumRequiredOsVersion = $TargetVersion }
    if ($Platform -eq "Android" -and $PatchLevel) {
      $body["minimumRequiredPatchVersion"] = $PatchLevel
    }
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json)
    }
    return [pscustomobject]@{Platform=$Platform;Type="AppProtection";Setting="MinimumVersion";Name=$name;Current=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;EffectiveDate=$EffectiveDate;Action="Updated";TargetPatch=$PatchLevel;CurrentPatch=$currentPatch}
  }
  catch {
    $errMsg = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = $_.ErrorDetails.Message }
    elseif ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = $_.Exception.Response.Content }
    return [pscustomobject]@{Platform=$Platform;Type="AppProtection";Setting="MinimumVersion";Name=$name;Current=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;EffectiveDate=$EffectiveDate;Action="Error";Error=$errMsg;TargetPatch=$PatchLevel;CurrentPatch=$currentPatch}
  }
}

# --------------------------- Main ---------------------------
Write-Output "========================================="
Write-Output "IntuneComplianceMaintainer Starting"
Write-Output "========================================="
Write-Output "AuthMode: $AuthMode"
Write-Output "DryRun: $DryRun"
Write-Output "CadenceDays: $CadenceDays"
Write-Output "========================================="

$token = $null
try {
  Write-Output "[MAIN] Attempting to acquire Graph API token..."
  $token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -AuthMode $AuthMode -CertThumbprint $CertThumbprint -ClientSecret $ClientSecret
  Write-Output "[MAIN] Token acquired successfully"
} catch {
  Write-Output "[MAIN][CRITICAL ERROR] Failed to acquire token!"
  Write-Output "[MAIN][ERROR] Exception: $($_.Exception.Message)"
  Write-Output "[MAIN][ERROR] Stack: $($_.ScriptStackTrace)"
  throw
}

$now = Get-Date
$results = @()

Write-Log "Starting run: DryRun=$DryRun; AllowDowngrade=$AllowDowngrade; ForceApply=$ForceApply; WindowsComplianceMode=$WindowsComplianceMode; CadenceDays=$CadenceDays"

foreach ($platform in $EolProducts.Keys) {
  $hasCompliance = $CompliancePolicies[$platform] -and $CompliancePolicies[$platform].Count -gt 0
  $hasAppProtect = $AppProtectionPolicies[$platform] -and $AppProtectionPolicies[$platform].Count -gt 0
  if (-not ($hasCompliance -or $hasAppProtect)) { continue }

  Write-Log "Platform ${platform}: compliance=$($CompliancePolicies[$platform].Count) appProtection=$($AppProtectionPolicies[$platform].Count)" "INFO"

  $latest = $null
  $notEffectiveCompliance = $false
  $appLatest = $null
  $notEffectiveApp = $false
  $winData = $null

  if ($platform -eq "Windows" -and ($hasCompliance -or $hasAppProtect)) {
    $winData = Get-WindowsBuildRanges -Token $token -BuildNumbers $WindowsBuildNumbers -Classification $WindowsUpdateClassification -NumberOfUpdates $WindowsNumberOfUpdates -AllowNewerBuilds ([bool]$WindowsAllowNewerBuilds) -CadenceDays $CadenceDays
  }

  if ($platform -eq "Windows" -and $hasCompliance) {
    $notEffectiveCompliance = $winData.EffectiveDate -and ($now -lt $winData.EffectiveDate)
  } elseif ($platform -eq "Android") {
    $latest = Get-AndroidVersionData -CadenceDays $CadenceDays
    $notEffectiveCompliance = $now -lt $latest.EffectiveDate
  } else {
    $latest = Get-LatestOsVersion -ProductSlug $EolProducts[$platform] -CadenceDays $CadenceDays
    $notEffectiveCompliance = $now -lt $latest.EffectiveDate
  }

  if ($hasAppProtect) {
    if ($platform -eq "Windows") {
      $notEffectiveApp = $winData.EffectiveDate -and ($now -lt $winData.EffectiveDate)
    } elseif ($platform -eq "Android") {
      $appLatest = if ($latest) { $latest } else { Get-AndroidVersionData -CadenceDays $CadenceDays }
      $notEffectiveApp = $now -lt $appLatest.EffectiveDate
    } else {
      $appLatest = Get-LatestOsVersion -ProductSlug $EolProducts[$platform] -CadenceDays $CadenceDays
      $notEffectiveApp = $now -lt $appLatest.EffectiveDate
    }
  }

  foreach ($policyId in $CompliancePolicies[$platform]) {
    if ($platform -eq "Windows") {
      $info = Get-CompliancePolicyInfo -Token $token -PolicyId $policyId
      if ($WindowsComplianceMode -eq "MinimumVersion") {
        $winMinVersion = Get-WindowsTargetVersionFromRanges -Ranges $winData.Ranges -Mode "HighestLowest"
        $targetText = $winMinVersion
        $currentText = if ($info.Current) { $info.Current } else { Get-RangeText -Ranges $info.Ranges }

        if ($notEffectiveCompliance -and -not $ForceApply) {
          $results += [pscustomobject]@{Platform=$platform;Type="Compliance";Setting=$WindowsComplianceMode;Name=$info.Name;Current=$currentText;Target=$targetText;ReleaseDate=$winData.ReleaseDate;Action="NotEffectiveYet";EffectiveDate=$winData.EffectiveDate}
          continue
        }
        if (-not $winMinVersion) {
          $results += [pscustomobject]@{Platform=$platform;Type="Compliance";Setting=$WindowsComplianceMode;Name=$info.Name;Current=$currentText;Target="(none)";ReleaseDate=$winData.ReleaseDate;Action="NoData";EffectiveDate=$winData.EffectiveDate}
          continue
        }
        $results += Update-CompliancePolicy -Token $token -PolicyId $policyId -TargetVersion $winMinVersion -DryRun $DryRun -AllowDowngrade $AllowDowngrade -Platform $platform -ReleaseDate $winData.ReleaseDate
      } else {
        # Ranges mode
        $targetText = Get-RangeText -Ranges $winData.Ranges
        $currentText = Get-RangeText -Ranges $info.Ranges

        if ($notEffectiveCompliance -and -not $ForceApply) {
          $results += [pscustomobject]@{Platform=$platform;Type="Compliance";Setting=$WindowsComplianceMode;Name=$info.Name;Current=$currentText;Target=$targetText;ReleaseDate=$winData.ReleaseDate;Action="NotEffectiveYet";EffectiveDate=$winData.EffectiveDate}
          continue
        }
        if (-not $winData.Ranges -or $winData.Ranges.Count -eq 0) {
          $results += [pscustomobject]@{Platform=$platform;Type="Compliance";Setting=$WindowsComplianceMode;Name=$info.Name;Current=$currentText;Target="(none)";ReleaseDate=$winData.ReleaseDate;Action="NoData";EffectiveDate=$winData.EffectiveDate}
          continue
        }
        $results += Update-WindowsCompliancePolicy -Token $token -PolicyId $policyId -Ranges $winData.Ranges -DryRun $DryRun -ReleaseDate $winData.ReleaseDate
      }
      continue
    }

    if ($notEffectiveCompliance) {
      $info = Get-CompliancePolicyInfo -Token $token -PolicyId $policyId
      if (-not $ForceApply) {
        $results += [pscustomobject]@{Platform=$platform;Type="Compliance";Setting="MinimumVersion";Name=$info.Name;Current=$info.Current;Target=$latest.Version;ReleaseDate=$latest.ReleaseDate;Action="NotEffectiveYet";EffectiveDate=$latest.EffectiveDate;TargetPatch=$latest.PatchDate;CurrentPatch=$info.CurrentPatch}
        continue
      }
    }
    $results += Update-CompliancePolicy -Token $token -PolicyId $policyId -TargetVersion $latest.Version -DryRun $DryRun -AllowDowngrade $AllowDowngrade -Platform $platform -ReleaseDate $latest.ReleaseDate -PatchLevel $latest.PatchDate
  }
  foreach ($policyId in $AppProtectionPolicies[$platform]) {
    if ($platform -eq "Windows") {
      $effective = $winData.EffectiveDate
      $releaseDate = $winData.ReleaseDate
      $targetVersion = $null
      if ($winData -and $winData.Ranges -and $winData.Ranges.Count -gt 0) {
        $appTargetMode = if ($WindowsAppProtectionTarget -eq "Highest") { "HighestHighest" } else { "LowestLowest" }
        $targetVersion = Get-WindowsTargetVersionFromRanges -Ranges $winData.Ranges -Mode $appTargetMode
      }
      if (-not $winData -or -not $winData.Ranges -or $winData.Ranges.Count -eq 0 -or -not $targetVersion) {
        $results += [pscustomobject]@{Platform=$platform;Type="AppProtection";Setting="MinimumVersion";Name=$policyId;Current="(unknown)";Target="(none)";ReleaseDate=$releaseDate;Action="NoData";EffectiveDate=$effective}
        continue
      }
      # Check cadence before making any API calls; fetch info only when needed for the
      # NotEffectiveYet display name, with a graceful fallback to the policy ID.
      if ($notEffectiveApp -and -not $ForceApply) {
        $policyName = $policyId
        try { $policyName = (Get-AppProtectionPolicyInfo -Token $token -PolicyId $policyId -Platform $platform).Name } catch {}
        $results += [pscustomobject]@{Platform=$platform;Type="AppProtection";Setting="MinimumVersion";Name=$policyName;Current="(unknown)";Target=$targetVersion;ReleaseDate=$releaseDate;Action="NotEffectiveYet";EffectiveDate=$effective}
        continue
      }
      $results += Update-AppProtectionPolicy -Token $token -PolicyId $policyId -TargetVersion $targetVersion -DryRun $DryRun -AllowDowngrade $AllowDowngrade -Platform $platform -ReleaseDate $releaseDate -EffectiveDate $effective
      continue
    }

    if ($notEffectiveApp -and -not $ForceApply) {
      $info = Get-AppProtectionPolicyInfo -Token $token -PolicyId $policyId -Platform $platform
      $results += [pscustomobject]@{Platform=$platform;Type="AppProtection";Setting="MinimumVersion";Name=$info.Name;Current=$info.Current;Target=$appLatest.Version;ReleaseDate=$appLatest.ReleaseDate;Action="NotEffectiveYet";EffectiveDate=$appLatest.EffectiveDate;TargetPatch=$appLatest.PatchDate;CurrentPatch=$info.CurrentPatch}
      continue
    }
    $results += Update-AppProtectionPolicy -Token $token -PolicyId $policyId -TargetVersion $appLatest.Version -DryRun $DryRun -AllowDowngrade $AllowDowngrade -Platform $platform -ReleaseDate $appLatest.ReleaseDate -EffectiveDate $appLatest.EffectiveDate -PatchLevel $appLatest.PatchDate
  }
}

if ($VerboseLogging) {
  foreach ($row in $results) { Write-ResultLog -Row $row }
  Write-Host ""
}

Write-Output "[MAIN] Displaying results table..."
$results | Format-Table -AutoSize
Write-Output "[MAIN] Script completed successfully"