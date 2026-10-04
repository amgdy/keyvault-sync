[CmdletBinding()]
<#
.SYNOPSIS
Coordinates optional interactive postdeploy onboarding for all enabled target-declared mappings.
.DESCRIPTION
The script discovers vaults across configured subscriptions, previews every pair through
Grant-KeyVaultAccess.ps1, and asks once before applying. Non-interactive azd runs skip it.
If a later pair fails, earlier applied assignments are retained and a rerun converges safely.
#>
param()

$ErrorActionPreference = 'Stop'

# Ask an interactive question whose empty response means no.
function Confirm-Step {
    param([Parameter(Mandatory = $true)][string] $Prompt)
    try {
        $answer = Read-Host "$Prompt [y/N]"
    }
    catch {
        Write-Host 'No interactive response was available; vault access was not changed.'
        return $false
    }
    return $answer -in @('y', 'Y', 'yes', 'YES')
}

# Read one case-insensitive string tag from a discovered vault object.
function Get-TagValue {
    param($Resource, [string] $Name)
    if ($null -eq $Resource.tags) { return $null }
    $property = $Resource.tags.PSObject.Properties |
        Where-Object Name -IEQ $Name |
        Select-Object -First 1
    if ($null -eq $property -or $property.Value -isnot [string]) { return $null }
    $value = $property.Value.Trim()
    return $(if ([string]::IsNullOrWhiteSpace($value)) { $null } else { $value })
}

# Split a Key Vault ARM resource ID into the display columns of the discovery table.
function New-TableRow {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Pair,
        [Parameter(Mandatory = $true)][string] $Role,
        [Parameter(Mandatory = $true)][string] $ResourceId,
        [string] $FallbackName = ''
    )
    $subscription = if ($ResourceId -match '/subscriptions/([^/]+)') { $Matches[1] } else { '' }
    $group = if ($ResourceId -match '/resourceGroups/([^/]+)') { $Matches[1] } else { '' }
    $vault = if ($ResourceId -match '/providers/[^/]+/vaults/([^/]+)') { $Matches[1] } else { $FallbackName }
    return [pscustomobject][ordered]@{
        '#' = $Pair
        'Role' = $Role
        'Subscription' = $subscription
        'Resource Group' = $group
        'Key Vault' = $vault
    }
}

# Validate azd outputs before discovering any vaults.
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'az is required.'
}

$subscriptions = if (-not [string]::IsNullOrWhiteSpace($env:KEYVAULTSYNC_SUBSCRIPTIONS)) {
    @($env:KEYVAULTSYNC_SUBSCRIPTIONS -split '[,;\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}
elseif (-not [string]::IsNullOrWhiteSpace($env:AZURE_SUBSCRIPTION_ID)) {
    @($env:AZURE_SUBSCRIPTION_ID)
}
else {
    throw 'KEYVAULTSYNC_SUBSCRIPTIONS was not provided by azd.'
}
$identityId = $env:KEYVAULTSYNC_IDENTITY_RESOURCE_ID
if ([string]::IsNullOrWhiteSpace($identityId)) {
    throw 'KEYVAULTSYNC_IDENTITY_RESOURCE_ID was not provided by the deployment outputs.'
}
if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
    Write-Host 'Skipping optional Key Vault access onboarding because azd is running non-interactively.'
    return
}

$grantScript = Join-Path $PSScriptRoot 'Grant-KeyVaultAccess.ps1'
if (-not (Test-Path -LiteralPath $grantScript -PathType Leaf)) {
    throw "Grant script was not found: $grantScript"
}

# Explain the target-owned mapping contract before the operator approves discovery.
Write-Host @'

KeyVaultSync vault access is not granted automatically.

Declare each pair on its target vault:
  sync-source-keyvault-id=<source vault's full ARM resource ID>

Source and target may be in different configured subscriptions, but must use
Azure RBAC and the same tenant. Set KeyVaultSyncDisabled=true on either vault
to keep the pair disabled.
'@

if (-not (Confirm-Step 'Have you finished tagging target vaults and want to preview access for every enabled pair?')) {
    Write-Host 'Skipped Key Vault access onboarding. You can rerun it with: azd hooks run postdeploy'
    return
}

# Discover value-free Key Vault ARM metadata from every configured subscription.
$vaults = [System.Collections.Generic.List[object]]::new()
foreach ($subscription in $subscriptions) {
    $json = & az keyvault list --subscription $subscription --resource-type vault --only-show-errors --output json
    if ($LASTEXITCODE -ne 0) {
        throw "Key Vault discovery failed for subscription $subscription with Azure CLI exit code $LASTEXITCODE."
    }
    foreach ($vault in @(ConvertFrom-Json -InputObject ($json -join [Environment]::NewLine) -Depth 100)) {
        [void] $vaults.Add($vault)
    }
}

# Convert discovered target tags into a stable, deduplicated mapping list.
$targets = @(
    $vaults |
        ForEach-Object {
            $sourceId = Get-TagValue $_ 'sync-source-keyvault-id'
            $disabled = Get-TagValue $_ 'KeyVaultSyncDisabled'
            if (-not [string]::IsNullOrWhiteSpace($sourceId) -and $disabled -ine 'true') {
                [pscustomobject]@{ Id = $_.id; Name = $_.name; SourceId = $sourceId }
            }
        } |
        Sort-Object Id -Unique
)

if ($targets.Count -eq 0) {
    Write-Host 'No enabled target-declared sync mappings were found in the configured subscriptions.'
    return
}

# Render the discovered mappings as an aligned table so the operator can review the
# subscription, resource group, and vault name of both sides before approving any write.
Write-Host "`nFound $($targets.Count) enabled mapping pair(s):`n"
$rows = [System.Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt $targets.Count; $index++) {
    $target = $targets[$index]
    [void] $rows.Add((New-TableRow -Pair ($index + 1) -Role 'source' -ResourceId $target.SourceId))
    [void] $rows.Add((New-TableRow -Pair '' -Role 'target' -ResourceId $target.Id -FallbackName $target.Name))
}
Write-Host (($rows | Format-Table -AutoSize | Out-String -Width 500).Trim())
Write-Host "`nPreflighting every pair; this phase performs reads only."

# Preview every pair first; no IAM write occurs in this phase.
foreach ($target in $targets) {
    & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $target.Id
}

Write-Host "`nAll pair previews completed without writes."
if (-not (Confirm-Step "Apply the displayed access grants for all $($targets.Count) mapping(s)?")) {
    Write-Host 'Skipped Key Vault access changes.'
    return
}

# Apply the already reviewed pairs sequentially. Rerunning is safe if a later pair fails.
Write-Host 'Applying reviewed grants. A failure can leave earlier pairs applied; rerun to converge safely.'
foreach ($target in $targets) {
    & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $target.Id -Apply -Confirm:$false
}

Write-Host "Key Vault access onboarding completed for $($targets.Count) mapping(s)."
