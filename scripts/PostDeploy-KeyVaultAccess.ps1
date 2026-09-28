[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

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

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'az is required.'
}

$subscriptionId = $env:AZURE_SUBSCRIPTION_ID
$identityId = $env:KEYVAULTSYNC_IDENTITY_RESOURCE_ID
if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
    throw 'AZURE_SUBSCRIPTION_ID was not provided by azd.'
}
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

Write-Host @'

KeyVaultSync vault access is not granted automatically.

Before continuing, tag every source vault you want KeyVaultSync to discover:
  Tag name:  sync-vault-id
  Tag value: the target vault's full ARM resource ID

Example value:
  /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.KeyVault/vaults/<target-vault>

Source and target must be in this deployment's subscription. Do not put the
sync-vault-id tag on a target vault. Set KeyVaultSyncDisabled=true on either
vault to keep that pair disabled. Verify every mapping before granting access.
'@

if (-not (Confirm-Step 'Have you finished tagging the source vaults and want to preview access for every enabled pair?')) {
    Write-Host 'Skipped Key Vault access onboarding. You can rerun it with: azd hooks run postdeploy'
    return
}

$vaultJson = & az keyvault list --subscription $subscriptionId --resource-type vault --only-show-errors --output json
if ($LASTEXITCODE -ne 0) {
    throw "Key Vault discovery failed with Azure CLI exit code $LASTEXITCODE."
}
$vaults = @(ConvertFrom-Json -InputObject ($vaultJson -join [Environment]::NewLine) -Depth 100)
$sources = @(
    $vaults |
        ForEach-Object {
            $vault = $_
            $targetTag = @($vault.tags.PSObject.Properties | Where-Object Name -IEQ 'sync-vault-id' | Select-Object -First 1)
            $disabledTag = @($vault.tags.PSObject.Properties | Where-Object Name -IEQ 'KeyVaultSyncDisabled' | Select-Object -First 1)
            $target = if ($targetTag.Count -eq 1 -and $targetTag[0].Value -is [string]) { $targetTag[0].Value.Trim() } else { '' }
            $disabled = if ($disabledTag.Count -eq 1 -and $disabledTag[0].Value -is [string]) { $disabledTag[0].Value } else { '' }
            $targetVault = @($vaults | Where-Object id -IEQ $target | Select-Object -First 1)
            $targetDisabledTag = if ($targetVault.Count -eq 1) {
                @($targetVault[0].tags.PSObject.Properties | Where-Object Name -IEQ 'KeyVaultSyncDisabled' | Select-Object -First 1)
            }
            else {
                @()
            }
            $targetDisabled = if ($targetDisabledTag.Count -eq 1 -and $targetDisabledTag[0].Value -is [string]) {
                $targetDisabledTag[0].Value
            }
            else {
                ''
            }
            if (-not [string]::IsNullOrWhiteSpace($target) -and $disabled -ine 'true' -and $targetDisabled -ine 'true') {
                [pscustomobject]@{ Id = $vault.id; Name = $vault.name; Target = $target }
            }
        } |
        Sort-Object Id
)

if ($sources.Count -eq 0) {
    Write-Host "No enabled source vaults with a non-empty sync-vault-id tag were found in subscription $subscriptionId."
    return
}

Write-Host "`nFound $($sources.Count) enabled source vault(s):"
foreach ($source in $sources) {
    Write-Host "  $($source.Name)`n    source: $($source.Id)`n    target: $($source.Target)"
}
Write-Host "`nPreflighting every pair; this phase performs reads only."

foreach ($source in $sources) {
    & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $source.Id
}

Write-Host "`nAll pair previews completed without writes."
if (-not (Confirm-Step "Apply the displayed access grants for all $($sources.Count) enabled source vault(s)?")) {
    Write-Host 'Skipped Key Vault access changes.'
    return
}

Write-Host 'Applying reviewed grants. A failure can leave earlier pairs applied; rerun to converge safely.'
foreach ($source in $sources) {
    & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $source.Id -Apply -Confirm:$false
}

Write-Host "Key Vault access onboarding completed for $($sources.Count) source vault(s)."
