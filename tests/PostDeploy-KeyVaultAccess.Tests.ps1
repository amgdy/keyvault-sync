$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )

    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$fixtureDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "keyvaultsync-postdeploy-$([guid]::NewGuid())"
$fixtureScripts = Join-Path $fixtureDirectory 'scripts'
$script:grantLog = Join-Path $fixtureDirectory 'grants.jsonl'
New-Item -ItemType Directory -Path $fixtureScripts -Force | Out-Null
Copy-Item (Join-Path $repositoryRoot 'scripts/PostDeploy-KeyVaultAccess.ps1') $fixtureScripts

@'
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $IdentityResourceId,
    [string] $SourceVaultResourceId,
    [switch] $Apply
)
@{
    identity = $IdentityResourceId
    source = $SourceVaultResourceId
    apply = $Apply.IsPresent
} | ConvertTo-Json -Compress | Add-Content -LiteralPath $env:KEYVAULTSYNC_TEST_GRANT_LOG
if ($env:KEYVAULTSYNC_TEST_PREVIEW_FAILURE -eq 'true' -and -not $Apply) {
    throw 'Mock preview failure.'
}
'@ | Set-Content -LiteralPath (Join-Path $fixtureScripts 'Grant-KeyVaultAccess.ps1')

$subscriptionId = '11111111-1111-1111-1111-111111111111'
$sourceOne = "/subscriptions/$subscriptionId/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-one"
$sourceTwo = "/subscriptions/$subscriptionId/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-two"
$targetOne = "/subscriptions/$subscriptionId/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-one"
$targetTwo = "/subscriptions/$subscriptionId/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-two"
$global:KeyVaultSyncTestVaults = @(
    [pscustomobject]@{ id = $sourceOne; name = 'source-one'; tags = [pscustomobject]@{ 'sync-vault-id' = $targetOne } }
    [pscustomobject]@{ id = $sourceTwo; name = 'source-two'; tags = [pscustomobject]@{ 'SYNC-VAULT-ID' = $targetTwo } }
    [pscustomobject]@{
        id = "/subscriptions/$subscriptionId/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-disabled"
        name = 'source-disabled'
        tags = [pscustomobject]@{ 'sync-vault-id' = $targetOne; KeyVaultSyncDisabled = 'TRUE' }
    }
    [pscustomobject]@{
        id = "/subscriptions/$subscriptionId/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-target-disabled"
        name = 'source-target-disabled'
        tags = [pscustomobject]@{ 'sync-vault-id' = "$targetTwo-disabled" }
    }
    [pscustomobject]@{ id = $targetOne; name = 'target-one'; tags = [pscustomobject]@{} }
    [pscustomobject]@{ id = $targetTwo; name = 'target-two'; tags = [pscustomobject]@{} }
    [pscustomobject]@{ id = "$targetTwo-disabled"; name = 'target-disabled'; tags = [pscustomobject]@{ KeyVaultSyncDisabled = 'true' } }
)
$global:KeyVaultSyncTestAnswers = [System.Collections.Generic.Queue[string]]::new()

function global:az {
    $global:LASTEXITCODE = 0
    if ("$($args[0]) $($args[1])" -ne 'keyvault list') {
        $global:LASTEXITCODE = 99
        return
    }
    return ($global:KeyVaultSyncTestVaults | ConvertTo-Json -Depth 20)
}

function global:Read-Host {
    param([string] $Prompt)
    if ($global:KeyVaultSyncTestAnswers.Count -eq 0) {
        return ''
    }
    return $global:KeyVaultSyncTestAnswers.Dequeue()
}

function Invoke-Hook {
    param([string[]] $Answers)

    $global:KeyVaultSyncTestAnswers.Clear()
    foreach ($answer in $Answers) {
        $global:KeyVaultSyncTestAnswers.Enqueue($answer)
    }
    & (Join-Path $fixtureScripts 'PostDeploy-KeyVaultAccess.ps1') 6>&1
}

try {
    $env:AZURE_SUBSCRIPTION_ID = $subscriptionId
    $env:KEYVAULTSYNC_IDENTITY_RESOURCE_ID = "/subscriptions/$subscriptionId/resourceGroups/identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/keyvaultsync"
    $env:KEYVAULTSYNC_TEST_GRANT_LOG = $script:grantLog
    $env:KEYVAULTSYNC_TEST_PREVIEW_FAILURE = 'false'

    Set-Content -LiteralPath $script:grantLog -Value ''
    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @() | Out-Null
    Assert-True ((Get-Content $script:grantLog | Where-Object { $_ }).Count -eq 0) 'non-interactive mode must perform no pair calls'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Write-Host 'PASS PowerShell non-interactive azd mode skips onboarding without reads or writes'

    Set-Content -LiteralPath $script:grantLog -Value ''
    Invoke-Hook -Answers @('n') | Out-Null
    Assert-True ((Get-Content $script:grantLog | Where-Object { $_ }).Count -eq 0) 'declining the first prompt must perform no pair calls'
    Write-Host 'PASS PowerShell declining tag confirmation performs no pair previews or writes'

    Set-Content -LiteralPath $script:grantLog -Value ''
    $hookOutput = Invoke-Hook -Answers @('y', 'n') | Out-String
    $calls = @(Get-Content $script:grantLog | Where-Object { $_ } | ForEach-Object { ConvertFrom-Json $_ })
    Assert-True ($calls.Count -eq 2) "both enabled tagged sources should be previewed; captured $($calls.Count): $($calls | ConvertTo-Json -Compress); output: $hookOutput"
    Assert-True (@($calls | Where-Object apply).Count -eq 0) 'declining apply must perform no apply calls'
    Assert-True ((@($calls.source | Sort-Object) -join ',') -eq (@($sourceOne, $sourceTwo | Sort-Object) -join ',')) 'the enabled source set should match'
    Write-Host 'PASS PowerShell previews every enabled tagged source before a declined apply'

    Set-Content -LiteralPath $script:grantLog -Value ''
    Invoke-Hook -Answers @('y', 'y') | Out-Null
    $calls = @(Get-Content $script:grantLog | Where-Object { $_ } | ForEach-Object { ConvertFrom-Json $_ })
    Assert-True ($calls.Count -eq 4) 'two previews and two apply calls are expected'
    Assert-True (@($calls | Where-Object apply).Count -eq 2) 'the second confirmation should apply both pairs'
    Write-Host 'PASS PowerShell explicit second confirmation applies every preflighted pair'

    Set-Content -LiteralPath $script:grantLog -Value ''
    $env:KEYVAULTSYNC_TEST_PREVIEW_FAILURE = 'true'
    $failed = $false
    try {
        Invoke-Hook -Answers @('y', 'y') | Out-Null
    }
    catch {
        $failed = $true
    }
    $calls = @(Get-Content $script:grantLog | Where-Object { $_ } | ForEach-Object { ConvertFrom-Json $_ })
    Assert-True $failed 'a failed preview should fail the hook'
    Assert-True (@($calls | Where-Object apply).Count -eq 0) 'a failed preview must prevent apply calls'
    Write-Host 'PASS PowerShell preview failure prevents all apply calls'

    Write-Host 'All PowerShell azd postdeploy hook checks passed without live Azure calls.'
}
finally {
    Remove-Item Env:KEYVAULTSYNC_TEST_GRANT_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_TEST_PREVIEW_FAILURE -ErrorAction SilentlyContinue
    Remove-Item Env:AZD_NON_INTERACTIVE -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force
    Remove-Item Function:global:az -ErrorAction SilentlyContinue
    Remove-Item Function:global:Read-Host -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncTestVaults -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncTestAnswers -Scope Global -ErrorAction SilentlyContinue
}
