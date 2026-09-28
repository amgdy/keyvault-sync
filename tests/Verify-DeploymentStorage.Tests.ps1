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
$hook = Join-Path $repositoryRoot 'scripts/Verify-DeploymentStorage.ps1'
$global:KeyVaultSyncStorageAccess = 'Enabled'

function global:az {
    $global:LASTEXITCODE = 0
    return $global:KeyVaultSyncStorageAccess
}

try {
    $env:AZURE_SUBSCRIPTION_ID = '11111111-1111-1111-1111-111111111111'
    $env:AZURE_RESOURCE_GROUP = 'example-resource-group'
    $env:KEYVAULTSYNC_STORAGE_ACCOUNT_URI = 'https://example.blob.core.windows.net/'

    $global:KeyVaultSyncStorageAccess = 'Enabled'
    $output = & $hook 6>&1 | Out-String
    Assert-True ($output.Contains('Verified Flex deployment storage example')) 'enabled storage should pass'
    Write-Host 'PASS PowerShell accessible deployment storage passes the predeploy guard'

    $global:KeyVaultSyncStorageAccess = 'Disabled'
    $message = ''
    try {
        & $hook 6>&1 | Out-Null
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('requires a reachable Blob endpoint')) 'inaccessible storage should explain the deployment requirement'
    Assert-True ($message.Contains("environment's approved architecture")) 'inaccessible storage should provide neutral remediation'
    Write-Host 'PASS PowerShell inaccessible deployment storage fails before package upload with neutral remediation'

    Write-Host 'All PowerShell deployment-storage predeploy checks passed without Azure changes.'
}
finally {
    Remove-Item Env:AZURE_SUBSCRIPTION_ID -ErrorAction SilentlyContinue
    Remove-Item Env:AZURE_RESOURCE_GROUP -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_STORAGE_ACCOUNT_URI -ErrorAction SilentlyContinue
    Remove-Item Function:global:az -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncStorageAccess -Scope Global -ErrorAction SilentlyContinue
}
