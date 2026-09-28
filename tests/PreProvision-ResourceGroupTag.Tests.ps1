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
$hook = Join-Path $repositoryRoot 'scripts/PreProvision-ResourceGroupTag.ps1'
$global:KeyVaultSyncTagTestAnswers = [System.Collections.Generic.Queue[string]]::new()
$global:KeyVaultSyncTagTestCalls = [System.Collections.Generic.List[object]]::new()
$global:KeyVaultSyncPersistedTags = @{}

function global:azd {
    if ($args.Count -ge 3 -and $args[0] -eq 'env' -and $args[1] -eq 'get-value') {
        if (-not $global:KeyVaultSyncPersistedTags.ContainsKey($args[2])) {
            $global:LASTEXITCODE = 1
            return
        }
        $global:LASTEXITCODE = 0
        return $global:KeyVaultSyncPersistedTags[$args[2]]
    }
    [void] $global:KeyVaultSyncTagTestCalls.Add(@($args))
    $global:LASTEXITCODE = 0
}

function global:Read-Host {
    param([string] $Prompt)
    if ($global:KeyVaultSyncTagTestAnswers.Count -eq 0) {
        return ''
    }
    return $global:KeyVaultSyncTagTestAnswers.Dequeue()
}

function Invoke-Hook {
    param([string[]] $Answers)

    $global:KeyVaultSyncTagTestAnswers.Clear()
    $global:KeyVaultSyncTagTestCalls.Clear()
    foreach ($answer in $Answers) {
        $global:KeyVaultSyncTagTestAnswers.Enqueue($answer)
    }
    & $hook 6>&1 | Out-Null
}

try {
    $env:AZURE_ENV_NAME = 'test'
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE -ErrorAction SilentlyContinue

    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'non-interactive mode must not write azd environment values'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Write-Host 'PASS PowerShell non-interactive mode preserves configuration without prompting'

    $env:AZD_NON_INTERACTIVE = 'true'
    $env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME = 'IncompleteTag'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('Set both KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME and KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE')) 'incomplete non-interactive tag configuration must fail before Bicep'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'incomplete non-interactive tag configuration must not write azd values'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME
    Write-Host 'PASS PowerShell incomplete non-interactive tag configuration fails before Bicep'

    Invoke-Hook -Answers @('n')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'declining the optional tag must not write azd environment values'
    Write-Host 'PASS PowerShell declining the optional tag performs no environment writes'

    Invoke-Hook -Answers @('y', 'ComplianceClass', 'Reviewed', '')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 2) 'two azd environment values should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME|ComplianceClass|--environment|test') 'the selected tag name should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[1] -join '|') -eq 'env|set|KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE|Reviewed|--environment|test') 'the selected tag value should be persisted'
    Write-Host 'PASS PowerShell an operator-selected tag is persisted to the active azd environment'

    $env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME = 'ExistingTag'
    $env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE = 'ExistingValue'
    Invoke-Hook -Answers @('')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'retaining a complete tag should not rewrite azd environment values'
    Write-Host 'PASS PowerShell existing complete tag configuration can be retained'

    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE
    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME'] = 'PersistedTag'
    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE'] = 'PersistedValue'
    Invoke-Hook -Answers @('')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'persisted azd tag configuration should not be rewritten'
    Write-Host 'PASS PowerShell persisted azd tag configuration is loaded when hook variables are not exported'

    Write-Host 'All PowerShell resource-group tag preprovision hook checks passed without Azure calls.'
}
finally {
    Remove-Item Env:AZD_NON_INTERACTIVE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE -ErrorAction SilentlyContinue
    Remove-Item Function:global:azd -ErrorAction SilentlyContinue
    Remove-Item Function:global:Read-Host -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncTagTestAnswers -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncTagTestCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncPersistedTags -Scope Global -ErrorAction SilentlyContinue
}
