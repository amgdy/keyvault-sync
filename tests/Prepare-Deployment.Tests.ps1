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
$hook = Join-Path $repositoryRoot 'scripts/Prepare-Deployment.ps1'
$global:KeyVaultSyncTagTestAnswers = [System.Collections.Generic.Queue[string]]::new()
$global:KeyVaultSyncTagTestCalls = [System.Collections.Generic.List[object]]::new()
$global:KeyVaultSyncPersistedTags = @{}
$testHmacKey = [Convert]::ToBase64String([byte[]]::new(32))
$global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_HMAC_KEY'] = $testHmacKey
$global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_SUBSCRIPTIONS'] = '11111111-1111-1111-1111-111111111111'

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
    if ($args.Count -ge 4 -and $args[0] -eq 'env' -and $args[1] -eq 'set') {
        $global:KeyVaultSyncPersistedTags[$args[2]] = $args[3]
    }
    $global:LASTEXITCODE = 0
}

function global:Read-Host {
    param([string] $Prompt, [switch] $AsSecureString)
    if ($global:KeyVaultSyncTagTestAnswers.Count -eq 0) {
        return ''
    }
    $answer = $global:KeyVaultSyncTagTestAnswers.Dequeue()
    if ($AsSecureString) {
        return ConvertTo-SecureString $answer -AsPlainText -Force
    }
    return $answer
}

function global:az {
    $global:LASTEXITCODE = 0
    if ($args.Count -ge 3 -and $args[0] -eq 'storage' -and $args[1] -eq 'container' -and $args[2] -eq 'exists') {
        if (-not $global:KeyVaultSyncStorageDataPlaneReachable) {
            $global:LASTEXITCODE = 1
            return
        }
        return [pscustomobject]@{ exists = $true } | ConvertTo-Json -Compress
    }
    return [pscustomobject]@{
        publicNetworkAccess = $global:KeyVaultSyncStorageAccess
        bypass = if ($global:KeyVaultSyncStorageAccess -eq 'Enabled') { 'AzureServices' } else { 'None' }
    } | ConvertTo-Json -Compress
}

function Invoke-Hook {
    param([string[]] $Answers)

    $global:KeyVaultSyncTagTestAnswers.Clear()
    $global:KeyVaultSyncTagTestCalls.Clear()
    foreach ($answer in $Answers) {
        $global:KeyVaultSyncTagTestAnswers.Enqueue($answer)
    }
    & $hook provision 6>&1 | Out-Null
}

try {
    $env:AZURE_ENV_NAME = 'test'
    $env:KEYVAULTSYNC_NETWORK_MODE = 'public'
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_HMAC_KEY -ErrorAction SilentlyContinue

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_SUBSCRIPTIONS')
    $env:KEYVAULTSYNC_SUBSCRIPTIONS = '11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222'
    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'a process subscription list should be persisted exactly once'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_SUBSCRIPTIONS|11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222|--environment|test') 'whitespace-separated subscriptions should be preserved'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_SUBSCRIPTIONS
    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_SUBSCRIPTIONS'] = '11111111-1111-1111-1111-111111111111'
    Write-Host 'PASS PowerShell whitespace-separated subscription IDs are validated and persisted'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_SUBSCRIPTIONS')
    $env:KEYVAULTSYNC_SUBSCRIPTIONS = '"11111111-1111-1111-1111-111111111111"'
    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'quoted subscription input should be persisted exactly once'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_SUBSCRIPTIONS|11111111-1111-1111-1111-111111111111|--environment|test') 'quoted subscription input should be normalized'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_SUBSCRIPTIONS
    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_SUBSCRIPTIONS'] = '11111111-1111-1111-1111-111111111111'
    Write-Host 'PASS PowerShell quoted subscription input is normalized before validation'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_SUBSCRIPTIONS')
    $env:KEYVAULTSYNC_SUBSCRIPTIONS = 'not-a-subscription'
    $env:AZD_NON_INTERACTIVE = 'true'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('must contain Azure subscription GUIDs separated by commas, semicolons, or whitespace')) 'invalid subscriptions should fail validation'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'invalid subscriptions must not be persisted'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_SUBSCRIPTIONS
    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_SUBSCRIPTIONS'] = '11111111-1111-1111-1111-111111111111'
    Write-Host 'PASS PowerShell invalid subscription IDs fail before persistence'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_SUBSCRIPTIONS')
    $env:AZURE_SUBSCRIPTION_ID = '33333333-3333-3333-3333-333333333333'
    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'the azd deployment subscription should initialize the list once'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_SUBSCRIPTIONS|33333333-3333-3333-3333-333333333333|--environment|test') 'the deployment subscription should initialize KEYVAULTSYNC_SUBSCRIPTIONS'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:AZURE_SUBSCRIPTION_ID
    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_SUBSCRIPTIONS'] = '11111111-1111-1111-1111-111111111111'
    Write-Host 'PASS PowerShell the azd deployment subscription initializes the discovery list'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_SUBSCRIPTIONS')
    $env:AZD_NON_INTERACTIVE = 'true'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('KEYVAULTSYNC_SUBSCRIPTIONS is required')) 'missing subscription configuration should fail'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'missing subscription configuration must not write azd values'
    Remove-Item Env:AZD_NON_INTERACTIVE
    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_SUBSCRIPTIONS'] = '11111111-1111-1111-1111-111111111111'
    Write-Host 'PASS PowerShell missing subscription configuration fails before persistence'

    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'non-interactive mode must not write azd environment values'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Write-Host 'PASS PowerShell non-interactive mode preserves configuration without prompting'

    Remove-Item Env:KEYVAULTSYNC_NETWORK_MODE
    $privateVaultIds = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/providers/Microsoft.KeyVault/vaults/source,/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/providers/Microsoft.KeyVault/vaults/target'
    Invoke-Hook -Answers @('r', 'm', $privateVaultIds, 'n')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 3) 'private managed selection should persist mode, source, and vault endpoint IDs'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_NETWORK_MODE|private|--environment|test') 'private mode should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[1] -join '|') -eq 'env|set|KEYVAULTSYNC_NETWORK_SOURCE|managed|--environment|test') 'managed network source should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[2] -join '|') -eq "env|set|KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS|$privateVaultIds|--environment|test") 'approved vault IDs should be persisted'
    $env:KEYVAULTSYNC_NETWORK_MODE = 'public'
    Write-Host 'PASS PowerShell interactive networking selection persists private managed mode and approved vault endpoints'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS')
    $env:KEYVAULTSYNC_NETWORK_MODE = 'private'
    $env:KEYVAULTSYNC_NETWORK_SOURCE = 'managed'
    $env:AZD_NON_INTERACTIVE = 'true'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS is required')) 'managed private networking should require explicit vault endpoint IDs'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'missing private vault IDs must not persist values'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_NETWORK_SOURCE
    $env:KEYVAULTSYNC_NETWORK_MODE = 'public'
    Write-Host 'PASS PowerShell managed private networking requires an explicit vault endpoint list'

    $env:KEYVAULTSYNC_NETWORK_MODE = 'private'
    $env:KEYVAULTSYNC_NETWORK_SOURCE = 'existing'
    $env:AZD_NON_INTERACTIVE = 'true'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID is required')) 'incomplete existing networking should fail before Bicep'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'incomplete existing networking must not persist values'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_NETWORK_SOURCE
    $env:KEYVAULTSYNC_NETWORK_MODE = 'public'
    Write-Host 'PASS PowerShell incomplete existing-network configuration fails before Bicep'

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

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_HMAC_KEY')
    $global:KeyVaultSyncTagTestCalls.Clear()
    $env:AZD_NON_INTERACTIVE = 'true'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('KEYVAULTSYNC_HMAC_KEY is required for non-interactive deployment')) 'a missing non-interactive HMAC key must fail instead of generating a replacement'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'a missing non-interactive HMAC key must not be persisted'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Write-Host 'PASS PowerShell missing non-interactive HMAC configuration fails safely'

    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_HMAC_KEY'] = 'invalid'
    $env:AZD_NON_INTERACTIVE = 'true'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('KEYVAULTSYNC_HMAC_KEY is invalid')) 'an invalid non-interactive HMAC key must fail instead of being replaced'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'an invalid non-interactive HMAC key must not be persisted'
    Remove-Item Env:AZD_NON_INTERACTIVE
    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_HMAC_KEY')
    Write-Host 'PASS PowerShell invalid non-interactive HMAC configuration fails safely'

    $env:KEYVAULTSYNC_HMAC_KEY = $testHmacKey
    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'protected non-interactive configuration should be persisted exactly once'
    Assert-True ($global:KeyVaultSyncTagTestCalls[0][3] -ceq $testHmacKey) 'protected non-interactive configuration should be stored without transformation'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_HMAC_KEY
    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_HMAC_KEY')
    Write-Host 'PASS PowerShell protected non-interactive HMAC input is persisted'

    $global:KeyVaultSyncTagTestCalls.Clear()
    Invoke-Hook -Answers @('', '')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'interactive generation should persist exactly one HMAC setting'
    $generatedKey = [string] $global:KeyVaultSyncTagTestCalls[0][3]
    $generatedKeyBytes = [Convert]::FromBase64String($generatedKey)
    Assert-True ($generatedKeyBytes.Length -eq 32) 'the generated HMAC key must decode to exactly 32 bytes'
    Write-Host 'PASS PowerShell interactive HMAC generation persists a valid 256-bit key'

    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_HMAC_KEY'] = "`"$generatedKey`""
    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'a quoted saved HMAC key should be reused without persistence'
    Remove-Item Env:AZD_NON_INTERACTIVE
    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_HMAC_KEY'] = $generatedKey
    Write-Host 'PASS PowerShell quoted saved HMAC key is normalized without rotation'

    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_HMAC_KEY'] = 'invalid'
    Invoke-Hook -Answers @('', '')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'repairing an invalid saved HMAC key should persist exactly one replacement'
    $replacementKey = [string] $global:KeyVaultSyncTagTestCalls[0][3]
    $replacementKeyBytes = [Convert]::FromBase64String($replacementKey)
    Assert-True ($replacementKeyBytes.Length -eq 32) 'the replacement HMAC key must decode to exactly 32 bytes'
    Write-Host 'PASS PowerShell invalid saved HMAC key can be replaced by a generated valid key'

    $env:KEYVAULTSYNC_HMAC_KEY = $testHmacKey
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('contain different HMAC keys')) 'different process and azd keys must fail instead of rotating the saved key'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'conflicting HMAC keys must not be persisted'
    Remove-Item Env:KEYVAULTSYNC_HMAC_KEY
    Write-Host 'PASS PowerShell conflicting HMAC keys fail without changing the saved key'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_HMAC_KEY')
    $global:KeyVaultSyncTagTestCalls.Clear()
    Invoke-Hook -Answers @('s', $testHmacKey, '')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'interactive supply should persist exactly one HMAC setting'
    Assert-True ($global:KeyVaultSyncTagTestCalls[0][3] -ceq $testHmacKey) 'the supplied HMAC key should be stored without transformation'
    Write-Host 'PASS PowerShell supplied HMAC key is validated and persisted'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_HMAC_KEY')
    $message = ''
    try {
        Invoke-Hook -Answers @('s', 'invalid')
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('The HMAC key must be Base64 for exactly 32 bytes')) 'invalid supplied HMAC keys must be rejected'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'an invalid supplied HMAC key must not be persisted'
    Write-Host 'PASS PowerShell invalid HMAC input is rejected before persistence'

    $global:KeyVaultSyncPersistedTags['KEYVAULTSYNC_HMAC_KEY'] = $testHmacKey
    $env:AZURE_SUBSCRIPTION_ID = '11111111-1111-1111-1111-111111111111'
    $env:AZURE_RESOURCE_GROUP = 'example-resource-group'
    $env:KEYVAULTSYNC_STORAGE_ACCOUNT_URI = 'https://example.blob.core.windows.net/'

    $global:KeyVaultSyncStorageAccess = 'Enabled'
    $global:KeyVaultSyncStorageDataPlaneReachable = $true
    $output = & $hook deploy 6>&1 | Out-String
    Assert-True ($output.Contains('Verified deployment storage example')) 'direct deploy should validate accessible storage'
    Write-Host 'PASS PowerShell direct deploy revalidates the HMAC key and accessible deployment storage'

    $env:KEYVAULTSYNC_NETWORK_MODE = 'private'
    $global:KeyVaultSyncStorageAccess = 'Disabled'
    $output = & $hook deploy 6>&1 | Out-String
    Assert-True ($output.Contains('Verified private deployment storage example through the Blob data plane')) 'private deploy should verify Blob connectivity'
    Write-Host 'PASS PowerShell private deploy verifies Blob data-plane connectivity'

    $global:KeyVaultSyncStorageDataPlaneReachable = $false
    $message = ''
    try {
        & $hook deploy 6>&1 | Out-Null
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('not reachable through the deployment agent')) 'unreachable private storage should fail before upload'
    $global:KeyVaultSyncStorageDataPlaneReachable = $true
    $env:KEYVAULTSYNC_NETWORK_MODE = 'public'
    Write-Host 'PASS PowerShell unreachable private deployment storage fails before package upload'

    $global:KeyVaultSyncStorageAccess = 'Disabled'
    $message = ''
    try {
        & $hook deploy 6>&1 | Out-Null
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('requires a reachable Blob endpoint')) 'inaccessible deployment storage should fail before upload'
    Write-Host 'PASS PowerShell inaccessible deployment storage fails before package upload'

    Write-Host 'All PowerShell deployment preparation checks passed without Azure changes.'
}
finally {
    Remove-Item Env:AZD_NON_INTERACTIVE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_HMAC_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_SUBSCRIPTIONS -ErrorAction SilentlyContinue
    Remove-Item Env:AZURE_SUBSCRIPTION_ID -ErrorAction SilentlyContinue
    Remove-Item Env:AZURE_RESOURCE_GROUP -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_STORAGE_ACCOUNT_URI -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_NETWORK_MODE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_NETWORK_SOURCE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS -ErrorAction SilentlyContinue
    Remove-Item Function:global:azd -ErrorAction SilentlyContinue
    Remove-Item Function:global:az -ErrorAction SilentlyContinue
    Remove-Item Function:global:Read-Host -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncTagTestAnswers -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncTagTestCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncPersistedTags -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncStorageAccess -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncStorageDataPlaneReachable -Scope Global -ErrorAction SilentlyContinue
}
