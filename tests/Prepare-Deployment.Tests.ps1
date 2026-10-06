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
        if ([string]::IsNullOrEmpty($answer)) {
            return [System.Security.SecureString]::new()
        }
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
    $env:AZURE_RESOURCE_GROUP = 'existing-resource-group'
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
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

    Remove-Item Env:AZURE_RESOURCE_GROUP
    Remove-Item Env:KEYVAULTSYNC_REGION_CODE -ErrorAction SilentlyContinue
    $null = $global:KeyVaultSyncPersistedTags.Remove('AZURE_RESOURCE_GROUP')
    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_REGION_CODE')
    Invoke-Hook -Answers @('SWC', '')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 2) 'resource-group generation should persist the region abbreviation and resource-group name'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_REGION_CODE|swc|--environment|test') 'the normalized region abbreviation should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[1] -join '|') -eq 'env|set|AZURE_RESOURCE_GROUP|rg-keyvaultsync-swc-test|--environment|test') 'the CAF-style resource-group name should be persisted'
    $env:AZURE_RESOURCE_GROUP = 'existing-resource-group'
    Write-Host 'PASS PowerShell missing resource-group configuration generates and persists a CAF-style name'

    Remove-Item Env:AZURE_RESOURCE_GROUP
    $null = $global:KeyVaultSyncPersistedTags.Remove('AZURE_RESOURCE_GROUP')
    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_REGION_CODE')
    $message = ''
    try {
        Invoke-Hook -Answers @('sw')
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('KEYVAULTSYNC_REGION_CODE must contain exactly three ASCII letters')) 'invalid region abbreviations should fail validation'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'invalid region abbreviations must not persist resource-group configuration'
    $env:AZURE_RESOURCE_GROUP = 'existing-resource-group'
    Write-Host 'PASS PowerShell invalid region abbreviations fail before resource-group configuration is persisted'

    Remove-Item Env:AZURE_RESOURCE_GROUP
    $null = $global:KeyVaultSyncPersistedTags.Remove('AZURE_RESOURCE_GROUP')
    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_REGION_CODE')
    $env:AZD_NON_INTERACTIVE = 'true'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message.Contains('KEYVAULTSYNC_REGION_CODE is required when AZURE_RESOURCE_GROUP is not configured')) 'non-interactive resource-group generation should require a region abbreviation'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'missing non-interactive region abbreviation must not persist resource-group configuration'
    Remove-Item Env:AZD_NON_INTERACTIVE
    $env:AZURE_RESOURCE_GROUP = 'existing-resource-group'
    Write-Host 'PASS PowerShell non-interactive resource-group generation requires an explicit region abbreviation'

    Remove-Item Env:AZURE_RESOURCE_GROUP
    $null = $global:KeyVaultSyncPersistedTags.Remove('AZURE_RESOURCE_GROUP')
    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_REGION_CODE')
    $env:KEYVAULTSYNC_REGION_CODE = 'EUN'
    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 2) 'a supplied region abbreviation should generate resource-group configuration'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_REGION_CODE|eun|--environment|test') 'the supplied region abbreviation should be normalized and persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[1] -join '|') -eq 'env|set|AZURE_RESOURCE_GROUP|rg-keyvaultsync-eun-test|--environment|test') 'the supplied region abbreviation should produce the CAF-style resource-group name'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_REGION_CODE
    $env:AZURE_RESOURCE_GROUP = 'existing-resource-group'
    Write-Host 'PASS PowerShell non-interactive resource-group generation accepts and normalizes a supplied region abbreviation'

    Remove-Item Env:KEYVAULTSYNC_NETWORK_PROFILE -ErrorAction SilentlyContinue
    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_NETWORK_PROFILE')
    Invoke-Hook -Answers @('', '')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'public default selection should persist only the network profile'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_NETWORK_PROFILE|public|--environment|test') 'public profile should be persisted'
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
    Write-Host 'PASS PowerShell interactive networking selection defaults to public and persists the choice'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_NETWORK_PROFILE')
    Remove-Item Env:KEYVAULTSYNC_NETWORK_PROFILE
    $env:KEYVAULTSYNC_NETWORK_MODE = 'private'
    $env:KEYVAULTSYNC_NETWORK_SOURCE = 'managed'
    $env:AZD_NON_INTERACTIVE = 'true'
    Invoke-Hook -Answers @()
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'retired network settings should migrate to one profile'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_NETWORK_PROFILE|private-managed|--environment|test') 'retired managed-private settings should preserve their posture'
    Remove-Item Env:AZD_NON_INTERACTIVE
    Remove-Item Env:KEYVAULTSYNC_NETWORK_MODE
    Remove-Item Env:KEYVAULTSYNC_NETWORK_SOURCE
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
    Write-Host 'PASS PowerShell retired network mode and source migrate to one managed-private profile'

    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'unsupported'
    try {
        Invoke-Hook -Answers @()
        throw 'unsupported networking profile should fail'
    }
    catch {
        Assert-True ($_.Exception.Message -match 'KEYVAULTSYNC_NETWORK_PROFILE must be public, private-managed, or private-existing') 'unsupported networking profile should report the accepted values'
    }
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'unsupported networking profile should fail before persisting configuration'
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
    Write-Host 'PASS PowerShell unsupported networking profile fails before persisting configuration'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_NETWORK_PROFILE')
    Remove-Item Env:KEYVAULTSYNC_NETWORK_PROFILE
    Invoke-Hook -Answers @('2', '', '')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 6) 'private managed selection should persist one profile and topology defaults'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_NETWORK_PROFILE|private-managed|--environment|test') 'private managed profile should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[1] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_VNET_ADDRESS_PREFIX|10.42.0.0/24|--environment|test') 'managed VNet prefix should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[2] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_NAME|snet-functions|--environment|test') 'managed Function subnet name should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[3] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_PREFIX|10.42.0.0/27|--environment|test') 'managed Function subnet prefix should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[4] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_NAME|snet-private-endpoints|--environment|test') 'managed endpoint subnet name should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[5] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_PREFIX|10.42.0.32/27|--environment|test') 'managed endpoint subnet prefix should be persisted'
    Assert-True ((($global:KeyVaultSyncTagTestCalls | ForEach-Object { $_[2] }) -contains 'KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS') -eq $false) 'customer vault endpoint IDs must not be requested or persisted'
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
    Write-Host 'PASS PowerShell interactive private managed selection persists topology defaults without requesting vault endpoints'

    foreach ($name in @(
        'KEYVAULTSYNC_NETWORK_PROFILE',
        'KEYVAULTSYNC_MANAGED_VNET_ADDRESS_PREFIX',
        'KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_NAME',
        'KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_PREFIX',
        'KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_NAME',
        'KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_PREFIX'
    )) {
        $null = $global:KeyVaultSyncPersistedTags.Remove($name)
    }
    Remove-Item Env:KEYVAULTSYNC_NETWORK_PROFILE
    Invoke-Hook -Answers @(
        '2',
        '2',
        '10.80.0.0/23',
        'snet-runtime',
        '10.80.0.0/26',
        'snet-endpoints',
        '10.80.0.64/27',
        ''
    )
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 6) 'private managed selection should persist one profile and each custom topology value'
    Assert-True (($global:KeyVaultSyncTagTestCalls[1] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_VNET_ADDRESS_PREFIX|10.80.0.0/23|--environment|test') 'custom managed VNet prefix should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[2] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_NAME|snet-runtime|--environment|test') 'custom Function subnet name should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[3] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_PREFIX|10.80.0.0/26|--environment|test') 'custom Function subnet prefix should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[4] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_NAME|snet-endpoints|--environment|test') 'custom endpoint subnet name should be persisted'
    Assert-True (($global:KeyVaultSyncTagTestCalls[5] -join '|') -eq 'env|set|KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_PREFIX|10.80.0.64/27|--environment|test') 'custom endpoint subnet prefix should be persisted'
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
    Write-Host 'PASS PowerShell interactive private managed selection persists custom VNet and subnet values'

    foreach ($name in @(
        'KEYVAULTSYNC_NETWORK_PROFILE',
        'KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID',
        'KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID',
        'KEYVAULTSYNC_EXISTING_BLOB_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_QUEUE_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_TABLE_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_MONITOR_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_OMS_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_ODS_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_AGENTSVC_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_AMPLS_ID'
    )) {
        $null = $global:KeyVaultSyncPersistedTags.Remove($name)
    }
    Remove-Item Env:KEYVAULTSYNC_NETWORK_PROFILE
    $existingValues = @(
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/network/providers/Microsoft.Network/virtualNetworks/shared/subnets/functions',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/network/providers/Microsoft.Network/virtualNetworks/shared/subnets/endpoints',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.queue.core.windows.net',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.table.core.windows.net',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.monitor.azure.com',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.oms.opinsights.azure.com',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.ods.opinsights.azure.com',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.agentsvc.azure-automation.net',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/monitor/providers/Microsoft.Insights/privateLinkScopes/shared'
    )
    Invoke-Hook -Answers (@('3') + $existingValues + @('', ''))
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 11) 'private existing selection should persist one profile and every required network value'
    Assert-True (($global:KeyVaultSyncTagTestCalls[0] -join '|') -eq 'env|set|KEYVAULTSYNC_NETWORK_PROFILE|private-existing|--environment|test') 'private existing profile should be persisted'
    Assert-True ($global:KeyVaultSyncTagTestCalls[1][2] -eq 'KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID') 'existing Function subnet should be persisted first'
    Assert-True ($global:KeyVaultSyncTagTestCalls[2][2] -eq 'KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID') 'existing endpoint subnet should be persisted second'
    Assert-True ($global:KeyVaultSyncTagTestCalls[10][2] -eq 'KEYVAULTSYNC_EXISTING_AMPLS_ID') 'existing AMPLS should be persisted'
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
    Write-Host 'PASS PowerShell interactive private existing selection prompts for and persists every required network value'

    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'private-managed'
    $env:AZD_NON_INTERACTIVE = 'true'
    $message = ''
    try {
        Invoke-Hook -Answers @()
    }
    catch {
        $message = $_.Exception.Message
    }
    Assert-True ($message -eq '') 'managed private networking should succeed without customer vault IDs'
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'no additional values should be persisted when the environment is already complete'
    Remove-Item Env:AZD_NON_INTERACTIVE
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
    Write-Host 'PASS PowerShell managed private networking succeeds without any customer vault resource IDs'

    foreach ($name in @(
        'KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID',
        'KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID',
        'KEYVAULTSYNC_EXISTING_BLOB_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_QUEUE_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_TABLE_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_MONITOR_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_OMS_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_ODS_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_AGENTSVC_PRIVATE_DNS_ZONE_ID',
        'KEYVAULTSYNC_EXISTING_AMPLS_ID'
    )) {
        $null = $global:KeyVaultSyncPersistedTags.Remove($name)
    }
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'private-existing'
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
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
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

    Invoke-Hook -Answers @('')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 0) 'declining the optional tag must not write azd environment values'
    Write-Host 'PASS PowerShell declining the optional tag performs no environment writes'

    Invoke-Hook -Answers @('2', 'ComplianceClass', 'Reviewed', '')
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
    Invoke-Hook -Answers @($testHmacKey, '')
    Assert-True ($global:KeyVaultSyncTagTestCalls.Count -eq 1) 'interactive supply should persist exactly one HMAC setting'
    Assert-True ($global:KeyVaultSyncTagTestCalls[0][3] -ceq $testHmacKey) 'the supplied HMAC key should be stored without transformation'
    Write-Host 'PASS PowerShell supplied HMAC key is validated and persisted'

    $null = $global:KeyVaultSyncPersistedTags.Remove('KEYVAULTSYNC_HMAC_KEY')
    $message = ''
    try {
        Invoke-Hook -Answers @('invalid')
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

    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'private-managed'
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
    $env:KEYVAULTSYNC_NETWORK_PROFILE = 'public'
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
    Remove-Item Env:KEYVAULTSYNC_REGION_CODE -ErrorAction SilentlyContinue
    Remove-Item Env:AZURE_SUBSCRIPTION_ID -ErrorAction SilentlyContinue
    Remove-Item Env:AZURE_RESOURCE_GROUP -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_STORAGE_ACCOUNT_URI -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_NETWORK_PROFILE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_NETWORK_MODE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_NETWORK_SOURCE -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_MANAGED_VNET_ADDRESS_PREFIX -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_PREFIX -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_PREFIX -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_BLOB_PRIVATE_DNS_ZONE_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_QUEUE_PRIVATE_DNS_ZONE_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_TABLE_PRIVATE_DNS_ZONE_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_MONITOR_PRIVATE_DNS_ZONE_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_OMS_PRIVATE_DNS_ZONE_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_ODS_PRIVATE_DNS_ZONE_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_AGENTSVC_PRIVATE_DNS_ZONE_ID -ErrorAction SilentlyContinue
    Remove-Item Env:KEYVAULTSYNC_EXISTING_AMPLS_ID -ErrorAction SilentlyContinue
    Remove-Item Function:global:azd -ErrorAction SilentlyContinue
    Remove-Item Function:global:az -ErrorAction SilentlyContinue
    Remove-Item Function:global:Read-Host -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncTagTestAnswers -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncTagTestCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncPersistedTags -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncStorageAccess -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KeyVaultSyncStorageDataPlaneReachable -Scope Global -ErrorAction SilentlyContinue
}
