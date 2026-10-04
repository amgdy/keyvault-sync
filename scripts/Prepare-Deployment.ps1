[CmdletBinding()]
<#
.SYNOPSIS
Prepares protected azd configuration for provisioning or package deployment.
.DESCRIPTION
The provision phase validates discovery subscriptions, establishes the stable HMAC key,
and optionally configures one deployment tag. The deploy phase preserves the HMAC key
and validates Flex deployment-storage reachability. The HMAC value is never displayed.
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('provision', 'deploy')]
    [string] $Phase
)

$ErrorActionPreference = 'Stop'

# Ask an interactive yes/no question with explicit unavailable-input behavior.
function Confirm-Yes {
    param(
        [Parameter(Mandatory = $true)][string] $Prompt,
        [switch] $DefaultYes,
        [switch] $AllowUnavailableDefault
    )

    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    try {
        $answer = Read-Host "$Prompt $suffix"
    }
    catch {
        if ($DefaultYes -and $AllowUnavailableDefault) {
            return $true
        }
        throw 'No interactive response was available.'
    }

    if ($DefaultYes -and [string]::IsNullOrWhiteSpace($answer)) {
        return $true
    }
    return $answer -in @('y', 'Y', 'yes', 'YES')
}

# Persist one value in the selected azd environment.
function Set-AzdValue {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Value
    )

    $arguments = @('env', 'set', $Name, $Value)
    if (-not [string]::IsNullOrWhiteSpace($env:AZURE_ENV_NAME)) {
        $arguments += @('--environment', $env:AZURE_ENV_NAME)
    }
    & azd @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "azd failed to save $Name."
    }
}

# Normalize one scalar passed through an azd environment or process variable.
function ConvertFrom-AzdScalar {
    param([AllowEmptyString()][string] $Value)

    $normalized = $Value.Trim()
    if ($normalized.Length -ge 2) {
        $firstCharacter = $normalized[0]
        $lastCharacter = $normalized[$normalized.Length - 1]
        if (($firstCharacter -eq '"' -and $lastCharacter -eq '"') -or
            ($firstCharacter -eq "'" -and $lastCharacter -eq "'")) {
            $normalized = $normalized.Substring(1, $normalized.Length - 2)
        }
    }
    return $normalized
}

# Read one value from the selected azd environment, returning empty when absent.
function Get-AzdValue {
    param([Parameter(Mandatory = $true)][string] $Name)

    $arguments = @('env', 'get-value', $Name)
    if (-not [string]::IsNullOrWhiteSpace($env:AZURE_ENV_NAME)) {
        $arguments += @('--environment', $env:AZURE_ENV_NAME)
    }
    $value = & azd @arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        return ''
    }
    return ConvertFrom-AzdScalar (($value | Out-String).Trim())
}

# Validate the exact Base64 shape of a 32-byte HMAC key without printing it.
function Test-HmacKey {
    param([Parameter(Mandatory = $true)][string] $Value)

    return $Value -cmatch '\A[A-Za-z0-9+/]{43}=\z'
}

# Store protected HMAC material while suppressing command output.
function Set-HmacKey {
    param(
        [Parameter(Mandatory = $true)][string] $EnvironmentName,
        [Parameter(Mandatory = $true)][string] $Value
    )

    $arguments = @('env', 'set', 'KEYVAULTSYNC_HMAC_KEY', $Value, '--environment', $EnvironmentName)
    & azd @arguments *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not persist KEYVAULTSYNC_HMAC_KEY in the active azd environment.'
    }
}

# Generate a cryptographically random 32-byte HMAC key and clear the temporary buffer.
function New-HmacKey {
    $bytes = [byte[]]::new(32)
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes)
    }
    finally {
        $random.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

# Read supplied HMAC material without echoing it and clear unmanaged plaintext storage.
function Read-HmacKey {
    $secureValue = Read-Host 'Enter the Base64-encoded 32-byte key (input hidden)' -AsSecureString
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
        if ($null -ne $secureValue) {
            $secureValue.Dispose()
        }
    }
}

# Reuse, import, or interactively generate the stable per-environment HMAC key.
function Ensure-HmacKey {
    $environmentName = ConvertFrom-AzdScalar $env:AZURE_ENV_NAME
    if ([string]::IsNullOrWhiteSpace($environmentName)) {
        $environmentName = Get-AzdValue 'AZURE_ENV_NAME'
    }
    if ([string]::IsNullOrWhiteSpace($environmentName)) {
        throw 'AZURE_ENV_NAME is missing; select an azd environment before provisioning.'
    }

    $processKey = ConvertFrom-AzdScalar $env:KEYVAULTSYNC_HMAC_KEY
    $environmentKey = Get-AzdValue 'KEYVAULTSYNC_HMAC_KEY'
    if (-not [string]::IsNullOrWhiteSpace($environmentKey) -and
        -not [string]::IsNullOrWhiteSpace($processKey) -and
        $environmentKey -cne $processKey) {
        throw 'The process and azd environment contain different HMAC keys. Resolve the mismatch without rotating the key accidentally.'
    }

    $hmacKey = if (-not [string]::IsNullOrWhiteSpace($environmentKey)) { $environmentKey } else { $processKey }
    if (-not [string]::IsNullOrWhiteSpace($hmacKey)) {
        if (Test-HmacKey $hmacKey) {
            if ([string]::IsNullOrWhiteSpace($environmentKey)) {
                Set-HmacKey -EnvironmentName $environmentName -Value $hmacKey
            }
            Write-Host "Reusing the configured HMAC key for azd environment $environmentName."
            return
        }

        if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
            throw 'KEYVAULTSYNC_HMAC_KEY is invalid. Provide Base64 for exactly 32 bytes through protected pipeline configuration.'
        }

        Write-Host @'

The saved KEYVAULTSYNC_HMAC_KEY is not valid Base64 for exactly 32 bytes and
cannot be used for object signatures. Choose a replacement below. The invalid
value will not be displayed and will be overwritten only after the replacement
passes validation.
'@
        $hmacKey = ''
    }

    if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
        throw 'KEYVAULTSYNC_HMAC_KEY is required for non-interactive deployment. Provide it through protected pipeline configuration or run azd interactively to supply or generate it.'
    }

    Write-Host @'

Supported object synchronization requires a stable Base64-encoded 32-byte HMAC key.
The key is stored in the active azd environment's .env file and passed to the Function
App through a secure Bicep parameter. The local .env file is plaintext; protect it and
its backups. Reuse the saved key on later deployments; generating a replacement makes
existing object baselines incompatible.
'@

    $choice = Read-Host 'Choose [G]enerate a new key (recommended) or [S]upply an existing Base64 key [G]'
    switch -Regex ($choice) {
        '^\s*$|^[gG]$' { $hmacKey = New-HmacKey; break }
        '^[sS]$' { $hmacKey = Read-HmacKey; break }
        default { throw 'Choose G to generate a key or S to supply one.' }
    }

    if (-not (Test-HmacKey $hmacKey)) {
        throw 'The HMAC key must be Base64 for exactly 32 bytes. No key was saved.'
    }
    Set-HmacKey -EnvironmentName $environmentName -Value $hmacKey
    Write-Host "Configured the HMAC key for azd environment $environmentName; the value was not displayed."
}

# Resolve, validate, and persist the complete subscription discovery list.
function Ensure-SubscriptionList {
    $configured = ConvertFrom-AzdScalar $env:KEYVAULTSYNC_SUBSCRIPTIONS
    if ([string]::IsNullOrWhiteSpace($configured)) {
        $configured = Get-AzdValue 'KEYVAULTSYNC_SUBSCRIPTIONS'
    }
    if ([string]::IsNullOrWhiteSpace($configured)) {
        $configured = ConvertFrom-AzdScalar $env:AZURE_SUBSCRIPTION_ID
    }
    if ([string]::IsNullOrWhiteSpace($configured)) {
        $configured = Get-AzdValue 'AZURE_SUBSCRIPTION_ID'
    }
    if ([string]::IsNullOrWhiteSpace($configured)) {
        throw 'KEYVAULTSYNC_SUBSCRIPTIONS is required. Supply one or more comma-separated Azure subscription IDs.'
    }

    $subscriptionIds = $configured -split '[,;\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($subscriptionIds.Count -eq 0 -or $null -ne ($subscriptionIds | Where-Object {
        $parsed = [Guid]::Empty
        -not [Guid]::TryParse($_, [ref] $parsed)
    } | Select-Object -First 1)) {
        throw 'KEYVAULTSYNC_SUBSCRIPTIONS must contain Azure subscription GUIDs separated by commas, semicolons, or whitespace.'
    }

    if ([string]::IsNullOrWhiteSpace((Get-AzdValue 'KEYVAULTSYNC_SUBSCRIPTIONS'))) {
        Set-AzdValue -Name 'KEYVAULTSYNC_SUBSCRIPTIONS' -Value $configured | Out-Null
    }
    Write-Host "Configured $($subscriptionIds.Count) subscription(s) for KeyVaultSync discovery."
}

# Persist an explicit public/private posture and private network ownership model.
function Ensure-NetworkConfiguration {
    $networkMode = $env:KEYVAULTSYNC_NETWORK_MODE
    if ([string]::IsNullOrWhiteSpace($networkMode)) {
        $networkMode = Get-AzdValue 'KEYVAULTSYNC_NETWORK_MODE'
    }
    $networkSource = $env:KEYVAULTSYNC_NETWORK_SOURCE
    if ([string]::IsNullOrWhiteSpace($networkSource)) {
        $networkSource = Get-AzdValue 'KEYVAULTSYNC_NETWORK_SOURCE'
    }

    if ([string]::IsNullOrWhiteSpace($networkMode)) {
        if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
            $networkMode = 'public'
        }
        else {
            $choice = Read-Host 'Choose [P]ublic endpoints (default) or p[R]ivate networking [P]'
            $networkMode = switch -Regex ($choice) {
                '^\s*$|^[pP]$' { 'public'; break }
                '^[rR]$' { 'private'; break }
                default { throw 'Choose P for public endpoints or R for private networking.' }
            }
        }
        Set-AzdValue -Name 'KEYVAULTSYNC_NETWORK_MODE' -Value $networkMode | Out-Null
    }

    if ($networkMode -notin @('public', 'private')) {
        throw "KEYVAULTSYNC_NETWORK_MODE must be public or private; found $networkMode."
    }
    if ($networkMode -eq 'public') {
        Write-Host 'Configured public service networking.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($networkSource)) {
        if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
            throw 'KEYVAULTSYNC_NETWORK_SOURCE is required for non-interactive private deployment.'
        }
        $choice = Read-Host 'Choose [M]anaged VNet (default) or [E]xisting enterprise network [M]'
        $networkSource = switch -Regex ($choice) {
            '^\s*$|^[mM]$' { 'managed'; break }
            '^[eE]$' { 'existing'; break }
            default { throw 'Choose M for a managed VNet or E for an existing enterprise network.' }
        }
        Set-AzdValue -Name 'KEYVAULTSYNC_NETWORK_SOURCE' -Value $networkSource | Out-Null
    }

    if ($networkSource -notin @('managed', 'existing')) {
        throw "KEYVAULTSYNC_NETWORK_SOURCE must be managed or existing; found $networkSource."
    }
    if ($networkSource -eq 'managed') {
        $privateVaultResourceIds = $env:KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS
        if ([string]::IsNullOrWhiteSpace($privateVaultResourceIds)) {
            $privateVaultResourceIds = Get-AzdValue 'KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS'
        }
        if ([string]::IsNullOrWhiteSpace($privateVaultResourceIds)) {
            if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
                throw 'KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS is required for private/managed networking. Supply the comma-separated source and target vault resource IDs approved for private endpoints.'
            }
            $privateVaultResourceIds = Read-Host 'Approved source and target Key Vault resource IDs (comma-separated)'
            if ([string]::IsNullOrWhiteSpace($privateVaultResourceIds)) {
                throw 'At least one approved Key Vault resource ID is required for a managed private network.'
            }
            Set-AzdValue -Name 'KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS' -Value $privateVaultResourceIds | Out-Null
        }
    }
    if ($networkSource -eq 'existing') {
        $requiredExistingValues = @(
            'KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID',
            'KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID',
            'KEYVAULTSYNC_EXISTING_BLOB_PRIVATE_DNS_ZONE_ID',
            'KEYVAULTSYNC_EXISTING_QUEUE_PRIVATE_DNS_ZONE_ID',
            'KEYVAULTSYNC_EXISTING_TABLE_PRIVATE_DNS_ZONE_ID',
            'KEYVAULTSYNC_EXISTING_KEYVAULT_PRIVATE_DNS_ZONE_ID',
            'KEYVAULTSYNC_EXISTING_MONITOR_PRIVATE_DNS_ZONE_ID',
            'KEYVAULTSYNC_EXISTING_OMS_PRIVATE_DNS_ZONE_ID',
            'KEYVAULTSYNC_EXISTING_ODS_PRIVATE_DNS_ZONE_ID',
            'KEYVAULTSYNC_EXISTING_AGENTSVC_PRIVATE_DNS_ZONE_ID',
            'KEYVAULTSYNC_EXISTING_AMPLS_ID'
        )
        $resolvedValues = @{}
        foreach ($requiredName in $requiredExistingValues) {
            $requiredValue = [Environment]::GetEnvironmentVariable($requiredName)
            if ([string]::IsNullOrWhiteSpace($requiredValue)) {
                $requiredValue = Get-AzdValue $requiredName
            }
            if ([string]::IsNullOrWhiteSpace($requiredValue)) {
                throw "$requiredName is required for private/existing networking."
            }
            $resolvedValues[$requiredName] = $requiredValue
        }
        if ($resolvedValues['KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID'] -eq
            $resolvedValues['KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID']) {
            throw 'The Function integration subnet and private endpoint subnet must be different.'
        }
    }

    Write-Host "Configured private networking with networkSource=$networkSource."
}

# Verify the deployed storage network posture required by Flex package deployment.
function Test-DeploymentStorage {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI is required.'
    }
    if ([string]::IsNullOrWhiteSpace($env:KEYVAULTSYNC_STORAGE_ACCOUNT_URI)) {
        throw 'KEYVAULTSYNC_STORAGE_ACCOUNT_URI is missing. Run azd provision before azd deploy.'
    }
    if ([string]::IsNullOrWhiteSpace($env:AZURE_SUBSCRIPTION_ID)) {
        throw 'AZURE_SUBSCRIPTION_ID is missing.'
    }
    if ([string]::IsNullOrWhiteSpace($env:AZURE_RESOURCE_GROUP)) {
        throw 'AZURE_RESOURCE_GROUP is missing.'
    }

    $storageUri = $null
    if (-not [Uri]::TryCreate($env:KEYVAULTSYNC_STORAGE_ACCOUNT_URI, [UriKind]::Absolute, [ref] $storageUri) -or
        $storageUri.Scheme -ne 'https' -or
        $storageUri.Host -notmatch '^([a-z0-9]{3,24})\.blob\.core\.windows\.net$') {
        throw "KEYVAULTSYNC_STORAGE_ACCOUNT_URI is not a supported Azure Blob service URI: $($env:KEYVAULTSYNC_STORAGE_ACCOUNT_URI)"
    }
    $storageAccount = $Matches[1]

    $network = & az storage account show `
        --subscription $env:AZURE_SUBSCRIPTION_ID `
        --resource-group $env:AZURE_RESOURCE_GROUP `
        --name $storageAccount `
        --query '{publicNetworkAccess:publicNetworkAccess,bypass:networkRuleSet.bypass}' `
        --output json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read storage account $storageAccount."
    }

    $publicNetworkAccess = [string]$network.publicNetworkAccess
    $bypass = [string]$network.bypass
    $networkMode = $env:KEYVAULTSYNC_NETWORK_MODE
    if ([string]::IsNullOrWhiteSpace($networkMode)) {
        $networkMode = Get-AzdValue 'KEYVAULTSYNC_NETWORK_MODE'
    }
    if ([string]::IsNullOrWhiteSpace($networkMode)) {
        $networkMode = 'public'
    }
    if ($networkMode -eq 'private') {
        if ($publicNetworkAccess.Trim() -ne 'Disabled') {
            throw "Private mode requires deployment storage publicNetworkAccess=Disabled; found $($publicNetworkAccess.Trim())."
        }
        $containerStatus = & az storage container exists `
            --account-name $storageAccount `
            --name function-releases `
            --auth-mode login `
            --only-show-errors `
            --output json | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) {
            throw "Private deployment storage $storageAccount is not reachable through the deployment agent's DNS and network path."
        }
        if (-not $containerStatus.exists) {
            throw "Private deployment storage container function-releases was not reachable in $storageAccount."
        }
        Write-Host "Verified private deployment storage $storageAccount through the Blob data plane."
        return
    }
    if ($networkMode -ne 'public') {
        throw "KEYVAULTSYNC_NETWORK_MODE must be public or private; found $networkMode."
    }
    if ($publicNetworkAccess.Trim() -ne 'Enabled' -and $bypass -notmatch 'AzureServices') {
        throw @"
Flex deployment storage $storageAccount has publicNetworkAccess=$($publicNetworkAccess.Trim()) and bypass=$bypass.
This deployment path requires a reachable Blob endpoint. Align the storage network configuration
with the environment's approved architecture before retrying azd deploy.
"@
    }

    Write-Host "Verified deployment storage $storageAccount is reachable by the deployment service (publicNetworkAccess=$publicNetworkAccess, bypass=$bypass)."
}

if (-not (Get-Command azd -ErrorAction SilentlyContinue)) {
    throw 'azd is required.'
}

# Both phases must establish the same protected HMAC key before any Azure deployment step.
Ensure-HmacKey

if ($Phase -eq 'deploy') {
    # Predeploy performs no configuration prompts; it only validates the package-deployment path.
    Test-DeploymentStorage
    return
}

# Preprovision validates runtime discovery scope before Bicep receives parameters.
Ensure-SubscriptionList
Ensure-NetworkConfiguration

$currentName = $env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME
if ([string]::IsNullOrWhiteSpace($currentName)) {
    $currentName = Get-AzdValue 'KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME'
}
$currentValue = $env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE
if ([string]::IsNullOrWhiteSpace($currentValue)) {
    $currentValue = Get-AzdValue 'KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE'
}

if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
    # Pipelines may use a complete preconfigured tag or omit tagging; partial input is rejected.
    if (-not [string]::IsNullOrWhiteSpace($currentName) -and -not [string]::IsNullOrWhiteSpace($currentValue)) {
        Write-Host "Using the preconfigured optional deployment tag $currentName=$currentValue."
    }
    elseif (-not [string]::IsNullOrWhiteSpace($currentName) -or -not [string]::IsNullOrWhiteSpace($currentValue)) {
        throw 'The optional deployment tag is incomplete. Set both KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME and KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE, or clear both.'
    }
    else {
        Write-Host 'No optional deployment tag is configured; continuing without one.'
    }
    return
}

Write-Host @'

KeyVaultSync can add one optional tag to the deployment resource group and
tagged resources managed by this deployment. Existing tags are preserved.
Do not use tag names or values to store secrets or personal information.
'@

# Interactive tagging changes only azd environment values consumed by Bicep.
if (-not [string]::IsNullOrWhiteSpace($currentName) -and -not [string]::IsNullOrWhiteSpace($currentValue)) {
    if (Confirm-Yes "Use the configured tag $currentName=$currentValue?" -DefaultYes -AllowUnavailableDefault) {
        return
    }
}
elseif ([string]::IsNullOrWhiteSpace($currentName) -and [string]::IsNullOrWhiteSpace($currentValue)) {
    if (-not (Confirm-Yes 'Add an optional tag to this deployment?')) {
        Write-Host 'Continuing without an optional deployment tag.'
        return
    }
}
else {
    Write-Host 'The current optional deployment tag is incomplete and must be replaced.'
}

$tagName = Read-Host 'Tag name'
if ([string]::IsNullOrWhiteSpace($tagName)) {
    throw 'The tag name cannot be empty.'
}
if ($tagName.Length -gt 512 -or $tagName.IndexOfAny([char[]]'<>\%&?/') -ge 0) {
    throw 'The tag name is invalid or exceeds 512 characters.'
}

$tagValue = Read-Host 'Tag value'
if ([string]::IsNullOrWhiteSpace($tagValue)) {
    throw 'The tag value cannot be empty.'
}
if ($tagValue.Length -gt 256) {
    throw 'The tag value must be 256 characters or fewer.'
}

if (-not (Confirm-Yes "Use optional deployment tag $tagName=$tagValue?" -DefaultYes)) {
    Write-Host 'Optional deployment tag was not changed.'
    return
}

Set-AzdValue KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME $tagName
Set-AzdValue KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE $tagValue
Write-Host "Configured the optional deployment tag for azd environment $($env:AZURE_ENV_NAME)."
