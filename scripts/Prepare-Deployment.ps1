[CmdletBinding()]
<#
.SYNOPSIS
Prepares protected azd configuration for provisioning or package deployment.
.DESCRIPTION
The provision phase validates discovery subscriptions, establishes CAF-style resource-group
naming, collects and persists network configuration, establishes the stable HMAC key, and
optionally configures one deployment tag. The deploy phase preserves the HMAC key and
validates Flex deployment-storage reachability. The HMAC value is never displayed.
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('provision', 'deploy')]
    [string] $Phase
)

$ErrorActionPreference = 'Stop'

# Render a numbered menu and return the selected option value.
# Each option supplies Value, Label, and optional Aliases; the first option answers empty input.
function Read-Choice {
    param(
        [Parameter(Mandatory = $true)][string] $Title,
        [Parameter(Mandatory = $true)][object[]] $Options
    )

    Write-Host $Title
    for ($index = 0; $index -lt $Options.Count; $index++) {
        $suffix = if ($index -eq 0) { ' (default)' } else { '' }
        Write-Host ("  {0}) {1}{2}" -f ($index + 1), $Options[$index].Label, $suffix)
    }

    try {
        $answer = Read-Host 'Enter a number [1]'
    }
    catch {
        throw 'No interactive response was available.'
    }

    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $Options[0].Value
    }

    $answer = $answer.Trim().ToLowerInvariant()
    for ($index = 0; $index -lt $Options.Count; $index++) {
        $option = $Options[$index]
        $aliases = @()
        if ($option.Contains('Aliases') -and $null -ne $option.Aliases) {
            $aliases = @($option.Aliases)
        }
        if ($answer -eq [string]($index + 1) -or $answer -eq $option.Value -or $aliases -contains $answer) {
            return $option.Value
        }
    }

    throw "Enter a number between 1 and $($Options.Count), or press Enter for the default."
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
    param(
        [string] $Prompt = 'Enter the Base64-encoded 32-byte key (input hidden)'
    )

    $secureValue = Read-Host $Prompt -AsSecureString
    if ($secureValue -isnot [System.Security.SecureString]) {
        return [string] $secureValue
    }
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
cannot be used for object signatures. Supply a replacement below. The invalid
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

    $hmacKey = ConvertFrom-AzdScalar (Read-HmacKey `
        -Prompt 'Paste an existing Base64-encoded 32-byte HMAC key, or press Enter to generate a new one (input hidden)')
    if ([string]::IsNullOrWhiteSpace($hmacKey)) {
        $hmacKey = New-HmacKey
        Write-Host 'No key was entered; generated a new HMAC key.'
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

# Preserve an existing resource-group name or configure the CAF-style name azd will create.
function Ensure-ResourceGroupName {
    $resourceGroup = ConvertFrom-AzdScalar $env:AZURE_RESOURCE_GROUP
    if ([string]::IsNullOrWhiteSpace($resourceGroup)) {
        $resourceGroup = Get-AzdValue 'AZURE_RESOURCE_GROUP'
    }
    if (-not [string]::IsNullOrWhiteSpace($resourceGroup)) {
        Write-Host "Using configured deployment resource group $resourceGroup."
        return
    }

    $regionCode = ConvertFrom-AzdScalar $env:KEYVAULTSYNC_REGION_CODE
    if ([string]::IsNullOrWhiteSpace($regionCode)) {
        $regionCode = Get-AzdValue 'KEYVAULTSYNC_REGION_CODE'
    }
    if ([string]::IsNullOrWhiteSpace($regionCode)) {
        if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
            throw 'KEYVAULTSYNC_REGION_CODE is required when AZURE_RESOURCE_GROUP is not configured. Provide a three-letter Azure region abbreviation such as eun or swc.'
        }
        $regionCode = ConvertFrom-AzdScalar (Read-Host 'Three-letter Azure region abbreviation for the new resource group (for example eun or swc)')
    }
    $regionCode = $regionCode.ToLowerInvariant()
    if ($regionCode -cnotmatch '\A[a-z]{3}\z') {
        throw 'KEYVAULTSYNC_REGION_CODE must contain exactly three ASCII letters.'
    }

    $environmentName = ConvertFrom-AzdScalar $env:AZURE_ENV_NAME
    if ([string]::IsNullOrWhiteSpace($environmentName)) {
        $environmentName = Get-AzdValue 'AZURE_ENV_NAME'
    }
    if ([string]::IsNullOrWhiteSpace($environmentName)) {
        throw 'AZURE_ENV_NAME is missing; select an azd environment before provisioning.'
    }
    $resourceGroupEnvironment = $environmentName.ToLowerInvariant().Replace('_', '-')
    $resourceGroupEnvironment = [regex]::Replace($resourceGroupEnvironment, '[^a-z0-9-]+', '-')
    $resourceGroupEnvironment = [regex]::Replace($resourceGroupEnvironment, '-+', '-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($resourceGroupEnvironment)) {
        throw 'AZURE_ENV_NAME must contain at least one letter or number for resource-group naming.'
    }

    $resourceGroup = "rg-keyvaultsync-$regionCode-$resourceGroupEnvironment"
    if ($resourceGroup.Length -gt 90) {
        throw "The generated resource-group name exceeds Azure's 90-character limit."
    }

    Set-AzdValue -Name 'KEYVAULTSYNC_REGION_CODE' -Value $regionCode | Out-Null
    Set-AzdValue -Name 'AZURE_RESOURCE_GROUP' -Value $resourceGroup | Out-Null
    Write-Host "Configured new deployment resource group $resourceGroup."
}

# Resolve one network value, preferring an explicit process value and persisting overrides.
function Resolve-NetworkValue {
    param([Parameter(Mandatory = $true)][string] $Name)

    $processValue = ConvertFrom-AzdScalar ([Environment]::GetEnvironmentVariable($Name))
    $savedValue = Get-AzdValue $Name
    if (-not [string]::IsNullOrWhiteSpace($processValue)) {
        if ($savedValue -cne $processValue) {
            Set-AzdValue -Name $Name -Value $processValue | Out-Null
        }
        return $processValue
    }
    return $savedValue
}

# Prompt for and persist one missing network value.
function Read-NetworkValue {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Prompt,
        [string] $DefaultValue = ''
    )

    $displayPrompt = if ([string]::IsNullOrWhiteSpace($DefaultValue)) {
        $Prompt
    }
    else {
        "$Prompt [$DefaultValue]"
    }
    $value = ConvertFrom-AzdScalar (Read-Host $displayPrompt)
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = $DefaultValue
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Name cannot be empty."
    }
    Set-AzdValue -Name $Name -Value $value | Out-Null
    return $value
}

# Prompt for missing managed VNet and subnet values, with safe standalone defaults.
function Ensure-ManagedNetworkValues {
    $settings = @(
        @{ Name = 'KEYVAULTSYNC_MANAGED_VNET_ADDRESS_PREFIX'; Prompt = 'Managed VNet address prefix'; Default = '10.42.0.0/24' },
        @{ Name = 'KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_NAME'; Prompt = 'Function integration subnet name'; Default = 'snet-functions' },
        @{ Name = 'KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_PREFIX'; Prompt = 'Function integration subnet address prefix'; Default = '10.42.0.0/27' },
        @{ Name = 'KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_NAME'; Prompt = 'Private endpoint subnet name'; Default = 'snet-private-endpoints' },
        @{ Name = 'KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_PREFIX'; Prompt = 'Private endpoint subnet address prefix'; Default = '10.42.0.32/27' }
    )
    $resolvedValues = @{}
    foreach ($setting in $settings) {
        $resolvedValues[$setting.Name] = Resolve-NetworkValue $setting.Name
    }
    $missingSettings = @($settings | Where-Object {
        [string]::IsNullOrWhiteSpace($resolvedValues[$_.Name])
    })

    if ($missingSettings.Count -eq 0 -or $env:AZD_NON_INTERACTIVE -ieq 'true') {
        return
    }

    Write-Host @'

Recommended managed private network:
  VNet:                         10.42.0.0/24
  Function integration subnet: 10.42.0.0/27
  Private endpoint subnet:     10.42.0.32/27

Confirm that these ranges do not overlap with connected enterprise, VPN,
peering, or ExpressRoute networks.
'@

    if ($missingSettings.Count -eq $settings.Count) {
        $managedNetworkAction = Read-Choice `
            -Title 'How should the managed private network be configured?' `
            -Options @(
                @{ Value = 'defaults'; Label = 'Use the recommended network names and ranges'; Aliases = @('d') },
                @{ Value = 'customize'; Label = 'Customize the network names or ranges'; Aliases = @('c') }
            )
        if ($managedNetworkAction -eq 'defaults') {
            foreach ($setting in $settings) {
                Set-AzdValue -Name $setting.Name -Value $setting.Default | Out-Null
            }
            return
        }
    }

    foreach ($setting in $missingSettings) {
        $resolvedValues[$setting.Name] = Read-NetworkValue `
            -Name $setting.Name `
            -Prompt $setting.Prompt `
            -DefaultValue $setting.Default
    }
}

# Resolve the single networking profile, migrating the retired mode/source pair when present.
function Resolve-NetworkProfile {
    $networkProfile = ConvertFrom-AzdScalar $env:KEYVAULTSYNC_NETWORK_PROFILE
    if ([string]::IsNullOrWhiteSpace($networkProfile)) {
        $networkProfile = Get-AzdValue 'KEYVAULTSYNC_NETWORK_PROFILE'
    }
    if (-not [string]::IsNullOrWhiteSpace($networkProfile)) {
        return $networkProfile
    }

    $legacyMode = ConvertFrom-AzdScalar $env:KEYVAULTSYNC_NETWORK_MODE
    if ([string]::IsNullOrWhiteSpace($legacyMode)) {
        $legacyMode = Get-AzdValue 'KEYVAULTSYNC_NETWORK_MODE'
    }
    $legacySource = ConvertFrom-AzdScalar $env:KEYVAULTSYNC_NETWORK_SOURCE
    if ([string]::IsNullOrWhiteSpace($legacySource)) {
        $legacySource = Get-AzdValue 'KEYVAULTSYNC_NETWORK_SOURCE'
    }
    if ([string]::IsNullOrWhiteSpace($legacyMode)) {
        return ''
    }

    $networkProfile = switch ("$legacyMode|$legacySource") {
        'public|' { 'public'; break }
        'public|managed' { 'public'; break }
        'public|existing' { 'public'; break }
        'private|managed' { 'private-managed'; break }
        'private|existing' { 'private-existing'; break }
        'private|' {
            throw 'The retired private network configuration is incomplete. Set KEYVAULTSYNC_NETWORK_PROFILE to private-managed or private-existing.'
        }
        default {
            throw "The retired KEYVAULTSYNC_NETWORK_MODE/KEYVAULTSYNC_NETWORK_SOURCE values are invalid: $legacyMode/$legacySource."
        }
    }

    Set-AzdValue -Name 'KEYVAULTSYNC_NETWORK_PROFILE' -Value $networkProfile | Out-Null
    return $networkProfile
}

# Persist one explicit networking profile and collect only the inputs that profile needs.
function Ensure-NetworkConfiguration {
    $networkProfile = Resolve-NetworkProfile

    if ([string]::IsNullOrWhiteSpace($networkProfile)) {
        if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
            $networkProfile = 'public'
        }
        else {
            $networkProfile = Read-Choice `
                -Title 'Select the networking profile for KeyVaultSync-managed components:' `
                -Options @(
                    @{ Value = 'public'; Label = 'Public service endpoints'; Aliases = @('p') },
                    @{ Value = 'private-managed'; Label = 'Private with a dedicated KeyVaultSync network'; Aliases = @('m', 'managed') },
                    @{ Value = 'private-existing'; Label = 'Private with existing enterprise networking'; Aliases = @('e', 'existing') }
                )
        }
        Set-AzdValue -Name 'KEYVAULTSYNC_NETWORK_PROFILE' -Value $networkProfile | Out-Null
    }

    if (@('public', 'private-managed', 'private-existing') -cnotcontains $networkProfile) {
        throw "KEYVAULTSYNC_NETWORK_PROFILE must be public, private-managed, or private-existing; found $networkProfile."
    }
    if ($networkProfile -eq 'public') {
        Write-Host 'Configured public service networking.'
        return
    }

    if ($networkProfile -eq 'private-managed') {
        Ensure-ManagedNetworkValues
    }
    if ($networkProfile -eq 'private-existing') {
        $requiredExistingSettings = @(
            @{ Name = 'KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID'; Prompt = 'Existing Function integration subnet resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID'; Prompt = 'Existing private endpoint subnet resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_BLOB_PRIVATE_DNS_ZONE_ID'; Prompt = 'Existing Blob private DNS zone resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_QUEUE_PRIVATE_DNS_ZONE_ID'; Prompt = 'Existing Queue private DNS zone resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_TABLE_PRIVATE_DNS_ZONE_ID'; Prompt = 'Existing Table private DNS zone resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_MONITOR_PRIVATE_DNS_ZONE_ID'; Prompt = 'Existing Azure Monitor private DNS zone resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_OMS_PRIVATE_DNS_ZONE_ID'; Prompt = 'Existing OMS private DNS zone resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_ODS_PRIVATE_DNS_ZONE_ID'; Prompt = 'Existing ODS private DNS zone resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_AGENTSVC_PRIVATE_DNS_ZONE_ID'; Prompt = 'Existing agent-service private DNS zone resource ID' },
            @{ Name = 'KEYVAULTSYNC_EXISTING_AMPLS_ID'; Prompt = 'Existing Azure Monitor Private Link Scope resource ID' }
        )
        $resolvedValues = @{}
        Write-Host "`nSupply the existing enterprise network resources used by KeyVaultSync."
        foreach ($setting in $requiredExistingSettings) {
            $requiredName = $setting.Name
            $requiredValue = Resolve-NetworkValue $requiredName
            if ([string]::IsNullOrWhiteSpace($requiredValue)) {
                if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
                    throw "$requiredName is required for the private-existing networking profile."
                }
                $requiredValue = Read-NetworkValue -Name $requiredName -Prompt $setting.Prompt
            }
            $resolvedValues[$requiredName] = $requiredValue
        }
        if ($resolvedValues['KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID'] -eq
            $resolvedValues['KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID']) {
            throw 'The Function integration subnet and private endpoint subnet must be different.'
        }
    }

    Write-Host "Configured networking profile $networkProfile."
    Write-Host 'Private networking covers KeyVaultSync components only (Function App, storage, monitoring).'
    Write-Host 'Source and target Key Vaults stay customer-owned; confirm they are reachable from the Function subnet.'
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
    $networkProfile = Resolve-NetworkProfile
    if ([string]::IsNullOrWhiteSpace($networkProfile)) {
        $networkProfile = 'public'
    }
    if ($networkProfile -in @('private-managed', 'private-existing')) {
        if ($publicNetworkAccess.Trim() -ne 'Disabled') {
            throw "A private networking profile requires deployment storage publicNetworkAccess=Disabled; found $($publicNetworkAccess.Trim())."
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
    if ($networkProfile -ne 'public') {
        throw "KEYVAULTSYNC_NETWORK_PROFILE must be public, private-managed, or private-existing; found $networkProfile."
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

# Preprovision validates deployment naming and runtime discovery scope before Bicep receives parameters.
Ensure-SubscriptionList
Ensure-ResourceGroupName
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
    $tagAction = Read-Choice `
        -Title "How should the configured tag $currentName=$currentValue be handled?" `
        -Options @(
            @{ Value = 'keep'; Label = 'Keep the configured tag'; Aliases = @('k') },
            @{ Value = 'replace'; Label = 'Replace the configured tag'; Aliases = @('r') }
        )
    if ($tagAction -eq 'keep') {
        return
    }
}
elseif ([string]::IsNullOrWhiteSpace($currentName) -and [string]::IsNullOrWhiteSpace($currentValue)) {
    $tagAction = Read-Choice `
        -Title 'Would you like to add an optional deployment tag?' `
        -Options @(
            @{ Value = 'skip'; Label = 'Continue without an optional tag'; Aliases = @('n', 'no') },
            @{ Value = 'add'; Label = 'Add an optional tag'; Aliases = @('y', 'yes') }
        )
    if ($tagAction -eq 'skip') {
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

$tagAction = Read-Choice `
    -Title "Save optional deployment tag $tagName=$tagValue?" `
    -Options @(
        @{ Value = 'save'; Label = 'Save this tag'; Aliases = @('y', 'yes') },
        @{ Value = 'cancel'; Label = 'Do not change the optional tag'; Aliases = @('n', 'no') }
    )
if ($tagAction -eq 'cancel') {
    Write-Host 'Optional deployment tag was not changed.'
    return
}

Set-AzdValue KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME $tagName
Set-AzdValue KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE $tagValue
Write-Host "Configured the optional deployment tag for azd environment $($env:AZURE_ENV_NAME)."
