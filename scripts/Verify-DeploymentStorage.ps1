[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

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

$publicNetworkAccess = & az storage account show `
    --subscription $env:AZURE_SUBSCRIPTION_ID `
    --resource-group $env:AZURE_RESOURCE_GROUP `
    --name $storageAccount `
    --query publicNetworkAccess `
    --output tsv
if ($LASTEXITCODE -ne 0) {
    throw "Could not read storage account $storageAccount."
}

if ($publicNetworkAccess.Trim() -ne 'Enabled') {
    throw @"
Flex deployment storage $storageAccount has publicNetworkAccess=$($publicNetworkAccess.Trim()).
This deployment path requires a reachable Blob endpoint. Align the storage network configuration
with the environment's approved architecture before retrying azd deploy.
"@
}

Write-Host "Verified Flex deployment storage $storageAccount has public network access enabled."
