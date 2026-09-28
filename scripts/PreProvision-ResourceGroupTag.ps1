[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

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
    return ($value | Out-String).Trim()
}

if (-not (Get-Command azd -ErrorAction SilentlyContinue)) {
    throw 'azd is required.'
}

$currentName = $env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME
if ([string]::IsNullOrWhiteSpace($currentName)) {
    $currentName = Get-AzdValue 'KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME'
}
$currentValue = $env:KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE
if ([string]::IsNullOrWhiteSpace($currentValue)) {
    $currentValue = Get-AzdValue 'KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE'
}

if ($env:AZD_NON_INTERACTIVE -ieq 'true') {
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
