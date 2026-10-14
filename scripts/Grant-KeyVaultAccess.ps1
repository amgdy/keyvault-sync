[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
<#
.SYNOPSIS
Previews or grants the runtime identity the four built-in Key Vault roles required by one mapping.
.DESCRIPTION
The target declares its source through sync-source-keyvault-id. Preview is the default.
-Apply creates only missing direct assignments after re-reading both vaults. The script never
changes vaults, tags, authorization mode, role definitions, objects, or existing assignments.
#>
param(
    [string] $IdentityResourceId,

    [Parameter(Mandatory = $true)]
    [string] $TargetVaultResourceId,

    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
$guidPattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
$identityPattern = "(?i)^/subscriptions/$guidPattern/resourceGroups/[^/]+/providers/Microsoft.ManagedIdentity/userAssignedIdentities/[^/]+$"
$vaultPattern = "(?i)^/subscriptions/$guidPattern/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/[^/]+$"

function ConvertFrom-AzdScalar {
    param([AllowEmptyString()][string] $Value)
    $normalized = $Value.Trim()
    if ($normalized.Length -ge 2 -and
        (($normalized[0] -eq '"' -and $normalized[-1] -eq '"') -or
         ($normalized[0] -eq "'" -and $normalized[-1] -eq "'"))) {
        return $normalized.Substring(1, $normalized.Length - 2)
    }
    return $normalized
}

function Resolve-IdentityResourceId {
    if (-not [string]::IsNullOrWhiteSpace($IdentityResourceId)) {
        return (ConvertFrom-AzdScalar $IdentityResourceId)
    }
    if (-not [string]::IsNullOrWhiteSpace($env:KEYVAULTSYNC_IDENTITY_RESOURCE_ID)) {
        return (ConvertFrom-AzdScalar $env:KEYVAULTSYNC_IDENTITY_RESOURCE_ID)
    }
    if ($null -eq (Get-Command azd -ErrorAction SilentlyContinue)) {
        throw 'azd is required when IdentityResourceId and KEYVAULTSYNC_IDENTITY_RESOURCE_ID are not supplied.'
    }
    $arguments = @('env', 'get-value', 'KEYVAULTSYNC_IDENTITY_RESOURCE_ID')
    if (-not [string]::IsNullOrWhiteSpace($env:AZURE_ENV_NAME)) {
        $arguments += @('--environment', $env:AZURE_ENV_NAME)
    }
    $output = & azd @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not read KEYVAULTSYNC_IDENTITY_RESOURCE_ID from the current azd environment.'
    }
    $resolved = ConvertFrom-AzdScalar ($output -join [Environment]::NewLine)
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw 'No managed identity was resolved. Supply IdentityResourceId or set KEYVAULTSYNC_IDENTITY_RESOURCE_ID in the current azd environment.'
    }
    return $resolved
}

$IdentityResourceId = Resolve-IdentityResourceId
if ($IdentityResourceId -notmatch $identityPattern) {
    throw 'IdentityResourceId must be a user-assigned managed identity ARM resource ID.'
}
if ($TargetVaultResourceId -notmatch $vaultPattern) {
    throw 'TargetVaultResourceId must be a Key Vault ARM resource ID.'
}
if ($null -eq (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'az is required.'
}
$authenticationCheck = & az account show --only-show-errors --output none 2>&1
if ($LASTEXITCODE -ne 0) {
    throw 'Azure CLI is not authenticated. Run az login once; azd must be configured with auth.useAzCliAuth=true so both tools share that session.'
}
Write-Host "[KeyVaultSync][vault-access] Starting $(if ($Apply) { 'apply' } else { 'read-only preview' }) for one target-declared mapping."

# Execute Azure CLI for one read or mutation and require parseable JSON.
function Invoke-AzJson {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)

    $output = & az @Arguments --only-show-errors --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI failed ($LASTEXITCODE): az $($Arguments -join ' ')`n$($output -join [Environment]::NewLine)"
    }
    $json = $output -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($json)) { return $null }
    try {
        return ConvertFrom-Json -InputObject $json -Depth 100
    }
    catch {
        throw "Azure CLI returned invalid JSON for: az $($Arguments -join ' ')"
    }
}

# Extract the subscription segment from a validated ARM resource ID.
function Get-SubscriptionId {
    param([Parameter(Mandatory = $true)][string] $ResourceId)
    return (($ResourceId.TrimEnd('/') -split '/')[2]).ToLowerInvariant()
}

# Normalize ARM IDs for case-insensitive equality checks.
function Normalize-ResourceId {
    param([Parameter(Mandatory = $true)][string] $ResourceId)
    return $ResourceId.Trim().TrimEnd('/').ToLowerInvariant()
}

# Read one case-insensitive string tag from Azure resource JSON.
function Get-TagValue {
    param(
        [Parameter(Mandatory = $true)] $Resource,
        [Parameter(Mandatory = $true)][string] $Name
    )
    if ($null -eq $Resource.tags) { return $null }
    $property = $Resource.tags.PSObject.Properties |
        Where-Object { $_.Name -ieq $Name } |
        Select-Object -First 1
    if ($null -eq $property -or $property.Value -isnot [string]) { return $null }
    $value = $property.Value.Trim()
    return $(if ([string]::IsNullOrWhiteSpace($value)) { $null } else { $value })
}

# Read one Key Vault resource by exact ARM ID.
function Get-Vault {
    param([Parameter(Mandatory = $true)][string] $ResourceId)
    $subscriptionId = Get-SubscriptionId $ResourceId
    return Invoke-AzJson -Arguments @('keyvault', 'show', '--ids', $ResourceId, '--subscription', $subscriptionId)
}

# Reject a changed, paused, cross-tenant, or access-policy vault before mutation.
function Assert-EligibleVault {
    param(
        [Parameter(Mandatory = $true)] $Vault,
        [Parameter(Mandatory = $true)][string] $ExpectedId,
        [Parameter(Mandatory = $true)][string] $TenantId,
        [Parameter(Mandatory = $true)][string] $Side
    )
    if ((Normalize-ResourceId $Vault.id) -ne (Normalize-ResourceId $ExpectedId) -or
        $Vault.properties.tenantId -ine $TenantId -or
        $Vault.properties.enableRbacAuthorization -ne $true) {
        throw "The $Side vault must match the declared ID, use the runtime tenant, and have Azure RBAC enabled."
    }
    if ((Get-TagValue $Vault 'KeyVaultSyncDisabled') -ieq 'true') {
        throw "The $Side mapping is disabled; no permissions were changed."
    }
}

# Resolve the managed identity principal and prove that the signed-in context uses its tenant.
$identitySubscription = Get-SubscriptionId $IdentityResourceId
$identity = Invoke-AzJson -Arguments @('identity', 'show', '--ids', $IdentityResourceId, '--subscription', $identitySubscription)
$principalId = [string] $identity.principalId
$tenantId = ([string] $identity.tenantId).ToLowerInvariant()
if ($principalId -notmatch "(?i)^$guidPattern$" -or [string]::IsNullOrWhiteSpace($tenantId)) {
    throw 'Managed identity metadata is incomplete.'
}
$account = Invoke-AzJson -Arguments @('account', 'show', '--subscription', $identitySubscription)
if ($account.tenantId -ine $tenantId) {
    throw 'The signed-in operator and runtime identity must belong to the same tenant.'
}

# Resolve the current signed-in principal and require a role assignment path that can grant Key Vault RBAC.
function Get-SignedInPrincipalId {
    $signedIn = & az ad signed-in-user show --query id -o tsv 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($signedIn)) {
        return $signedIn.Trim()
    }

    $accountInfo = Invoke-AzJson -Arguments @('account', 'show', '--subscription', $identitySubscription)
    $userName = [string] $accountInfo.user.name
    if ([string]::IsNullOrWhiteSpace($userName)) {
        throw 'Could not resolve the current Azure user or service principal for RBAC assignment checks.'
    }

    $servicePrincipal = & az ad sp show --id $userName --query id -o tsv 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($servicePrincipal)) {
        return $servicePrincipal.Trim()
    }

    throw 'The current Azure sign-in context cannot assign Key Vault RBAC roles. Sign in with an account that has Owner or User Access Administrator on the vaults.'
}

function Assert-CanManageRbacOnScope {
    param(
        [Parameter(Mandatory = $true)][string] $Scope,
        [Parameter(Mandatory = $true)][string] $SubscriptionId,
        [Parameter(Mandatory = $true)][string] $PrincipalId
    )

    # --include-inherited returns the vault scope and every parent scope, so --all
    # (which the CLI rejects when combined with --scope) is not needed.
    $assignments = @(Invoke-AzJson -Arguments @(
        'role', 'assignment', 'list',
        '--scope', $Scope,
        '--assignee-object-id', $PrincipalId,
        '--subscription', $SubscriptionId,
        '--include-inherited',
        '--include-groups',
        '--fill-principal-name', 'false'
    ))
    $canGrant = @($assignments | Where-Object {
        $name = ([string] $_.roleDefinitionName).ToLowerInvariant()
        $name -in @('owner', 'user access administrator', 'role based access control administrator')
    }).Count -gt 0
    if (-not $canGrant) {
        throw "The current signed-in principal does not have Owner, User Access Administrator, or Role Based Access Control Administrator effective on $Scope. Sign in with a principal that can assign Key Vault RBAC roles before onboarding."
    }
}

# Resolve the target-declared mapping before building any role-assignment plan.
$target = Get-Vault $TargetVaultResourceId
Assert-EligibleVault $target $TargetVaultResourceId $tenantId 'target'
$sourceId = Get-TagValue $target 'sync-source-keyvault-id'
if ($sourceId -notmatch $vaultPattern) {
    throw 'The target vault must declare a valid sync-source-keyvault-id.'
}
$source = Get-Vault $sourceId
Assert-EligibleVault $source $sourceId $tenantId 'source'

# Build the full supported object-replication onboarding plan. The source
# administrator role is intentionally broad because backup/restore of all Key
# Vault object types is not covered by the reader/user roles. The source Data
# Access Administrator grant is requested for operator-directed source
# role-assignment management; the runtime never writes assignments at source scope.
$sourceId = [string] $source.id
$targetId = [string] $target.id
$sourceSubscriptionId = Get-SubscriptionId $sourceId
$targetSubscriptionId = Get-SubscriptionId $targetId

# Preflight effective inherited/group RBAC assignments before the plan is approved.
# This remains read-only and prevents a later pair from failing after earlier pairs
# have already been onboarded.
Write-Host 'Checking whether the current Azure principal can assign Key Vault RBAC permissions on both vaults.'
$currentPrincipalId = Get-SignedInPrincipalId
Assert-CanManageRbacOnScope -Scope $targetId -SubscriptionId $targetSubscriptionId -PrincipalId $currentPrincipalId
Write-Host 'Verified the current Azure principal can manage role assignments on the target vault.'
Assert-CanManageRbacOnScope -Scope $sourceId -SubscriptionId $sourceSubscriptionId -PrincipalId $currentPrincipalId
Write-Host 'Verified the current Azure principal can manage role assignments on the source vault.'

$plans = @(
    # Key Vault Administrator (source backup/read access)
    [pscustomobject]@{
        Scope = $sourceId
        Subscription = Get-SubscriptionId $sourceId
        RoleId = '00482a5a-887f-4fb3-b363-3b7fe8e74483'
        RoleName = 'Key Vault Administrator'
    }
    # Key Vault Data Access Administrator (source role-assignment management)
    [pscustomobject]@{
        Scope = $sourceId
        Subscription = Get-SubscriptionId $sourceId
        RoleId = '8b54135c-b56d-4d72-a534-26097cfdc8d8'
        RoleName = 'Key Vault Data Access Administrator'
    }
    # Key Vault Administrator
    [pscustomobject]@{
        Scope = $targetId
        Subscription = Get-SubscriptionId $targetId
        RoleId = '00482a5a-887f-4fb3-b363-3b7fe8e74483'
        RoleName = 'Key Vault Administrator'
    }
    # Key Vault Data Access Administrator
    [pscustomobject]@{
        Scope = $targetId
        Subscription = Get-SubscriptionId $targetId
        RoleId = '8b54135c-b56d-4d72-a534-26097cfdc8d8'
        RoleName = 'Key Vault Data Access Administrator'
    }
)

# Preflight existing direct assignments without changing IAM.
$missing = [System.Collections.Generic.List[object]]::new()
foreach ($plan in $plans) {
    $assignments = @(Invoke-AzJson -Arguments @(
        'role', 'assignment', 'list',
        '--scope', $plan.Scope,
        '--assignee-object-id', $principalId,
        '--subscription', $plan.Subscription,
        '--fill-principal-name', 'false'
    ))
    $exists = @($assignments | Where-Object {
        (($_.roleDefinitionId -split '/')[-1]) -ieq $plan.RoleId -and
        (Normalize-ResourceId $_.scope) -eq (Normalize-ResourceId $plan.Scope)
    }).Count -gt 0
    if (-not $exists) { [void] $missing.Add($plan) }
}

Write-Host 'KeyVaultSync vault access plan'
Write-Host "  Source subscription: $(Get-SubscriptionId $sourceId)"
Write-Host "  Target subscription: $(Get-SubscriptionId $targetId)"
foreach ($plan in $plans) {
    $status = if ($missing.Contains($plan)) { 'create' } else { 'existing' }
    Write-Host "  - $($plan.RoleName) at $($plan.Scope) [$status]"
}

if (-not $Apply) {
    Write-Host 'Preview only; no role assignments were changed.'
    return
}

# Re-read both endpoints immediately before the first mutation.
$currentTarget = Get-Vault $targetId
$currentSource = Get-Vault $sourceId
Assert-EligibleVault $currentTarget $targetId $tenantId 'target'
Assert-EligibleVault $currentSource $sourceId $tenantId 'source'
if ((Normalize-ResourceId (Get-TagValue $currentTarget 'sync-source-keyvault-id')) -ne (Normalize-ResourceId $sourceId)) {
    throw 'The target mapping changed after preflight; no permissions were changed.'
}

foreach ($plan in $missing) {
    # ShouldProcess preserves PowerShell -WhatIf/-Confirm behavior at the mutation boundary.
    if ($PSCmdlet.ShouldProcess("$($plan.Scope) / $($plan.RoleName)", 'Create direct role assignment')) {
        [void] (Invoke-AzJson -Arguments @(
            'role', 'assignment', 'create',
            '--assignee-object-id', $principalId,
            '--assignee-principal-type', 'ServicePrincipal',
            '--role', $plan.RoleId,
            '--scope', $plan.Scope,
            '--subscription', $plan.Subscription
        ))
    }
}

Write-Host "Vault access onboarding completed; $($missing.Count) role assignment(s) were created."
