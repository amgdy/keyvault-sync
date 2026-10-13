$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$grantScript = Join-Path $repositoryRoot 'scripts/Grant-KeyVaultAccess.ps1'
$sourceSubscription = '11111111-1111-1111-1111-111111111111'
$targetSubscription = '22222222-2222-2222-2222-222222222222'
$tenantId = '33333333-3333-3333-3333-333333333333'
$principalId = '44444444-4444-4444-4444-444444444444'
$identityId = "/subscriptions/$sourceSubscription/resourceGroups/identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/keyvaultsync"
$sourceId = "/subscriptions/$sourceSubscription/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-vault"
$targetId = "/subscriptions/$targetSubscription/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-vault"

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Get-Argument {
    param([string[]] $Arguments, [string] $Name)
    for ($index = 0; $index -lt ($Arguments.Count - 1); $index++) {
        if ($Arguments[$index] -eq $Name) { return $Arguments[$index + 1] }
    }
    return $null
}

function To-Json {
    param($Value)
    ConvertTo-Json -InputObject $Value -Depth 100 -Compress
}

function Reset-Fixture {
    $global:Fixture = [ordered]@{
        Identity = [pscustomobject]@{ principalId = $principalId; tenantId = $tenantId }
        AccountTenantId = $tenantId
        Source = [pscustomobject]@{
            id = $sourceId
            tags = [pscustomobject]@{}
            properties = [pscustomobject]@{ tenantId = $tenantId; enableRbacAuthorization = $true }
        }
        Target = [pscustomobject]@{
            id = $targetId
            tags = [pscustomobject]@{ 'sync-source-keyvault-id' = $sourceId }
            properties = [pscustomobject]@{ tenantId = $tenantId; enableRbacAuthorization = $true }
        }
        Assignments = @()
        Calls = [System.Collections.Generic.List[object]]::new()
        Drift = $false
        TargetReads = 0
        OperatorRbacDeniedScope = $null
        OperatorRoleName = 'Owner'
        OperatorRbacReadFailureScope = $null
        AzureCliAuthenticated = $true
        AzdIdentity = $null
        AzdFailure = $false
        AzdCalls = [System.Collections.Generic.List[object]]::new()
    }
}

function az {
    $argumentsList = @($args | ForEach-Object { [string] $_ })
    [void] $global:Fixture.Calls.Add([string[]] $argumentsList)
    $global:LASTEXITCODE = 0
    $command = "$($argumentsList[0]) $($argumentsList[1]) $($argumentsList[2])"
    switch -Regex ($command) {
        '^identity show ' {
            return To-Json $global:Fixture.Identity
        }
        '^account show ' {
            if ($argumentsList -contains 'none' -and -not $global:Fixture.AzureCliAuthenticated) {
                $global:LASTEXITCODE = 1
                return 'Please run az login.'
            }
            return To-Json ([pscustomobject]@{ tenantId = $global:Fixture.AccountTenantId; user = [pscustomobject]@{ name = $principalId } })
        }
        '^ad signed-in-user show$' {
            return $principalId
        }
        '^keyvault show ' {
            $id = Get-Argument $argumentsList '--ids'
            if ($id -ieq $targetId) {
                $global:Fixture.TargetReads++
                if ($global:Fixture.Drift -and $global:Fixture.TargetReads -gt 1) {
                    $copy = $global:Fixture.Target | Select-Object *
                    $copy.tags = [pscustomobject]@{ 'sync-source-keyvault-id' = "$sourceId/changed" }
                    return To-Json $copy
                }
                return To-Json $global:Fixture.Target
            }
            if ($id -ieq $sourceId) { return To-Json $global:Fixture.Source }
            $global:LASTEXITCODE = 44
            return '{"error":"not found"}'
        }
        '^role assignment list$' {
            $scope = Get-Argument $argumentsList '--scope'
            if ($argumentsList -contains '--include-inherited') {
                if ($global:Fixture.OperatorRbacReadFailureScope -ieq $scope) {
                    $global:LASTEXITCODE = 55
                    return '{"error":"mock role assignment read failure"}'
                }
                if ($global:Fixture.OperatorRbacDeniedScope -ieq $scope) {
                    return '[]'
                }
                return To-Json -Value @([pscustomobject]@{
                    scope = $scope
                    principalId = $principalId
                    roleDefinitionName = $global:Fixture.OperatorRoleName
                })
            }
            return To-Json -Value @($global:Fixture.Assignments | Where-Object {
                $_.scope -ieq $scope -and $_.principalId -ieq $principalId
            })
        }
        '^role assignment create$' {
            $scope = Get-Argument $argumentsList '--scope'
            $role = Get-Argument $argumentsList '--role'
            $assignment = [pscustomobject]@{
                scope = $scope
                principalId = $principalId
                roleDefinitionId = "/providers/Microsoft.Authorization/roleDefinitions/$role"
            }
            $global:Fixture.Assignments = @($global:Fixture.Assignments) + @($assignment)
            return To-Json $assignment
        }
        default {
            $global:LASTEXITCODE = 99
            return '{"error":"unexpected mock call"}'
        }
    }
}

function azd {
    $argumentsList = @($args | ForEach-Object { [string] $_ })
    [void] $global:Fixture.AzdCalls.Add([string[]] $argumentsList)
    if ($global:Fixture.AzdFailure) {
        $global:LASTEXITCODE = 42
        return
    }
    $global:LASTEXITCODE = 0
    return $global:Fixture.AzdIdentity
}

function Get-WriteCount {
    return @($global:Fixture.Calls | Where-Object {
        $_.Count -ge 3 -and $_[0] -eq 'role' -and $_[1] -eq 'assignment' -and $_[2] -eq 'create'
    }).Count
}

# Report every created assignment as a sorted "<scope> <roleId>" line so the test
# pins the onboarding plan itself rather than only its size.
function Get-CreatedGrants {
    return @($global:Fixture.Calls | Where-Object {
        $_.Count -ge 3 -and $_[0] -eq 'role' -and $_[1] -eq 'assignment' -and $_[2] -eq 'create'
    } | ForEach-Object {
        "$(Get-Argument $_ '--scope') $(Get-Argument $_ '--role')"
    } | Sort-Object)
}

$keyVaultAdministrator = '00482a5a-887f-4fb3-b363-3b7fe8e74483'
$keyVaultDataAccessAdministrator = '8b54135c-b56d-4d72-a534-26097cfdc8d8'
$expectedGrants = @(
    "$sourceId $keyVaultAdministrator"
    "$sourceId $keyVaultDataAccessAdministrator"
    "$targetId $keyVaultAdministrator"
    "$targetId $keyVaultDataAccessAdministrator"
) | Sort-Object


Reset-Fixture
$env:KEYVAULTSYNC_IDENTITY_RESOURCE_ID = "'$identityId'"
& $grantScript -TargetVaultResourceId $targetId
Assert-True ($global:Fixture.AzdCalls.Count -eq 0) 'process environment identity should avoid azd lookup'
Remove-Item Env:KEYVAULTSYNC_IDENTITY_RESOURCE_ID

Reset-Fixture
$global:Fixture.AzdIdentity = "  `"$identityId`"  "
$env:AZURE_ENV_NAME = 'test-environment'
& $grantScript -TargetVaultResourceId $targetId
Assert-True ($global:Fixture.AzdCalls.Count -eq 1) 'omitted identity should query azd once'
Assert-True (($global:Fixture.AzdCalls[0] -join ' ') -eq 'env get-value KEYVAULTSYNC_IDENTITY_RESOURCE_ID --environment test-environment') 'azd lookup should use the selected environment'
Remove-Item Env:AZURE_ENV_NAME

Reset-Fixture
$global:Fixture.AzdIdentity = '/invalid/identity'
& $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId
Assert-True ($global:Fixture.AzdCalls.Count -eq 0) 'explicit identity should take precedence over azd'

Reset-Fixture
$global:Fixture.AzdIdentity = '/invalid/identity'
try {
    & $grantScript -TargetVaultResourceId $targetId
    throw 'Expected malformed azd identity failure.'
}
catch {
    Assert-True ($_.Exception.Message -like '*user-assigned managed identity ARM resource ID*') 'malformed azd identity should fail validation'
}
Assert-True ($global:Fixture.Calls.Count -eq 0) 'malformed identity should fail before Azure reads'

Reset-Fixture
try {
    & $grantScript -TargetVaultResourceId $targetId
    throw 'Expected unresolved azd identity failure.'
}
catch {
    Assert-True ($_.Exception.Message -like '*No managed identity was resolved*') 'missing azd identity should fail clearly'
}
Assert-True ($global:Fixture.Calls.Count -eq 0) 'missing identity should fail before Azure reads'

Reset-Fixture
$global:Fixture.AzureCliAuthenticated = $false
try {
    & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId
    throw 'Expected missing Azure CLI authentication failure.'
}
catch {
    Assert-True ($_.Exception.Message -like '*Run az login once*') 'missing Azure CLI authentication should give one-login guidance'
}
Assert-True ((Get-WriteCount) -eq 0) 'authentication failure must happen before writes'

Reset-Fixture
$global:Fixture.Identity.tenantId = '55555555-5555-5555-5555-555555555555'
try {
    & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId
    throw 'Expected identity tenant mismatch failure.'
}
catch {
    Assert-True ($_.Exception.Message -like '*runtime identity must belong to the same tenant*') 'identity tenant mismatch should fail closed'
}
Assert-True ((Get-WriteCount) -eq 0) 'identity tenant mismatch must happen before writes'

Reset-Fixture
& $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId
Assert-True ((Get-WriteCount) -eq 0) 'preview must not write'
$operatorChecks = @($global:Fixture.Calls | Where-Object {
    $_.Count -ge 3 -and $_[0] -eq 'role' -and $_[1] -eq 'assignment' -and $_[2] -eq 'list' -and
    $_ -contains '--include-inherited' -and $_ -contains '--include-groups'
})
Assert-True ($operatorChecks.Count -eq 2) 'preview should check inherited and group RBAC on both vaults'

Reset-Fixture
$global:Fixture.OperatorRoleName = 'Role Based Access Control Administrator'
& $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId
Assert-True ((Get-WriteCount) -eq 0) 'RBAC Administrator authority check should remain read-only'

Reset-Fixture
$global:Fixture.OperatorRbacReadFailureScope = $targetId
try {
    & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId
    throw 'Expected operator RBAC read failure.'
}
catch {
    Assert-True ($_.Exception.Message -like '*Azure CLI failed (55)*mock role assignment read failure*') 'operator RBAC read failure should preserve Azure CLI diagnostics'
}
Assert-True ((Get-WriteCount) -eq 0) 'operator RBAC read failure must happen before writes'

Reset-Fixture
& $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId -Apply -Confirm:$false
Assert-True ((Get-WriteCount) -eq 4) 'apply should create four missing assignments'
Assert-True ((Compare-Object (Get-CreatedGrants) $expectedGrants) -eq $null) 'apply should create the expected scope and role pairs'
Assert-True ($global:Fixture.Assignments.Count -eq 4) 'all assignments should be recorded'

$global:Fixture.Calls.Clear()
& $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId -Apply -Confirm:$false
Assert-True ((Get-WriteCount) -eq 0) 'second apply should be idempotent'

Reset-Fixture
$global:Fixture.Source.properties.enableRbacAuthorization = $false
try {
    & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId -Apply -Confirm:$false
    throw 'Expected non-RBAC source failure.'
}
catch {
    Assert-True ($_.Exception.Message -like '*Azure RBAC enabled*') 'non-RBAC source should fail closed'
}
Assert-True ((Get-WriteCount) -eq 0) 'eligibility failure must happen before writes'

Reset-Fixture
$global:Fixture.Drift = $true
try {
    & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId -Apply -Confirm:$false
    throw 'Expected mapping drift failure.'
}
catch {
    Assert-True ($_.Exception.Message -like '*mapping changed*') 'mapping drift should fail closed'
}
Assert-True ((Get-WriteCount) -eq 0) 'mapping drift must happen before writes'

Reset-Fixture
$global:Fixture.OperatorRbacDeniedScope = $targetId
try {
    & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId
    throw 'Expected missing target operator RBAC authority failure.'
}
catch {
    Assert-True ($_.Exception.Message -like '*does not have Owner, User Access Administrator, or Role Based Access Control Administrator*') 'operator RBAC authority should be required during preview'
}
Assert-True ((Get-WriteCount) -eq 0) 'operator RBAC validation must remain read-only'

Write-Host 'Grant-KeyVaultAccess.ps1 offline tests passed.'
