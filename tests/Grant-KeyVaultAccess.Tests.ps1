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
            return To-Json ([pscustomobject]@{ tenantId = $tenantId })
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
& $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId
Assert-True ((Get-WriteCount) -eq 0) 'preview must not write'

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

Write-Host 'Grant-KeyVaultAccess.ps1 offline tests passed.'
