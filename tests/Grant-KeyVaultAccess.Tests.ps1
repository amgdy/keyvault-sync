$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$grantScript = Join-Path $repositoryRoot 'scripts/Grant-KeyVaultAccess.ps1'
$subscriptionId = '11111111-1111-1111-1111-111111111111'
$tenantId = '22222222-2222-2222-2222-222222222222'
$principalId = '33333333-3333-3333-3333-333333333333'
$fixtureWriterRoleId = '44444444-4444-4444-4444-444444444444'
$fixtureBackupRoleId = '55555555-5555-5555-5555-555555555555'
$fixtureRestoreRoleId = '66666666-6666-6666-6666-666666666666'
$subscriptionScope = "/subscriptions/$subscriptionId"
$identityId = "$subscriptionScope/resourceGroups/identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-keyvaultsync"
$sourceId = "$subscriptionScope/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-vault"
$targetId = "$subscriptionScope/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-vault"
$otherId = "$subscriptionScope/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/other-vault"

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Convert-FixtureToJson {
    param($Value)
    return ConvertTo-Json -InputObject $Value -Depth 100 -Compress
}

function Get-MockArgument {
    param([string[]] $Arguments, [string] $Name)
    for ($index = 0; $index -lt ($Arguments.Count - 1); $index++) {
        if ($Arguments[$index] -eq $Name) { return $Arguments[$index + 1] }
    }
    return $null
}

function Get-MockPermissionValues {
    param([string[]] $Arguments, [string] $Name)
    $values = @()
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        if ($Arguments[$index] -eq $Name) {
            for ($next = $index + 1; $next -lt $Arguments.Count -and -not $Arguments[$next].StartsWith('--'); $next++) {
                $values += $Arguments[$next]
            }
            break
        }
    }
    return $values
}

function Reset-Fixture {
    param([ValidateSet('Rbac', 'Legacy', 'SourceRbac')][string] $Mode = 'Rbac')

    $sourceRbac = $Mode -ne 'Legacy'
    $targetRbac = $Mode -eq 'Rbac'
    $source = [pscustomobject]@{
        id = $sourceId
        name = 'source-vault'
        resourceGroup = 'vaults'
        tags = [pscustomobject]@{ 'sync-vault-id' = $targetId }
        properties = [pscustomobject]@{ tenantId = $tenantId; enableRbacAuthorization = $sourceRbac; accessPolicies = @() }
    }
    $target = [pscustomobject]@{
        id = $targetId
        name = 'target-vault'
        resourceGroup = 'vaults'
        tags = [pscustomobject]@{}
        properties = [pscustomobject]@{ tenantId = $tenantId; enableRbacAuthorization = $targetRbac; accessPolicies = @() }
    }
    $other = [pscustomobject]@{
        id = $otherId
        name = 'other-vault'
        resourceGroup = 'vaults'
        tags = [pscustomobject]@{}
        properties = [pscustomobject]@{ tenantId = $tenantId; enableRbacAuthorization = $true; accessPolicies = @() }
    }
    $global:Fixture = [ordered]@{
        Identity = [pscustomobject]@{ id = $identityId; principalId = $principalId; tenantId = $tenantId }
        OperatorTenant = $tenantId
        Vaults = @($source, $target, $other)
        Assignments = @()
        Definitions = @()
        Calls = [System.Collections.Generic.List[object]]::new()
        Drift = $false
        FailTarget = $false
    }
}

function Assert-NoWrites {
    $writeCalls = @($global:Fixture.Calls | Where-Object {
        ($_.Count -ge 3 -and $_[0] -eq 'role' -and $_[1] -eq 'assignment' -and $_[2] -eq 'create') -or
        ($_.Count -ge 3 -and $_[0] -eq 'role' -and $_[1] -eq 'definition' -and $_[2] -eq 'create') -or
        ($_.Count -ge 2 -and $_[0] -eq 'keyvault' -and $_[1] -eq 'set-policy')
    })
    Assert-True ($writeCalls.Count -eq 0) 'preview/WhatIf must not invoke an Azure write command'
}

function az {
    $argumentsList = @($args | ForEach-Object { [string] $_ })
    [void] $global:Fixture.Calls.Add([string[]] $argumentsList)
    $global:LASTEXITCODE = 0
    $command = "$($argumentsList[0]) $($argumentsList[1]) $($argumentsList[2])"

    switch -Regex ($command) {
        '^identity show ' {
            return (Convert-FixtureToJson $global:Fixture.Identity)
        }
        '^account show ' {
            return (Convert-FixtureToJson ([pscustomobject]@{ tenantId = $global:Fixture.OperatorTenant }))
        }
        '^keyvault list' {
            return (Convert-FixtureToJson -Value @($global:Fixture.Vaults))
        }
        '^keyvault show ' {
            $name = Get-MockArgument $argumentsList '--name'
            $resourceGroup = Get-MockArgument $argumentsList '--resource-group'
            $vault = @($global:Fixture.Vaults | Where-Object {
                $_.name -ieq $name -and $_.resourceGroup -ieq $resourceGroup
            }) | Select-Object -First 1
            if ($null -eq $vault) {
                $global:LASTEXITCODE = 1
                return '{"error":"Vault not found"}'
            }
            $resourceId = $vault.id
            if ($global:Fixture.Drift -and $resourceId -ieq $sourceId) {
                $showCount = @($global:Fixture.Calls | Where-Object { $_.Count -ge 2 -and $_[0] -eq 'keyvault' -and $_[1] -eq 'show' }).Count
                if ($showCount -gt 2) { $vault.tags.'sync-vault-id' = $otherId }
            }
            return (Convert-FixtureToJson $vault)
        }
        '^role assignment list$' {
            $scope = Get-MockArgument $argumentsList '--scope'
            $assignee = Get-MockArgument $argumentsList '--assignee-object-id'
            $result = @($global:Fixture.Assignments | Where-Object { $_.scope -ieq $scope -and $_.principalId -ieq $assignee })
            return (Convert-FixtureToJson -Value $result)
        }
        '^role assignment create$' {
            $scope = Get-MockArgument $argumentsList '--scope'
            if ($global:Fixture.FailTarget -and $scope -ieq $targetId) {
                $global:LASTEXITCODE = 73
                return '{"error":"simulated assignment failure"}'
            }
            $roleId = Get-MockArgument $argumentsList '--role'
            $assignee = Get-MockArgument $argumentsList '--assignee-object-id'
            $assignment = [pscustomobject]@{
                scope = $scope
                roleDefinitionId = "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/$roleId"
                principalId = $assignee
                condition = $null
            }
            $global:Fixture.Assignments = @($global:Fixture.Assignments) + @($assignment)
            return (Convert-FixtureToJson $assignment)
        }
        '^role definition list$' {
            $name = Get-MockArgument $argumentsList '--name'
            return (Convert-FixtureToJson -Value @($global:Fixture.Definitions | Where-Object { $_.roleName -eq $name }))
        }
        '^role definition create$' {
            $definitionJson = Get-MockArgument $argumentsList '--role-definition'
            $inputDefinition = ConvertFrom-Json -InputObject $definitionJson -Depth 100
            $roleId = if ($inputDefinition.Name -like '*Native Backup*') { $fixtureBackupRoleId }
                elseif ($inputDefinition.Name -like '*Native Restore*') { $fixtureRestoreRoleId }
                else { $fixtureWriterRoleId }
            $definition = [pscustomobject]@{
                name = $roleId
                roleName = $inputDefinition.Name
                roleType = 'CustomRole'
                assignableScopes = @($inputDefinition.AssignableScopes)
                permissions = @([pscustomobject]@{
                    actions = @($inputDefinition.Actions)
                    notActions = @($inputDefinition.NotActions)
                    dataActions = @($inputDefinition.DataActions)
                    notDataActions = @($inputDefinition.NotDataActions)
                })
            }
            $global:Fixture.Definitions = @($global:Fixture.Definitions) + @($definition)
            return (Convert-FixtureToJson $definition)
        }
        '^keyvault set-policy' {
            $vaultName = Get-MockArgument $argumentsList '--name'
            $principal = Get-MockArgument $argumentsList '--object-id'
            $tenant = Get-MockArgument $argumentsList '--tenant-id'
            $vault = @($global:Fixture.Vaults | Where-Object { $_.name -eq $vaultName }) | Select-Object -First 1
            $permissions = [pscustomobject]@{
                keys = @(Get-MockPermissionValues $argumentsList '--key-permissions')
                certificates = @(Get-MockPermissionValues $argumentsList '--certificate-permissions')
                secrets = @(Get-MockPermissionValues $argumentsList '--secret-permissions')
                storage = @(Get-MockPermissionValues $argumentsList '--storage-permissions')
            }
            $existing = @($vault.properties.accessPolicies | Where-Object { $_.objectId -ieq $principal }) | Select-Object -First 1
            if ($null -eq $existing) {
                $newPolicy = [pscustomobject]@{ objectId = $principal; tenantId = $tenant; permissions = $permissions }
                $vault.properties.accessPolicies = @($vault.properties.accessPolicies) + @($newPolicy)
            }
            else {
                $existing.permissions = $permissions
            }
            return '{}'
        }
        default {
            $global:LASTEXITCODE = 99
            return "Unexpected mocked Azure CLI call: $($argumentsList -join ' ')"
        }
    }
}

Reset-Fixture -Mode Legacy
$output = & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $sourceId 6>&1 | Out-String
Assert-True ($output.Contains('Preview only')) 'PowerShell default should preview'
Assert-True ($output.Contains('Mode: mapping-driven-sync')) 'PowerShell preview should report mapping-driven operation'
Assert-True ($output.Contains('Native key/certificate seed permissions: enabled')) 'default preview should include native permissions'
Assert-NoWrites
Write-Output 'PASS PowerShell default mapping-driven preview is pair-scoped and read-only'

$output = & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $sourceId -Apply -Confirm:$false 6>&1 | Out-String
$sourcePolicy = @($global:Fixture.Vaults[0].properties.accessPolicies | Where-Object { $_.objectId -eq $principalId })[0]
$targetPolicy = @($global:Fixture.Vaults[1].properties.accessPolicies | Where-Object { $_.objectId -eq $principalId })[0]
Assert-True ((@($sourcePolicy.permissions.secrets | Sort-Object -Unique) -join ',') -eq 'get,list') 'source legacy secret permissions'
Assert-True ((@($targetPolicy.permissions.secrets | Sort-Object -Unique) -join ',') -eq 'get,list,set') 'target legacy secret permissions'
Assert-True ((@($sourcePolicy.permissions.keys | Sort-Object -Unique) -join ',') -eq 'backup,get,list') 'source key permissions include backup'
Assert-True ((@($sourcePolicy.permissions.certificates | Sort-Object -Unique) -join ',') -eq 'backup,get,list') 'source certificate permissions include backup'
Assert-True ((@($targetPolicy.permissions.keys | Sort-Object -Unique) -join ',') -eq 'get,list,restore') 'target key permissions include restore'
Assert-True ((@($targetPolicy.permissions.certificates | Sort-Object -Unique) -join ',') -eq 'get,list,restore') 'target certificate permissions include restore'
Write-Output 'PASS PowerShell applies default source-read/target-write and native legacy policies'

Reset-Fixture -Mode Rbac
$output = & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $sourceId -Apply -Confirm:$false 6>&1 | Out-String
Assert-True ($global:Fixture.Assignments.Count -eq 6) 'RBAC sync should add Reader, secret, backup, writer, and restore pair grants'
Assert-True ($global:Fixture.Definitions.Count -eq 3) 'RBAC sync should create writer, backup, and restore roles'
$sourceAssignments = @($global:Fixture.Assignments | Where-Object { $_.scope -ieq $sourceId })
$targetAssignments = @($global:Fixture.Assignments | Where-Object { $_.scope -ieq $targetId })
Assert-True ($sourceAssignments.Count -eq 3) 'source RBAC grants should include Reader, Secrets User, and backup'
Assert-True ($targetAssignments.Count -eq 3) 'target RBAC grants should include Reader, writer, and restore'
$writerDefinition = @($global:Fixture.Definitions | Where-Object { $_.roleName -like '*Secret Writer*' })[0]
$backupDefinition = @($global:Fixture.Definitions | Where-Object { $_.roleName -like '*Native Backup*' })[0]
$restoreDefinition = @($global:Fixture.Definitions | Where-Object { $_.roleName -like '*Native Restore*' })[0]
$actualWriterActions = (@($writerDefinition.permissions[0].dataActions | Sort-Object) -join ',')
$expectedWriterActions = (@(
    'Microsoft.KeyVault/vaults/secrets/getSecret/action',
    'Microsoft.KeyVault/vaults/secrets/readMetadata/action',
    'Microsoft.KeyVault/vaults/secrets/setSecret/action',
    'Microsoft.KeyVault/vaults/secrets/update/action'
) | Sort-Object) -join ','
Assert-True ($actualWriterActions -eq $expectedWriterActions) 'RBAC target writer role actions'
Assert-True ((@($backupDefinition.permissions[0].dataActions | Sort-Object) -join ',') -eq
    'Microsoft.KeyVault/vaults/certificates/backup/action,Microsoft.KeyVault/vaults/keys/backup/action') 'source backup role actions'
Assert-True ((@($restoreDefinition.permissions[0].dataActions | Sort-Object) -join ',') -eq
    'Microsoft.KeyVault/vaults/certificates/restore/action,Microsoft.KeyVault/vaults/keys/restore/action') 'target restore role actions'
Write-Output 'PASS PowerShell default RBAC grants include narrow secret and native permissions'

Reset-Fixture -Mode Rbac
$global:Fixture.Vaults[0].tags.PSObject.Properties.Remove('sync-vault-id')
$global:Fixture.Vaults[1].tags | Add-Member -NotePropertyName 'sync-source-keyvault-id' -NotePropertyValue $sourceId
$output = & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId 6>&1 | Out-String
Assert-True ($output.Contains('Mapping: sync-source-keyvault-id')) 'target-side mapping should be identified in the preview'
Assert-NoWrites
$output = & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId -Apply -Confirm:$false 6>&1 | Out-String
Assert-True ($global:Fixture.Assignments.Count -eq 6) 'target-side mapping should grant the complete profile only to the selected pair'
Write-Output 'PASS PowerShell target-side reverse mapping supports preview and scoped grants'

Reset-Fixture -Mode Rbac
$global:Fixture.Vaults[0].tags.'sync-vault-id' = $otherId
$global:Fixture.Vaults[1].tags | Add-Member -NotePropertyName 'sync-source-keyvault-id' -NotePropertyValue $sourceId
$output = & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId -Apply -Confirm:$false 6>&1 | Out-String
Assert-True ($global:Fixture.Assignments.Count -eq 6) 'reverse target should remain valid when its source maps to a different target'
Assert-True (@($global:Fixture.Assignments | Where-Object { $_.scope -ieq $otherId }).Count -eq 0) 'unselected source target must not receive grants'
Write-Output 'PASS PowerShell reverse mapping supports an additional target without modifying the source mapping'

$conflictingMappingFailed = $false
Reset-Fixture -Mode Rbac
$global:Fixture.Vaults[1].tags | Add-Member -NotePropertyName 'sync-source-keyvault-id' -NotePropertyValue $otherId
try {
    $null = & $grantScript -IdentityResourceId $identityId -TargetVaultResourceId $targetId -Apply -Confirm:$false 6>&1
}
catch {
    $conflictingMappingFailed = $true
}
Assert-True $conflictingMappingFailed 'a reverse mapping must not conflict with a different forward owner'
Assert-NoWrites
Write-Output 'PASS PowerShell rejects conflicting source/target declarations before writes'

Reset-Fixture -Mode SourceRbac
$output = & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $sourceId -Apply -Confirm:$false 6>&1 | Out-String
Assert-True ($global:Fixture.Assignments.Count -eq 3) 'mixed mode should grant source Reader, secret read, and backup RBAC roles'
Assert-True ((@($global:Fixture.Vaults[1].properties.accessPolicies[0].permissions.secrets | Sort-Object) -join ',') -eq 'get,list,set') 'mixed-mode target legacy permissions'
$mixedTargetPermissions = $global:Fixture.Vaults[1].properties.accessPolicies[0].permissions
Assert-True ((@($mixedTargetPermissions.keys | Sort-Object) -join ',') -eq 'get,list,restore') 'mixed-mode target key restore permissions'
Assert-True ((@($mixedTargetPermissions.certificates | Sort-Object) -join ',') -eq 'get,list,restore') 'mixed-mode target certificate restore permissions'
Assert-True ($global:Fixture.Definitions.Count -eq 1 -and $global:Fixture.Definitions[0].roleName -like '*Native Backup*') 'mixed mode should create only the source backup role'
Write-Output 'PASS PowerShell default mixed RBAC/legacy secret and native permissions'

Reset-Fixture -Mode Legacy
$output = & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $sourceId -Apply -Confirm:$false 6>&1 | Out-String
Assert-True ($global:Fixture.Assignments.Count -eq 0) 'legacy native seed must not create role assignments'
Assert-True ($global:Fixture.Definitions.Count -eq 0) 'legacy native seed must not create custom roles'
$sourcePolicy = @($global:Fixture.Vaults[0].properties.accessPolicies | Where-Object { $_.objectId -eq $principalId })[0]
$targetPolicy = @($global:Fixture.Vaults[1].properties.accessPolicies | Where-Object { $_.objectId -eq $principalId })[0]
Assert-True ((@($sourcePolicy.permissions.keys | Sort-Object) -join ',') -eq 'backup,get,list') 'legacy source key backup permissions'
Assert-True ((@($sourcePolicy.permissions.certificates | Sort-Object) -join ',') -eq 'backup,get,list') 'legacy source certificate backup permissions'
Assert-True ((@($targetPolicy.permissions.keys | Sort-Object) -join ',') -eq 'get,list,restore') 'legacy target key restore permissions'
Assert-True ((@($targetPolicy.permissions.certificates | Sort-Object) -join ',') -eq 'get,list,restore') 'legacy target certificate restore permissions'
Write-Output 'PASS PowerShell default legacy permissions preserve pair direction'

Reset-Fixture -Mode Rbac
$output = & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $sourceId -Apply -WhatIf 6>&1 | Out-String
Assert-NoWrites
Write-Output 'PASS PowerShell -WhatIf suppresses all mapping-driven writes'

foreach ($retiredParameter in @('MetadataOnly', 'NativeSeed')) {
    $retiredParameterFailed = $false
    try {
        $null = & $grantScript -IdentityResourceId $identityId -SourceVaultResourceId $sourceId "-$retiredParameter" 6>&1
    }
    catch {
        $retiredParameterFailed = $true
    }
    Assert-True $retiredParameterFailed "retired onboarding switch -$retiredParameter should be rejected"
    Assert-NoWrites
}
Write-Output 'PASS PowerShell rejects retired onboarding profile switches without writes'

Write-Output 'All PowerShell onboarding checks passed without live Azure calls.'
