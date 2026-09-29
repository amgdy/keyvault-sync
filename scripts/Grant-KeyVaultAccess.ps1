[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Source')]
param(
    [Parameter(Mandatory = $true)]
    [string] $IdentityResourceId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Source')]
    [string] $SourceVaultResourceId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Target')]
    [string] $TargetVaultResourceId,

    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
$pairTag = 'sync-vault-id'
$sourceTag = 'sync-source-keyvault-id'
$readerRoleId = '21090545-7ca7-4776-b22c-e363652d74d2'
$secretReaderRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
$pendingWriterRoleId = 'pending-writer-role'
$pendingNativeBackupRoleId = 'pending-native-backup-role'
$pendingNativeRestoreRoleId = 'pending-native-restore-role'
$guidPattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
$identityPattern = "(?i)^/subscriptions/$guidPattern/resourceGroups/[^/]+/providers/Microsoft.ManagedIdentity/userAssignedIdentities/[^/]+$"
$vaultPattern = "(?i)^/subscriptions/$guidPattern/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/[^/]+$"

function Invoke-AzJson {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)

    $commandOutput = & az @Arguments --only-show-errors --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI failed ($LASTEXITCODE): az $($Arguments -join ' ')`n$($commandOutput -join [Environment]::NewLine)"
    }

    $json = $commandOutput -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($json)) {
        return $null
    }

    try {
        return ConvertFrom-Json -InputObject $json -Depth 100
    }
    catch {
        throw "Azure CLI returned invalid JSON for: az $($Arguments -join ' ')"
    }
}

function Get-SubscriptionId {
    param([Parameter(Mandatory = $true)][string] $ResourceId)
    return (($ResourceId.TrimEnd('/') -split '/')[2]).ToLowerInvariant()
}

function Normalize-ResourceId {
    param([Parameter(Mandatory = $true)][string] $ResourceId)
    return $ResourceId.Trim().TrimEnd('/').ToLowerInvariant()
}

function Get-TagValue {
    param(
        [Parameter(Mandatory = $true)] $Resource,
        [Parameter(Mandatory = $true)][string] $Name
    )

    if ($null -eq $Resource.tags) {
        return $null
    }

    $tag = $Resource.tags.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($null -eq $tag -or $tag.Value -isnot [string]) {
        return $null
    }

    $value = $tag.Value.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $null
    }

    return $value
}

function Assert-NotPaused {
    param(
        [Parameter(Mandatory = $true)] $Vault,
        [Parameter(Mandatory = $true)][string] $Side
    )

    if ((Get-TagValue -Resource $Vault -Name 'KeyVaultSyncDisabled') -ieq 'true') {
        throw "Sync is disabled on the $Side vault '$($Vault.name)'; no permissions were changed."
    }
}

function Get-Vault {
    param([Parameter(Mandatory = $true)][string] $ResourceId)

    $segments = $ResourceId.TrimEnd('/') -split '/'
    $resourceGroupName = $segments[4]
    $vaultName = $segments[8]
    $vault = Invoke-AzJson -Arguments @(
        'keyvault', 'show',
        '--name', $vaultName,
        '--resource-group', $resourceGroupName,
        '--subscription', $script:subscriptionId
    )
    if ((Normalize-ResourceId $vault.id) -ne (Normalize-ResourceId $ResourceId) -or
        $vault.properties.tenantId -ine $script:tenantId) {
        throw "Vault metadata is incomplete or does not match the requested ID/tenant: $ResourceId"
    }

    $usesRbac = $vault.properties.enableRbacAuthorization -eq $true
    if ($usesRbac -and $null -eq $vault.properties.accessPolicies) {
        $vault.properties | Add-Member -NotePropertyName accessPolicies -NotePropertyValue @() -Force
    }
    elseif ($vault.properties.accessPolicies -isnot [array]) {
        throw "Vault authorization metadata is incomplete: $ResourceId"
    }

    return $vault
}

function Get-AuthorizationSnapshot {
    param([Parameter(Mandatory = $true)] $Vault)

    $usesRbac = $Vault.properties.enableRbacAuthorization -eq $true
    $tags = @(
        $Vault.tags.PSObject.Properties |
            Sort-Object { $_.Name.ToLowerInvariant() } |
            ForEach-Object { [ordered]@{ name = $_.Name.ToLowerInvariant(); value = $_.Value } }
    )
    $policies = @()
    if (-not $usesRbac) {
        $matchingPolicies = @($Vault.properties.accessPolicies | Where-Object { $_.objectId -ieq $script:principalId })
        if ($matchingPolicies.Count -gt 1 -or
            @($matchingPolicies | Where-Object { -not [string]::IsNullOrWhiteSpace($_.applicationId) -or $_.tenantId -ine $script:tenantId }).Count -gt 0) {
            throw 'Existing UAMI access policy needs manual review (duplicate, tenant, or application-specific entry).'
        }

        foreach ($policy in $matchingPolicies) {
            $normalizedPermissions = [ordered]@{}
            foreach ($kind in @('keys', 'secrets', 'certificates', 'storage')) {
                $values = @()
                if ($null -ne $policy.permissions -and $null -ne $policy.permissions.$kind) {
                    $values = @($policy.permissions.$kind | Sort-Object -Unique)
                }
                $normalizedPermissions[$kind] = $values
            }
            $policies += [ordered]@{
                tenantId = $policy.tenantId.ToLowerInvariant()
                applicationId = if ($policy.applicationId) { $policy.applicationId.ToLowerInvariant() } else { '' }
                permissions = $normalizedPermissions
            }
        }
    }

    return [ordered]@{ rbac = $usesRbac; tags = $tags; policies = @($policies) }
}

function Get-RoleAssignmentSnapshot {
    param(
        [Parameter(Mandatory = $true)] $Assignments,
        [Parameter(Mandatory = $true)][string] $VaultId,
        [Parameter(Mandatory = $true)] $Roles
    )

    $snapshot = @()
    foreach ($assignment in @($Assignments)) {
        $roleId = ($assignment.roleDefinitionId -split '/')[-1]
        $requestedRole = @($Roles | Where-Object { $_.id -ieq $roleId })
        if ($assignment.principalId -ieq $script:principalId -and
            (Normalize-ResourceId $assignment.scope) -eq (Normalize-ResourceId $VaultId) -and
            $requestedRole.Count -gt 0) {
            $snapshot += [ordered]@{
                roleId = $roleId.ToLowerInvariant()
                condition = if ($assignment.condition) { $assignment.condition } else { '' }
                scope = (Normalize-ResourceId $assignment.scope)
            }
        }
    }

    return @($snapshot | Sort-Object roleId, scope)
}

function Get-CustomRolePlan {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $PlaceholderId,
        [Parameter(Mandatory = $true)][string] $SubscriptionId,
        [Parameter(Mandatory = $true)][string] $SubscriptionScope,
        [Parameter(Mandatory = $true)] $Definition
    )

    $definitions = @(Invoke-AzJson -Arguments @(
        'role', 'definition', 'list', '--name', $Name, '--scope', $SubscriptionScope, '--subscription', $SubscriptionId
    ))
    if ($definitions.Count -eq 0) {
        return [pscustomobject]@{
            Id = $PlaceholderId
            PlaceholderId = $PlaceholderId
            Name = $Name
            Definition = $Definition
            SubscriptionId = $SubscriptionId
            SubscriptionScope = $SubscriptionScope
        }
    }

    $definitionRecord = $definitions[0]
    $actualActions = @($definitionRecord.permissions[0].actions | Sort-Object)
    $actualNotActions = @($definitionRecord.permissions[0].notActions | Sort-Object)
    $actualDataActions = @($definitionRecord.permissions[0].dataActions | Sort-Object)
    $actualNotDataActions = @($definitionRecord.permissions[0].notDataActions | Sort-Object)
    $expectedDataActions = @($Definition.DataActions | Sort-Object)
    $actualScopes = @($definitionRecord.assignableScopes | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
    $expectedScopes = @($SubscriptionScope.ToLowerInvariant())
    if ($definitions.Count -ne 1 -or $definitionRecord.roleType -ne 'CustomRole' -or
        $actualActions.Count -ne 0 -or $actualNotActions.Count -ne 0 -or $actualNotDataActions.Count -ne 0 -or
        (Compare-Object $actualDataActions $expectedDataActions -SyncWindow 0) -or
        (Compare-Object $actualScopes $expectedScopes -SyncWindow 0)) {
        throw "The existing named custom role '$Name' differs from the required narrow role; it will not be overwritten."
    }

    return [pscustomobject]@{
        Id = $definitionRecord.name
        PlaceholderId = $PlaceholderId
        Name = $Name
        Definition = $Definition
        SubscriptionId = $SubscriptionId
        SubscriptionScope = $SubscriptionScope
    }
}

function New-VaultPlan {
    param(
        [Parameter(Mandatory = $true)][string] $Side,
        [Parameter(Mandatory = $true)] $Vault
    )

    $vaultId = $Vault.id
    $snapshot = Get-AuthorizationSnapshot -Vault $Vault
    $access = if ($Side -eq 'source') { 'read' } else { 'write' }
    $roles = @()
    $assignmentsSnapshot = @()
    $rolesToAdd = @()
    $permissions = $null
    $needsPolicy = $false

    if ($snapshot.rbac) {
        $roles = @([ordered]@{ id = $readerRoleId; label = 'Key Vault Reader' })
        if ($access -eq 'read') {
            $roles += [ordered]@{ id = $secretReaderRoleId; label = 'Key Vault Secrets User' }
        }
        elseif ($access -eq 'write') {
            $roles += [ordered]@{ id = $script:writerRoleId; label = 'KeyVaultSync Secret Writer' }
        }
        if ($Side -eq 'source') {
            $roles += [ordered]@{ id = $script:nativeBackupRoleId; label = 'KeyVaultSync Native Backup' }
        }
        else {
            $roles += [ordered]@{ id = $script:nativeRestoreRoleId; label = 'KeyVaultSync Native Restore' }
        }

        $vaultSubscription = Get-SubscriptionId $vaultId
        $assignments = Invoke-AzJson -Arguments @(
            'role', 'assignment', 'list', '--assignee-object-id', $script:principalId, '--scope', $vaultId,
            '--include-inherited', '--fill-principal-name', 'false', '--fill-role-definition-name', 'false',
            '--subscription', $vaultSubscription
        )
        $assignmentsSnapshot = @(Get-RoleAssignmentSnapshot -Assignments @($assignments) -VaultId $vaultId -Roles $roles)
        foreach ($role in $roles) {
            $matches = @($assignmentsSnapshot | Where-Object { $_.roleId -ieq $role.id })
            if (@($matches | Where-Object { -not [string]::IsNullOrWhiteSpace($_.condition) }).Count -gt 0) {
                throw "A conditional UAMI role assignment exists on the $Side vault; no permissions were changed."
            }
            if ($matches.Count -eq 0) {
                $rolesToAdd += $role
            }
        }
    }
    else {
        $existing = if ($snapshot.policies.Count -gt 0) { $snapshot.policies[0].permissions } else { $null }
        $secrets = @('list')
        if ($access -eq 'read') { $secrets += 'get' }
        elseif ($access -eq 'write') { $secrets += @('get', 'set') }
        $nativePermissions = if ($Side -eq 'source') { @('backup') } else { @('restore') }
        $permissions = [ordered]@{
            keys = @(@($existing.keys) + @('get', 'list') + $nativePermissions | Sort-Object -Unique)
            certificates = @(@($existing.certificates) + @('get', 'list') + $nativePermissions | Sort-Object -Unique)
            secrets = @(@($existing.secrets) + $secrets | Sort-Object -Unique)
            storage = @($existing.storage | Sort-Object -Unique)
        }
        $currentPermissions = if ($null -eq $existing) {
            [ordered]@{ keys = @(); certificates = @(); secrets = @(); storage = @() }
        }
        else {
            [ordered]@{
                keys = @($existing.keys | Sort-Object -Unique)
                certificates = @($existing.certificates | Sort-Object -Unique)
                secrets = @($existing.secrets | Sort-Object -Unique)
                storage = @($existing.storage | Sort-Object -Unique)
            }
        }
        $needsPolicy = (ConvertTo-Json -InputObject $currentPermissions -Depth 20 -Compress) -cne
            (ConvertTo-Json -InputObject $permissions -Depth 20 -Compress)
    }

    return [ordered]@{
        side = $Side
        id = $vaultId
        name = $Vault.name
        resourceGroup = (($vaultId -split '/')[4])
        subscriptionId = (Get-SubscriptionId $vaultId)
        snapshot = $snapshot
        roles = $roles
        assignmentsSnapshot = $assignmentsSnapshot
        rolesToAdd = $rolesToAdd
        permissions = $permissions
        needsPolicy = $needsPolicy
    }
}

try {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI (az) is required. Sign in with az login using an approved operator identity.'
    }
    if ($IdentityResourceId -notmatch $identityPattern) {
        throw '-IdentityResourceId must be a user-assigned managed identity ARM resource ID.'
    }
    $mappingMode = $PSCmdlet.ParameterSetName.ToLowerInvariant()
    $requestedVaultResourceId = if ($mappingMode -eq 'source') { $SourceVaultResourceId } else { $TargetVaultResourceId }
    if ($requestedVaultResourceId -notmatch $vaultPattern) {
        throw 'The selected source or target must be a Key Vault ARM resource ID.'
    }

    $identitySubscriptionId = Get-SubscriptionId $IdentityResourceId
    $script:subscriptionId = $identitySubscriptionId
    if ((Get-SubscriptionId $requestedVaultResourceId) -ne $identitySubscriptionId) {
        throw 'The selected vault and UAMI must be in the same subscription for this onboarding script.'
    }

    $identity = Invoke-AzJson -Arguments @('identity', 'show', '--ids', $IdentityResourceId)
    if ($identity.tenantId -notmatch $guidPattern -or $identity.principalId -notmatch $guidPattern) {
        throw 'Azure CLI did not return valid UAMI tenant and principal IDs.'
    }
    $script:principalId = $identity.principalId.ToLowerInvariant()
    $script:tenantId = $identity.tenantId.ToLowerInvariant()
    $account = Invoke-AzJson -Arguments @('account', 'show', '--subscription', $identitySubscriptionId)
    if ($account.tenantId -ine $script:tenantId) {
        throw 'The signed-in operator and UAMI must belong to the same tenant.'
    }

    $vaults = @(Invoke-AzJson -Arguments @('keyvault', 'list', '--subscription', $identitySubscriptionId, '--resource-type', 'vault'))
    $mappingTag = $pairTag
    if ($mappingMode -eq 'source') {
        $sourceId = $requestedVaultResourceId
        $source = Get-Vault -ResourceId $sourceId
        $targetId = Get-TagValue -Resource $source -Name $pairTag
        if ([string]::IsNullOrWhiteSpace($targetId)) {
            throw "Source vault is missing the $pairTag target tag."
        }
    }
    else {
        $targetId = $requestedVaultResourceId
        $target = Get-Vault -ResourceId $targetId
        $sourceId = Get-TagValue -Resource $target -Name $sourceTag
        $mappingTag = $sourceTag
        if ([string]::IsNullOrWhiteSpace($sourceId)) {
            throw "Target vault is missing the $sourceTag source tag."
        }
    }
    if ($sourceId -notmatch $vaultPattern) {
        throw 'The source mapping is not a Key Vault ARM resource ID.'
    }
    if ($targetId -notmatch $vaultPattern) {
        throw 'The target mapping is not a Key Vault ARM resource ID.'
    }
    if ((Normalize-ResourceId $targetId) -eq (Normalize-ResourceId $sourceId)) {
        throw 'Source maps to itself.'
    }
    if ((Get-SubscriptionId $sourceId) -ne $identitySubscriptionId -or (Get-SubscriptionId $targetId) -ne $identitySubscriptionId) {
        throw 'Source and target vaults must be in the UAMI subscription for this onboarding script.'
    }

    if ($mappingMode -eq 'source') {
        $target = Get-Vault -ResourceId $targetId
    }
    else {
        $source = Get-Vault -ResourceId $sourceId
    }
    if ((Normalize-ResourceId $source.id) -ne (Normalize-ResourceId $sourceId)) {
        throw 'The resolved source vault does not match its declared ARM resource ID.'
    }
    if ((Normalize-ResourceId $target.id) -ne (Normalize-ResourceId $targetId)) {
        throw 'The resolved target vault does not match its declared ARM resource ID.'
    }
    $inventorySource = @($vaults | Where-Object { (Normalize-ResourceId $_.id) -eq (Normalize-ResourceId $sourceId) })
    $inventoryTarget = @($vaults | Where-Object { (Normalize-ResourceId $_.id) -eq (Normalize-ResourceId $targetId) })
    if ($inventorySource.Count -eq 0 -or $inventoryTarget.Count -eq 0) {
        throw 'Both selected vaults must be present in the UAMI subscription discovery inventory.'
    }

    Assert-NotPaused -Vault $source -Side 'source'
    Assert-NotPaused -Vault $target -Side 'target'
    if (-not [string]::IsNullOrWhiteSpace((Get-TagValue -Resource $target -Name $pairTag))) {
        throw 'Target vault is also tagged as a sync source; chained mappings need manual review.'
    }
    $targetSourceTag = Get-TagValue -Resource $target -Name $sourceTag
    if (-not [string]::IsNullOrWhiteSpace($targetSourceTag) -and
        (Normalize-ResourceId $targetSourceTag) -ne (Normalize-ResourceId $sourceId)) {
        throw "Target $sourceTag conflicts with the selected source vault."
    }
    if ($mappingMode -eq 'target' -and [string]::IsNullOrWhiteSpace($targetSourceTag)) {
        throw "Target vault is missing the $sourceTag source tag."
    }

    $sourceParentId = Get-TagValue -Resource $source -Name $sourceTag
    if (-not [string]::IsNullOrWhiteSpace($sourceParentId)) {
        $sourceParent = @($vaults | Where-Object { (Normalize-ResourceId $_.id) -eq (Normalize-ResourceId $sourceParentId) })
        if ($sourceParent.Count -gt 0) {
            throw 'The source vault is already a mapped target; chained mappings need manual review.'
        }
    }
    $upstreamSources = @($vaults | Where-Object {
        $mappedTarget = Get-TagValue -Resource $_ -Name $pairTag
        -not [string]::IsNullOrWhiteSpace($mappedTarget) -and
        (Normalize-ResourceId $mappedTarget) -eq (Normalize-ResourceId $sourceId)
    })
    if ($upstreamSources.Count -gt 0) {
        throw 'The selected source vault is already a target of another source; chained mappings need manual review.'
    }

    $matchingSources = @($vaults | Where-Object {
        -not [string]::IsNullOrWhiteSpace((Get-TagValue -Resource $_ -Name $pairTag)) -and
        (Normalize-ResourceId (Get-TagValue -Resource $_ -Name $pairTag)) -eq (Normalize-ResourceId $targetId)
    })
    if ($matchingSources.Count -gt 1 -or
        ($matchingSources.Count -eq 1 -and (Normalize-ResourceId $matchingSources[0].id) -ne (Normalize-ResourceId $sourceId)) -or
        ($mappingMode -eq 'source' -and $matchingSources.Count -ne 1)) {
        throw 'Target is missing, duplicated, or mapped by another source in the discovery subscription.'
    }

    $targetSubscriptionId = Get-SubscriptionId $targetId
    $targetSubscriptionScope = "/subscriptions/$targetSubscriptionId"
    $script:writerRoleId = $pendingWriterRoleId
    $script:nativeBackupRoleId = $pendingNativeBackupRoleId
    $script:nativeRestoreRoleId = $pendingNativeRestoreRoleId
    $customRolePlans = @()
    if ($target.properties.enableRbacAuthorization -eq $true) {
        $writerRoleName = "KeyVaultSync Secret Writer ($targetSubscriptionId)"
        $writerRoleDefinition = [ordered]@{
            Name = $writerRoleName
            IsCustom = $true
            Description = 'KeyVaultSync target secret read/set/update only; no delete, purge, backup, restore, or authorization management.'
            Actions = @()
            NotActions = @()
            NotDataActions = @()
            AssignableScopes = @($targetSubscriptionScope)
            DataActions = @(
                'Microsoft.KeyVault/vaults/secrets/readMetadata/action',
                'Microsoft.KeyVault/vaults/secrets/getSecret/action',
                'Microsoft.KeyVault/vaults/secrets/setSecret/action',
                'Microsoft.KeyVault/vaults/secrets/update/action'
            )
        }
        $writerRolePlan = Get-CustomRolePlan -Name $writerRoleName -PlaceholderId $pendingWriterRoleId `
            -SubscriptionId $targetSubscriptionId -SubscriptionScope $targetSubscriptionScope -Definition $writerRoleDefinition
        $script:writerRoleId = $writerRolePlan.Id
        if ($writerRolePlan.Id -eq $pendingWriterRoleId) { $customRolePlans += $writerRolePlan }
    }

    if ($source.properties.enableRbacAuthorization -eq $true) {
        $backupRoleName = "KeyVaultSync Native Backup ($targetSubscriptionId)"
        $backupRoleDefinition = [ordered]@{
            Name = $backupRoleName
            IsCustom = $true
            Description = 'KeyVaultSync source backup for keys and certificates; assign only at the source vault.'
            Actions = @()
            NotActions = @()
            NotDataActions = @()
            AssignableScopes = @($targetSubscriptionScope)
            DataActions = @(
                'Microsoft.KeyVault/vaults/keys/backup/action',
                'Microsoft.KeyVault/vaults/certificates/backup/action'
            )
        }
        $backupRolePlan = Get-CustomRolePlan -Name $backupRoleName -PlaceholderId $pendingNativeBackupRoleId `
            -SubscriptionId $targetSubscriptionId -SubscriptionScope $targetSubscriptionScope -Definition $backupRoleDefinition
        $script:nativeBackupRoleId = $backupRolePlan.Id
        if ($backupRolePlan.Id -eq $pendingNativeBackupRoleId) { $customRolePlans += $backupRolePlan }
    }

    if ($target.properties.enableRbacAuthorization -eq $true) {
        $restoreRoleName = "KeyVaultSync Native Restore ($targetSubscriptionId)"
        $restoreRoleDefinition = [ordered]@{
            Name = $restoreRoleName
            IsCustom = $true
            Description = 'KeyVaultSync target restore for keys and certificates; assign only at the target vault.'
            Actions = @()
            NotActions = @()
            NotDataActions = @()
            AssignableScopes = @($targetSubscriptionScope)
            DataActions = @(
                'Microsoft.KeyVault/vaults/keys/restore/action',
                'Microsoft.KeyVault/vaults/certificates/restore/action'
            )
        }
        $restoreRolePlan = Get-CustomRolePlan -Name $restoreRoleName -PlaceholderId $pendingNativeRestoreRoleId `
            -SubscriptionId $targetSubscriptionId -SubscriptionScope $targetSubscriptionScope -Definition $restoreRoleDefinition
        $script:nativeRestoreRoleId = $restoreRolePlan.Id
        if ($restoreRolePlan.Id -eq $pendingNativeRestoreRoleId) { $customRolePlans += $restoreRolePlan }
    }

    $plans = @(
        (New-VaultPlan -Side 'source' -Vault $source)
        (New-VaultPlan -Side 'target' -Vault $target)
    )

    Write-Host "UAMI principal: $script:principalId"
    Write-Host "Source: $sourceId"
    Write-Host "Target: $targetId"
    Write-Host "Mapping: $mappingTag"
    Write-Host 'Mode: mapping-driven-sync'
    Write-Host 'Native key/certificate seed permissions: enabled (vault-scoped grants)'
    Write-Host "Apply: $Apply"
    foreach ($rolePlan in $customRolePlans) {
        Write-Host "CREATE custom role: $($rolePlan.Name) (subscription assignable scope)"
    }

    foreach ($plan in $plans) {
        if ($plan.snapshot.rbac) {
            if ($plan.rolesToAdd.Count -eq 0) {
                Write-Host "UNCHANGED`t$($plan.side)`t$($plan.id)"
            }
            else {
                foreach ($role in $plan.rolesToAdd) { Write-Host "ADD $($role.label)`t$($plan.side)`t$($plan.id)" }
            }
        }
        elseif ($plan.needsPolicy) {
            $permissionJson = ConvertTo-Json -InputObject $plan.permissions -Depth 20 -Compress
            Write-Host "MERGE legacy access policy`t$($plan.side)`t$($plan.id)`t$permissionJson"
        }
        else {
            Write-Host "UNCHANGED`t$($plan.side)`t$($plan.id)"
        }
    }

    if (-not $Apply) {
        Write-Host 'Preview only. Rerun with -Apply to grant these permissions; the script will re-read both vaults first.'
        return
    }

    foreach ($plan in $plans) {
        $currentVault = Get-Vault -ResourceId $plan.id
        $currentSnapshot = Get-AuthorizationSnapshot -Vault $currentVault
        $expectedSnapshot = ConvertTo-Json -InputObject $plan.snapshot -Depth 100 -Compress
        $actualSnapshot = ConvertTo-Json -InputObject $currentSnapshot -Depth 100 -Compress
        if ($actualSnapshot -cne $expectedSnapshot) {
            throw "Vault tags or authorization changed after preflight: $($plan.id). Rerun the preview."
        }

        if ($plan.snapshot.rbac) {
            $currentAssignments = Invoke-AzJson -Arguments @(
                'role', 'assignment', 'list', '--assignee-object-id', $script:principalId, '--scope', $plan.id,
                '--include-inherited', '--fill-principal-name', 'false', '--fill-role-definition-name', 'false',
                '--subscription', $plan.subscriptionId
            )
            $currentAssignmentSnapshot = @(Get-RoleAssignmentSnapshot -Assignments @($currentAssignments) -VaultId $plan.id -Roles $plan.roles)
            if ((ConvertTo-Json -InputObject $currentAssignmentSnapshot -Depth 20 -Compress) -cne
                (ConvertTo-Json -InputObject $plan.assignmentsSnapshot -Depth 20 -Compress)) {
                throw "UAMI role assignments changed after preflight on $($plan.id). Rerun the preview."
            }
        }
    }

    foreach ($rolePlan in $customRolePlans) {
        $recheckedRolePlan = Get-CustomRolePlan -Name $rolePlan.Name -PlaceholderId $rolePlan.PlaceholderId `
            -SubscriptionId $rolePlan.SubscriptionId -SubscriptionScope $rolePlan.SubscriptionScope -Definition $rolePlan.Definition
        if ($recheckedRolePlan.Id -ne $rolePlan.PlaceholderId) {
            $rolePlan.Id = $recheckedRolePlan.Id
            Write-Host "REUSE exact custom role '$($rolePlan.Name)' that appeared after preflight; scope and permissions verified."
        }
        elseif ($PSCmdlet.ShouldProcess($rolePlan.SubscriptionScope, "Create custom role '$($rolePlan.Name)'")) {
            $definitionJson = ConvertTo-Json -InputObject $rolePlan.Definition -Depth 20 -Compress
            $createdRole = Invoke-AzJson -Arguments @(
                'role', 'definition', 'create', '--role-definition', $definitionJson, '--subscription', $rolePlan.SubscriptionId
            )
            $rolePlan.Id = $createdRole.name
        }
        else {
            $rolePlan.Id = $null
        }
        if ($rolePlan.PlaceholderId -eq $pendingWriterRoleId) { $script:writerRoleId = $rolePlan.Id }
        elseif ($rolePlan.PlaceholderId -eq $pendingNativeBackupRoleId) { $script:nativeBackupRoleId = $rolePlan.Id }
        elseif ($rolePlan.PlaceholderId -eq $pendingNativeRestoreRoleId) { $script:nativeRestoreRoleId = $rolePlan.Id }
    }

    foreach ($plan in $plans) {
        if ($plan.snapshot.rbac) {
            foreach ($role in $plan.rolesToAdd) {
                $roleId = switch ($role.id) {
                    $pendingWriterRoleId { $script:writerRoleId; break }
                    $pendingNativeBackupRoleId { $script:nativeBackupRoleId; break }
                    $pendingNativeRestoreRoleId { $script:nativeRestoreRoleId; break }
                    default { $role.id }
                }
                if ([string]::IsNullOrWhiteSpace($roleId)) {
                    Write-Warning "Skipped '$($role.label)' on $($plan.id) because the custom role was not created."
                    continue
                }
                if ($PSCmdlet.ShouldProcess($plan.id, "Assign '$($role.label)' to the UAMI")) {
                    $null = Invoke-AzJson -Arguments @(
                        'role', 'assignment', 'create', '--assignee-object-id', $script:principalId,
                        '--assignee-principal-type', 'ServicePrincipal', '--role', $roleId,
                        '--scope', $plan.id, '--subscription', $plan.subscriptionId
                    )
                }
            }
        }
        elseif ($plan.needsPolicy) {
            $arguments = @(
                'keyvault', 'set-policy', '--name', $plan.name, '--resource-group', $plan.resourceGroup,
                '--object-id', $script:principalId, '--tenant-id', $script:tenantId,
                '--key-permissions'
            ) + @($plan.permissions.keys)
            $arguments += @('--certificate-permissions') + @($plan.permissions.certificates)
            $arguments += @('--secret-permissions') + @($plan.permissions.secrets)
            if (@($plan.permissions.storage).Count -gt 0) {
                $arguments += @('--storage-permissions') + @($plan.permissions.storage)
            }
            $arguments += @('--subscription', $plan.subscriptionId)
            if ($PSCmdlet.ShouldProcess($plan.id, "Merge legacy access policy for the UAMI")) {
                $null = Invoke-AzJson -Arguments $arguments
            }
        }
    }

    Write-Host 'Grant operations completed or were declined. Allow RBAC propagation, then run a read-only scan. Sync and mutation settings are unchanged.'
}
catch {
    Write-Error $_
    exit 1
}
