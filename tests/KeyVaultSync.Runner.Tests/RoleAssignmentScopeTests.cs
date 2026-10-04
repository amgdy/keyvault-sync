using KeyVaultSync.Runner;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class RoleAssignmentScopeTests
{
    private const string VaultId =
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sample/providers/Microsoft.KeyVault/vaults/kv-sample";

    [Theory]
    [InlineData(VaultId, "Vault")]
    [InlineData(VaultId + "/secrets/sample-secret", "Object")]
    [InlineData(VaultId + "/keys/sample-key", "Object")]
    [InlineData("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sample", "ResourceGroup")]
    [InlineData("/subscriptions/00000000-0000-0000-0000-000000000000", "Subscription")]
    public void Scope_kind_distinguishes_replicable_scopes_from_ancestors(string scope, string expected)
    {
        var assignment = Assignment(scope);

        Assert.Equal(expected, assignment.ScopeKind);
    }

    /// <summary>
    /// The ARM atScope() filter returns a scope's inherited ancestors alongside its own assignments.
    /// Only vault-scope and object-scope grants are replicable, so ancestor rows must be excluded to
    /// keep tenant-wide principal grants out of every vault inventory and run report.
    /// </summary>
    [Fact]
    public void Only_vault_and_object_assignments_are_treated_as_replicable()
    {
        string[] scopes =
        [
            "/",
            "/subscriptions/00000000-0000-0000-0000-000000000000",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sample",
            VaultId,
            VaultId + "/secrets/sample-secret",
        ];

        var replicable = scopes
            .Select(Assignment)
            .Where(assignment => assignment.ScopeKind is "Vault" or "Object")
            .Select(assignment => assignment.Scope)
            .ToArray();

        Assert.Equal([VaultId, VaultId + "/secrets/sample-secret"], replicable);
    }

    private static RoleAssignmentSummary Assignment(string scope) => new()
    {
        Id = $"{scope}/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000001",
        Scope = scope,
        PrincipalId = "00000000-0000-0000-0000-000000000002",
        PrincipalType = "ServicePrincipal",
        RoleDefinitionId = "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/00482a5a-887f-4fb3-b363-3b7fe8e74483",
    };
}
