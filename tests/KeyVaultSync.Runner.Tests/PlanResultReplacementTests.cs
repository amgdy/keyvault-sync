using KeyVaultSync.Runner;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class PlanResultReplacementTests
{
    [Fact]
    public void Authorization_results_are_matched_by_assignment_identity_not_display_name()
    {
        var first = Authorization("assignment-a", "principal-a");
        var second = Authorization("assignment-b", "principal-b");
        var firstResult = first with { Status = "RBAC_ASSIGNMENT_CREATED_AND_VERIFIED" };
        var secondResult = second with { Status = "RBAC_ACTION_FAILED" };

        Assert.True(RunnerApplication.IsSamePlanIdentity(first, firstResult));
        Assert.True(RunnerApplication.IsSamePlanIdentity(second, secondResult));
        Assert.False(RunnerApplication.IsSamePlanIdentity(first, secondResult));
    }

    private static PlanItem Authorization(string assignmentId, string principalId) => new()
    {
        ObjectType = "Authorization",
        Name = principalId,
        Action = "CreateRoleAssignment",
        Status = "READY_CREATE_ROLE_ASSIGNMENT",
        TargetScope = "/subscriptions/test/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target",
        AssignmentId = assignmentId,
        PrincipalId = principalId,
        RoleDefinitionId = "/subscriptions/test/providers/Microsoft.Authorization/roleDefinitions/role",
    };
}
