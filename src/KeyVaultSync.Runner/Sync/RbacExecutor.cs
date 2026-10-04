using Azure;
using KeyVaultSync.Runner.Azure;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.Sync;

/// <summary>Applies exact, allowlisted Key Vault role-assignment reconciliation and verifies ARM convergence.</summary>
/// <param name="client">ARM role-assignment client used only after plan validation.</param>
/// <param name="syncPrincipalId">Runtime identity object ID protected from self-revocation.</param>
/// <param name="logger">Structured logger; role-assignment failures exclude credentials and object values.</param>
internal sealed class RbacExecutor(
    IArmRbacClient client,
    string? syncPrincipalId,
    ILogger<RbacExecutor> logger)
{
    /// <summary>Executes actionable authorization items in their existing plan order.</summary>
    /// <param name="plan">Persisted pair plan containing authorization and non-authorization items.</param>
    /// <param name="cancellationToken">Cancellation propagated through ARM writes, reads, and bounded waits.</param>
    /// <returns>One terminal result for each role-assignment create or delete action.</returns>
    public async Task<IReadOnlyList<PlanItem>> ApplyAsync(
        IReadOnlyList<PlanItem> plan,
        CancellationToken cancellationToken)
    {
        var authorizationResults = new List<PlanItem>();
        foreach (var authorizationItem in plan.Where(
                     planItem => planItem.Action is "CreateRoleAssignment" or "DeleteRoleAssignment"))
        {
            authorizationResults.Add(await ApplyOneAsync(authorizationItem, cancellationToken));
        }

        return authorizationResults;
    }

    private async Task<PlanItem> ApplyOneAsync(PlanItem item, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(item.TargetScope)
            || string.IsNullOrWhiteSpace(item.AssignmentId)
            || string.IsNullOrWhiteSpace(item.PrincipalId)
            || string.IsNullOrWhiteSpace(item.RoleDefinitionId))
        {
            return item with
            {
                Status = "RBAC_ACTION_FAILED_INVALID_PLAN",
                Detail = "The authorization action is missing required identity or scope fields.",
            };
        }

        if (!KeyVaultRbacPolicy.IsKeyVaultRole(item.RoleDefinitionId))
        {
            return item with
            {
                Status = "RBAC_ACTION_BLOCKED_ROLE_NOT_ALLOWED",
                Detail = "The role definition is outside the Key Vault-specific allowlist.",
            };
        }

        if (item.Action == "DeleteRoleAssignment")
        {
            if (string.IsNullOrWhiteSpace(syncPrincipalId))
            {
                return item with
                {
                    Status = "RBAC_DELETE_BLOCKED_SYNC_IDENTITY_UNKNOWN",
                    Detail = "The runtime identity must be configured before any target-only assignment deletion.",
                };
            }

            if (item.PrincipalId.Equals(syncPrincipalId, StringComparison.OrdinalIgnoreCase))
            {
                return item with
                {
                    Status = "RBAC_DELETE_SKIPPED_SYNC_IDENTITY",
                    Detail = "The runtime identity cannot delete its own assignment.",
                };
            }
        }

        try
        {
            if (item.Action == "CreateRoleAssignment")
            {
                await client.PutAsync(new RbacMutation
                {
                    TargetScope = item.TargetScope,
                    AssignmentId = item.AssignmentId,
                    PrincipalId = item.PrincipalId,
                    RoleDefinitionId = item.RoleDefinitionId,
                    PrincipalType = item.PrincipalType,
                    Condition = item.Condition,
                    ConditionVersion = item.ConditionVersion,
                }, cancellationToken);
            }
            else
            {
                await client.DeleteAsync(item.TargetScope, item.AssignmentId, cancellationToken);
            }

            var assignmentShouldExist = item.Action == "CreateRoleAssignment";
            var assignmentExists = false;
            for (var attempt = 0; attempt < 5; attempt++)
            {
                assignmentExists = await client.ExistsAsync(item.TargetScope, item.AssignmentId, cancellationToken);
                if (assignmentExists == assignmentShouldExist)
                {
                    break;
                }

                // ARM role assignments are eventually consistent, so verification is bounded rather than immediate.
                await Task.Delay(TimeSpan.FromSeconds(attempt + 1), cancellationToken);
            }

            return assignmentExists == assignmentShouldExist
                ? item with
                {
                    Status = assignmentShouldExist ? "RBAC_ASSIGNMENT_CREATED_AND_VERIFIED" : "RBAC_ASSIGNMENT_DELETED_AND_VERIFIED",
                    Detail = "ARM read-back verified the exact role-assignment outcome.",
                }
                : item with
                {
                    Status = "RBAC_ACTION_FAILED_VERIFICATION",
                    Detail = "ARM did not converge to the expected exact assignment state within the bounded verification window.",
                };
        }
        catch (RequestFailedException exception)
        {
            logger.LogError(exception,
                "RBAC mutation failed. Action {Action}; HTTP {Status}; error {ErrorCode}.",
                item.Action, exception.Status, exception.ErrorCode);
            return item with
            {
                Status = "RBAC_ACTION_FAILED",
                Detail = $"ARM returned HTTP {exception.Status}, error {exception.ErrorCode ?? "unknown"}.",
            };
        }
    }
}
