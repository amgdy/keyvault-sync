using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Azure.Core;

namespace KeyVaultSync.Runner.Azure;

/// <summary>Describes one exact direct role assignment to create at a target Key Vault scope.</summary>
/// <remarks>The record carries declaration data only; it does not represent effective access or group membership.</remarks>
internal sealed record RbacMutation
{
    /// <summary>Gets the target vault, secret, or key ARM scope.</summary>
    public required string TargetScope { get; init; }
    /// <summary>Gets the deterministic role-assignment resource name.</summary>
    public required string AssignmentId { get; init; }
    /// <summary>Gets the Microsoft Entra object ID receiving the role.</summary>
    public required string PrincipalId { get; init; }
    /// <summary>Gets the allowlisted built-in Key Vault role-definition ID.</summary>
    public required string RoleDefinitionId { get; init; }
    /// <summary>Gets the principal type declared by the source assignment, when ARM supplied it.</summary>
    public string? PrincipalType { get; init; }
    /// <summary>Gets the source assignment condition, preserved verbatim to avoid widening access.</summary>
    public string? Condition { get; init; }
    /// <summary>Gets the ARM condition language version associated with <see cref="Condition"/>.</summary>
    public string? ConditionVersion { get; init; }
}

/// <summary>Abstracts exact ARM role-assignment writes and verification reads for <c>RbacExecutor</c>.</summary>
internal interface IArmRbacClient
{
    /// <summary>Creates or converges one deterministic direct role assignment.</summary>
    Task PutAsync(RbacMutation mutation, CancellationToken cancellationToken);
    /// <summary>Deletes one exact direct role assignment; an already absent assignment is successful.</summary>
    Task DeleteAsync(string targetScope, string assignmentId, CancellationToken cancellationToken);
    /// <summary>Returns whether one exact assignment resource currently exists.</summary>
    Task<bool> ExistsAsync(string targetScope, string assignmentId, CancellationToken cancellationToken);
}

/// <summary>Calls Azure Resource Manager for direct role-assignment creation, deletion, and read-back verification.</summary>
/// <remarks>
/// This client does not discover assignments or decide eligibility. <c>ReplicationPlanner</c> and
/// <c>RbacExecutor</c> must validate the scope and role allowlist before invoking it.
/// </remarks>
internal sealed class ArmRbacClient(
    TokenCredential credential,
    HttpClient? httpClient = null) : IArmRbacClient
{
    private static readonly TokenRequestContext TokenContext = new(["https://management.azure.com/.default"]);
    private readonly HttpClient _httpClient = httpClient ?? new HttpClient();

    /// <inheritdoc />
    public async Task PutAsync(RbacMutation mutation, CancellationToken cancellationToken)
    {
        var targetSubscriptionId = GetSubscriptionId(mutation.TargetScope);
        var builtInRoleId = mutation.RoleDefinitionId.TrimEnd('/').Split('/').Last();
        var roleDefinitionId =
            $"/subscriptions/{targetSubscriptionId}/providers/Microsoft.Authorization/roleDefinitions/{builtInRoleId}";
        var body = new
        {
            properties = new
            {
                principalId = mutation.PrincipalId,
                roleDefinitionId,
                principalType = mutation.PrincipalType,
                condition = mutation.Condition,
                conditionVersion = mutation.ConditionVersion,
            },
        };
        using var request = new HttpRequestMessage(
            HttpMethod.Put,
            BuildAssignmentUri(mutation.TargetScope, mutation.AssignmentId))
        {
            Content = JsonContent.Create(body),
        };
        await AuthorizeAsync(request, cancellationToken);
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
        {
            return;
        }

        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(
        string targetScope,
        string assignmentId,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, BuildAssignmentUri(targetScope, assignmentId));
        await AuthorizeAsync(request, cancellationToken);
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return;
        }

        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> ExistsAsync(
        string targetScope,
        string assignmentId,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildAssignmentUri(targetScope, assignmentId));
        await AuthorizeAsync(request, cancellationToken);
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return false;
        }

        await EnsureSuccessAsync(response, cancellationToken);
        return true;
    }

    private async Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await credential.GetTokenAsync(TokenContext, cancellationToken);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
    }

    private static Uri BuildAssignmentUri(string scope, string assignmentId) =>
        new($"https://management.azure.com{scope.TrimEnd('/')}/providers/Microsoft.Authorization/roleAssignments/{assignmentId}?api-version=2022-04-01");

    private static string GetSubscriptionId(string scope)
    {
        var segments = scope.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2 || !segments[0].Equals("subscriptions", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Target RBAC scope is not subscription-addressable.");
        }

        return segments[1];
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        string? errorCode = null;
        try
        {
            using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));
            errorCode = document.RootElement.GetProperty("error").GetProperty("code").GetString();
        }
        catch (JsonException)
        {
            // ARM error bodies are not guaranteed to be JSON. Preserve the HTTP status even when no code can be extracted.
        }

        throw new global::Azure.RequestFailedException(
            (int)response.StatusCode,
            $"ARM role-assignment request failed with HTTP {(int)response.StatusCode}.",
            errorCode,
            null);
    }
}
