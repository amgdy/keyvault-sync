using System.Security.Cryptography;
using System.Text;

namespace KeyVaultSync.Runner.Sync;

/// <summary>Defines the narrow Azure built-in role set that KeyVaultSync may mirror.</summary>
internal static class KeyVaultRbacPolicy
{
    // IDs are used instead of display names because role names can be localized or renamed in presentation surfaces.
    private static readonly IReadOnlySet<string> KeyVaultRoleDefinitionIds =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "00482a5a-887f-4fb3-b363-3b7fe8e74483", // Key Vault Administrator
            "a4417e6f-fecd-4de8-b567-7b0420556985", // Key Vault Certificates Officer
            "db79e9a7-68ee-4b58-9aeb-b90e7c24fcba", // Key Vault Certificate User
            "14b46e9e-c2b7-41b4-b07b-48a6ebf60603", // Key Vault Crypto Officer
            "e147488a-f6f5-4113-8e2d-b22465e65bf6", // Key Vault Crypto Service Encryption User
            "12338af0-0e69-4776-bea7-57ae8d297424", // Key Vault Crypto User
            "21090545-7ca7-4776-b22c-e363652d74d2", // Key Vault Reader
            "b86a8fe4-44ce-4948-aee5-eccb2c155cd7", // Key Vault Secrets Officer
            "4633458b-17de-408a-b874-0445c86b69e6", // Key Vault Secrets User
        };

    /// <summary>Returns whether a role-definition resource ID or GUID is in the built-in Key Vault allowlist.</summary>
    /// <param name="roleDefinitionId">Full ARM role-definition ID or terminal role GUID.</param>
    /// <returns>True only for the explicitly supported built-in Key Vault roles.</returns>
    public static bool IsKeyVaultRole(string roleDefinitionId)
    {
        var roleId = roleDefinitionId.TrimEnd('/').Split('/').LastOrDefault();
        return roleId is not null && KeyVaultRoleDefinitionIds.Contains(roleId);
    }

    /// <summary>Creates the stable assignment name used for idempotent target PUTs.</summary>
    /// <param name="targetScope">Mapped target vault, secret, or key scope.</param>
    /// <param name="principalId">Microsoft Entra principal object ID.</param>
    /// <param name="roleDefinitionId">Allowlisted built-in role-definition ID.</param>
    /// <returns>A deterministic GUID string bound to scope, principal, and role.</returns>
    public static string GetDeterministicAssignmentId(
        string targetScope,
        string principalId,
        string roleDefinitionId)
    {
        var canonical = string.Join(
            "\n",
            targetScope.TrimEnd('/').ToLowerInvariant(),
            principalId.Trim().ToLowerInvariant(),
            roleDefinitionId.TrimEnd('/').ToLowerInvariant());
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return new Guid(hash.AsSpan(0, 16)).ToString();
    }
}
