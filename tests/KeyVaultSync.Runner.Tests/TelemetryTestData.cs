using Azure.Core;

namespace KeyVaultSync.Runner.Tests;

/// <summary>Builds value-free run records and locations shared by the telemetry tests.</summary>
internal static class TelemetryTestData
{
    internal const string RunId = "20250102T0130450000000Z-0123456789abcdef0123456789abcdef";
    internal const string RunRecordContainer = "keyvaultsync-runs";
    internal const string RunRecordBlobName = $"runs/2025/01/02/{RunId}.json";
    internal const string RunRecordUri = $"https://account.blob.core.windows.net/{RunRecordContainer}/{RunRecordBlobName}";

    internal static RunRecordLocation Location() =>
        new("account", RunRecordContainer, RunRecordBlobName, RunRecordUri);

    internal static RunRecord Run(string status, DateTimeOffset? startedAt = null) => new()
    {
        RunId = RunId,
        SubscriptionIds = ["subscription-a", "subscription-b"],
        StartedAt = startedAt ?? new DateTimeOffset(2025, 1, 2, 1, 30, 45, TimeSpan.Zero),
        Mode = "AutomaticSync",
        Status = status,
    };

    internal static PairScanReport Pair(string pairId, string status, params string[] planStatuses) => new()
    {
        PairId = pairId,
        SourceVaultId = $"/subscriptions/subscription-a/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{pairId}-source",
        TargetVaultId = $"/subscriptions/subscription-b/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{pairId}-target",
        Status = status,
        StartedAt = new DateTimeOffset(2025, 1, 2, 1, 30, 46, TimeSpan.Zero),
        Plan = planStatuses.Select(Item).ToList(),
    };

    internal static PlanItem Item(string status) => new()
    {
        ObjectType = "Secret",
        Name = "redacted",
        Action = "None",
        Status = status,
    };
}

/// <summary>Fails every token request, so authenticated Azure calls stop before any request is sent.</summary>
internal sealed class CountingFailingTokenCredential : TokenCredential
{
    private int _tokenRequestCount;

    public int TokenRequestCount => Volatile.Read(ref _tokenRequestCount);

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        throw CreateFailure();

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        throw CreateFailure();

    private InvalidOperationException CreateFailure()
    {
        Interlocked.Increment(ref _tokenRequestCount);
        return new InvalidOperationException("The test credential does not issue tokens.");
    }
}
