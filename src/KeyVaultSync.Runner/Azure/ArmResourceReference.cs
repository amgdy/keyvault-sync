using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.Azure;

/// <summary>Readable subscription, resource-group, and name parts of an ARM resource ID for structured logs.</summary>
/// <remarks>
/// Logs carry these parts as separate properties instead of the full ARM ID so console, file, and Application Insights
/// output stay short and every part stays queryable. Full IDs remain in the private run record, pair state, and trace
/// tags, which need exact identity. Parsing is lenient and never throws: a value without a <c>subscriptions</c> segment
/// (for example an invalid mapping tag) is returned as the name with no subscription or resource group, so the
/// administrator can still see what was configured.
/// </remarks>
/// <param name="SubscriptionId">Subscription GUID text, or <see langword="null"/> when the value has none.</param>
/// <param name="ResourceGroup">Resource-group name, or <see langword="null"/> for subscription-level scopes.</param>
/// <param name="Name">Last resource-name segment, or <see langword="null"/> for subscription and resource-group scopes.</param>
internal readonly record struct ArmResourceReference(string? SubscriptionId, string? ResourceGroup, string? Name)
{
    /// <summary>Splits an ARM resource ID or scope into its readable parts.</summary>
    public static ArmResourceReference Parse(string? resourceId)
    {
        if (string.IsNullOrWhiteSpace(resourceId))
        {
            return default;
        }

        var segments = resourceId.Trim().Split('/', StringSplitOptions.RemoveEmptyEntries);
        var subscriptionIndex = Array.FindIndex(segments, segment => segment.Equals("subscriptions", StringComparison.OrdinalIgnoreCase));
        if (subscriptionIndex < 0 || subscriptionIndex + 1 >= segments.Length)
        {
            return new ArmResourceReference(null, null, resourceId.Trim());
        }

        var subscriptionId = segments[subscriptionIndex + 1];
        var groupIndex = Array.FindIndex(segments, subscriptionIndex + 2, segment => segment.Equals("resourceGroups", StringComparison.OrdinalIgnoreCase));
        var resourceGroup = groupIndex >= 0 && groupIndex + 1 < segments.Length ? segments[groupIndex + 1] : null;
        var providersIndex = Array.FindIndex(segments, subscriptionIndex + 2, segment => segment.Equals("providers", StringComparison.OrdinalIgnoreCase));
        // providers/{namespace}/{type}/{name}[/{childType}/{childName}...]: the last segment is the innermost name.
        var name = providersIndex >= 0 && segments.Length >= providersIndex + 4 ? segments[^1] : null;
        return new ArmResourceReference(subscriptionId, resourceGroup, name);
    }

    /// <summary>Adds <c>{prefix}SubscriptionId</c>, <c>{prefix}ResourceGroup</c>, and <c>{prefix}{nameProperty}</c>.</summary>
    public void AddTo(IDictionary<string, object?> properties, string prefix, string nameProperty)
    {
        properties[$"{prefix}SubscriptionId"] = SubscriptionId;
        properties[$"{prefix}ResourceGroup"] = ResourceGroup;
        properties[$"{prefix}{nameProperty}"] = Name;
    }
}

/// <summary>Builds the logger scope that identifies one source/target pair by readable parts instead of ARM IDs.</summary>
internal static class PairLogScope
{
    /// <summary>
    /// Starts a scope with <c>SourceSubscriptionId</c>, <c>SourceResourceGroup</c>, <c>SourceVaultName</c>, and the
    /// matching <c>Target*</c> properties, plus any extra properties supplied by the caller.
    /// </summary>
    public static IDisposable? Begin(ILogger logger, VaultPair pair, IReadOnlyDictionary<string, object?>? extraProperties = null)
    {
        var properties = CreateProperties(pair);
        if (extraProperties is not null)
        {
            foreach (var (name, value) in extraProperties)
            {
                properties[name] = value;
            }
        }

        return logger.BeginScope(properties);
    }

    /// <summary>Starts the same scope from a persisted <c>{sourceId}=&gt;{targetId}</c> pair identity.</summary>
    public static IDisposable? Begin(ILogger logger, string pairId)
    {
        var separatorIndex = pairId.IndexOf("=>", StringComparison.Ordinal);
        return separatorIndex < 0
            ? logger.BeginScope(CreateProperties(pairId, null))
            : logger.BeginScope(CreateProperties(pairId[..separatorIndex], pairId[(separatorIndex + 2)..]));
    }

    /// <summary>Returns the six pair-identity properties used by <see cref="Begin(ILogger, VaultPair, IReadOnlyDictionary{string, object?})"/>.</summary>
    public static Dictionary<string, object?> CreateProperties(VaultPair pair) => CreateProperties(pair.Source.Id, pair.Target.Id);

    private static Dictionary<string, object?> CreateProperties(string sourceId, string? targetId)
    {
        var properties = new Dictionary<string, object?>(StringComparer.Ordinal);
        ArmResourceReference.Parse(sourceId).AddTo(properties, "Source", "VaultName");
        ArmResourceReference.Parse(targetId).AddTo(properties, "Target", "VaultName");
        return properties;
    }
}
