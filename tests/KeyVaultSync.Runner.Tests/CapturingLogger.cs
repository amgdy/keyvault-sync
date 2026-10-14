using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.Tests;

/// <summary>Records each structured log with the scope values active when it was written.</summary>
/// <remarks>Scopes are tracked per logger instance, which is sufficient for the sequential flows these tests drive.</remarks>
internal sealed class CapturingLogger : ILogger
{
    private readonly List<IReadOnlyDictionary<string, object?>> _activeScopes = [];

    public List<CapturedLogEntry> Entries { get; } = [];

    public IDisposable BeginScope<TState>(TState state) where TState : notnull
    {
        IReadOnlyDictionary<string, object?> scope = state is IEnumerable<KeyValuePair<string, object?>> values
            ? values.ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal)
            : new Dictionary<string, object?>(StringComparer.Ordinal) { ["Scope"] = state.ToString() };
        _activeScopes.Add(scope);
        return new ScopeHandle(() => _activeScopes.Remove(scope));
    }

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var values = state as IEnumerable<KeyValuePair<string, object?>> ?? [];
        var properties = values
            .Where(value => value.Key != "{OriginalFormat}")
            .ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal);
        var scopes = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var scope in _activeScopes)
        {
            foreach (var (key, value) in scope)
            {
                scopes[key] = value;
            }
        }

        Entries.Add(new CapturedLogEntry(logLevel, eventId, formatter(state, exception), properties, scopes, exception));
    }

    public IReadOnlyList<CapturedLogEntry> WithEventId(int eventId) =>
        Entries.Where(entry => entry.EventId.Id == eventId).ToArray();

    private sealed class ScopeHandle(Action dispose) : IDisposable
    {
        public void Dispose() => dispose();
    }
}

internal sealed record CapturedLogEntry(
    LogLevel Level,
    EventId EventId,
    string Message,
    IReadOnlyDictionary<string, object?> Properties,
    IReadOnlyDictionary<string, object?> Scopes,
    Exception? Exception);
