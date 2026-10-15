using System.Text.Json;

namespace KeyVaultSync.Runner;

/// <summary>Loads the <c>Values</c> section of a Functions-style <c>local.settings.json</c> into process environment variables.</summary>
/// <remarks>
/// Used only by the terminal host so it can share the ignored file that the local Function host already uses.
/// Runtime configuration remains environment-only: <see cref="RunnerOptions.Parse"/> still reads the environment after
/// this loader runs. Variables already present in the environment win, so a shell or pipeline can override the file.
/// Values are never logged or returned; only the applied setting names are reported to the caller.
/// </remarks>
internal static class LocalSettingsFile
{
    /// <summary>Applies string entries from the file's <c>Values</c> object that are not already set.</summary>
    /// <param name="path">Path to a JSON file with a top-level <c>Values</c> object of string properties.</param>
    /// <param name="getVariable">Reads an existing environment variable.</param>
    /// <param name="setVariable">Sets an environment variable for this process only.</param>
    /// <returns>Names of the settings applied from the file, in file order.</returns>
    /// <exception cref="FileNotFoundException">The file does not exist.</exception>
    /// <exception cref="InvalidDataException">The file is not JSON or has no <c>Values</c> object.</exception>
    public static IReadOnlyList<string> Apply(
        string path,
        Func<string, string?> getVariable,
        Action<string, string> setVariable)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("The settings file does not exist.", path);
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
            });
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"The settings file is not valid JSON: {exception.Message}", exception);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("Values", out var values)
                || values.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("The settings file must contain a top-level \"Values\" object.");
            }

            var applied = new List<string>();
            foreach (var setting in values.EnumerateObject())
            {
                if (setting.Value.ValueKind != JsonValueKind.String
                    || !string.IsNullOrEmpty(getVariable(setting.Name)))
                {
                    continue;
                }

                setVariable(setting.Name, setting.Value.GetString()!);
                applied.Add(setting.Name);
            }

            return applied;
        }
    }
}
