using KeyVaultSync.Runner;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class LocalSettingsFileTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"keyvaultsync-settings-{Guid.NewGuid():N}.json");

    public void Dispose() => File.Delete(_path);

    [Fact]
    public void AppliesUnsetStringValuesWithoutOverridingEnvironment()
    {
        File.WriteAllText(_path, """
            {
              // Functions files may carry comments.
              "IsEncrypted": false,
              "Values": {
                "KEYVAULTSYNC_LOG_LEVEL": "Debug",
                "KEYVAULTSYNC_STATE_CONTAINER": "from-file",
                "NOT_A_STRING": 5,
              }
            }
            """);
        var environment = new Dictionary<string, string> { ["KEYVAULTSYNC_STATE_CONTAINER"] = "from-shell" };

        var applied = LocalSettingsFile.Apply(
            _path,
            name => environment.GetValueOrDefault(name),
            (name, value) => environment[name] = value);

        Assert.Equal(["KEYVAULTSYNC_LOG_LEVEL"], applied);
        Assert.Equal("Debug", environment["KEYVAULTSYNC_LOG_LEVEL"]);
        Assert.Equal("from-shell", environment["KEYVAULTSYNC_STATE_CONTAINER"]);
        Assert.False(environment.ContainsKey("NOT_A_STRING"));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{ "IsEncrypted": false }""")]
    [InlineData("""{ "Values": [] }""")]
    public void RejectsFilesWithoutValuesObject(string content)
    {
        File.WriteAllText(_path, content);

        Assert.Throws<InvalidDataException>(() => LocalSettingsFile.Apply(_path, _ => null, (_, _) => { }));
    }

    [Fact]
    public void RejectsMissingFile()
    {
        Assert.Throws<FileNotFoundException>(() => LocalSettingsFile.Apply(_path, _ => null, (_, _) => { }));
    }
}
