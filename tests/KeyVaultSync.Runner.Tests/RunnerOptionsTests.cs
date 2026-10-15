using KeyVaultSync.Runner;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class RunnerOptionsTests
{
    [Theory]
    [InlineData("  aaaaaaaa-2222-3333-4444-bbbbbbbbbbbb  ")]
    [InlineData("aaaaaaaa-2222-3333-4444-bbbbbbbbbbbb")]
    [InlineData("{aaaaaaaa-2222-3333-4444-bbbbbbbbbbbb}")]
    [InlineData("AAAAAAAA-2222-3333-4444-BBBBBBBBBBBB")]
    public void PrincipalIdIsNormalizedToCanonicalForm(string configured) =>
        Assert.Equal("aaaaaaaa-2222-3333-4444-bbbbbbbbbbbb", RunnerOptions.NormalizePrincipalId(configured));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void UnsetPrincipalIdIsNull(string? configured) => Assert.Null(RunnerOptions.NormalizePrincipalId(configured));

    [Fact]
    public void InvalidPrincipalIdIsRejected() =>
        Assert.Contains("KVS-CONFIG-PRINCIPAL", Assert.Throws<ArgumentException>(() => RunnerOptions.NormalizePrincipalId("not-a-guid")).Message);
}
