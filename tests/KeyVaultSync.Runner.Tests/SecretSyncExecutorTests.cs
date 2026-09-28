using System.Runtime.CompilerServices;
using Azure.Security.KeyVault.Secrets;
using KeyVaultSync.Runner;
using KeyVaultSync.Runner.Azure;
using KeyVaultSync.Runner.Security;
using KeyVaultSync.Runner.State;
using KeyVaultSync.Runner.Sync;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class SecretSyncExecutorTests
{
    private const string SecretName = "db-password";
    private const string BaselineValue = "baseline-value";
    private const string ChangedValue = "changed-value";

    [Fact]
    public void New_target_version_requires_hmac_verification_before_refresh()
    {
        using var fixture = CreateFixture(
            sourceVersions: [("source-v1", BaselineValue)],
            targetVersions: [("target-v1", BaselineValue), ("target-v2", BaselineValue)],
            sourceInventoryVersion: "source-v1",
            targetInventoryVersion: "target-v2");

        var plan = SyncPlanner.CreatePlan(fixture.Pair, fixture.State, fixture.SourceInventory, fixture.TargetInventory, hmacAvailable: true);
        var secret = Assert.Single(plan, item => item.ObjectType == "Secret");

        Assert.Equal("VerifySecretBaseline", secret.Action);
        Assert.Equal("VERIFY_TARGET_HMAC", secret.Status);

        var blockedPlan = SyncPlanner.CreatePlan(fixture.Pair, fixture.State, fixture.SourceInventory, fixture.TargetInventory, hmacAvailable: false);
        var blockedSecret = Assert.Single(blockedPlan, item => item.ObjectType == "Secret");
        Assert.Equal("BLOCKED_HMAC_KEY_NOT_CONFIGURED", blockedSecret.Status);
    }

    [Fact]
    public async Task New_target_version_with_baseline_equivalent_content_refreshes_without_a_write()
    {
        using var fixture = CreateFixture(
            sourceVersions: [("source-v1", BaselineValue)],
            targetVersions: [("target-v1", BaselineValue), ("target-v2", BaselineValue)],
            sourceInventoryVersion: "source-v1",
            targetInventoryVersion: "target-v2");
        var targetClient = fixture.TargetClient;
        var liveHead = await targetClient.GetSecretAsync(SecretName, version: null, CancellationToken.None);
        var baseline = fixture.Lease.State.SecretBaselines[SecretName];
        Assert.Equal(baseline.MetadataDigest, ComputeMetadataDigest(liveHead.Properties));
        Assert.True(SecretHmacService.ValueHmacEquals(baseline.ValueHmac, ComputeValueHmac(fixture, liveHead.Value)));

        var result = await fixture.ApplyAsync();

        Assert.True(result.Status == "IN_SYNC_BY_HMAC_AND_METADATA", result.Detail);
        Assert.Equal(0, targetClient.SetCount);
        Assert.Equal(1, fixture.Lease.SaveCount);
        Assert.Equal("source-v1", fixture.Lease.State.SecretBaselines[SecretName].SourceVersion);
        Assert.Equal("target-v2", fixture.Lease.State.SecretBaselines[SecretName].TargetVersion);
        Assert.Empty(fixture.Lease.State.PendingSecretWrites);
    }

    [Fact]
    public async Task New_target_version_with_drift_is_not_overwritten()
    {
        using var fixture = CreateFixture(
            sourceVersions: [("source-v1", BaselineValue)],
            targetVersions: [("target-v1", BaselineValue), ("target-v2", ChangedValue)],
            sourceInventoryVersion: "source-v1",
            targetInventoryVersion: "target-v2");

        var result = await fixture.ApplyAsync();

        Assert.Equal("CONFLICT_TARGET_DRIFT", result.Status);
        Assert.Equal(0, fixture.TargetClient.SetCount);
        Assert.Equal(0, fixture.Lease.SaveCount);
        Assert.Empty(fixture.Lease.State.PendingSecretWrites);
        Assert.Equal("target-v1", fixture.Lease.State.SecretBaselines[SecretName].TargetVersion);
    }

    [Fact]
    public async Task New_source_version_with_baseline_equivalent_content_refreshes_without_a_write()
    {
        using var fixture = CreateFixture(
            sourceVersions: [("source-v1", BaselineValue), ("source-v2", BaselineValue)],
            targetVersions: [("target-v1", BaselineValue)],
            sourceInventoryVersion: "source-v2",
            targetInventoryVersion: "target-v1");

        var result = await fixture.ApplyAsync();

        Assert.Equal("IN_SYNC_BY_HMAC_AND_METADATA", result.Status);
        Assert.Equal(0, fixture.TargetClient.SetCount);
        Assert.Equal(1, fixture.Lease.SaveCount);
        Assert.Equal("source-v2", fixture.Lease.State.SecretBaselines[SecretName].SourceVersion);
        Assert.Equal("target-v1", fixture.Lease.State.SecretBaselines[SecretName].TargetVersion);
    }

    [Fact]
    public async Task Source_update_is_applied_when_new_target_version_still_matches_baseline()
    {
        using var fixture = CreateFixture(
            sourceVersions: [("source-v1", BaselineValue), ("source-v2", ChangedValue)],
            targetVersions: [("target-v1", BaselineValue), ("target-v2", BaselineValue)],
            sourceInventoryVersion: "source-v2",
            targetInventoryVersion: "target-v2");

        var result = await fixture.ApplyAsync();

        Assert.Equal("SECRET_SYNCED_AND_VERIFIED", result.Status);
        Assert.Equal(1, fixture.TargetClient.SetCount);
        Assert.Equal(2, fixture.Lease.SaveCount);
        Assert.Empty(fixture.Lease.State.PendingSecretWrites);
        Assert.Equal("source-v2", fixture.Lease.State.SecretBaselines[SecretName].SourceVersion);
        Assert.Equal("target-write-1", fixture.Lease.State.SecretBaselines[SecretName].TargetVersion);
        Assert.Equal(ComputeValueHmac(fixture, ChangedValue), fixture.Lease.State.SecretBaselines[SecretName].ValueHmac);
    }

    [Fact]
    public async Task Target_change_after_inventory_is_blocked_before_intent()
    {
        using var fixture = CreateFixture(
            sourceVersions: [("source-v1", BaselineValue), ("source-v2", ChangedValue)],
            targetVersions: [("target-v1", BaselineValue)],
            sourceInventoryVersion: "source-v2",
            targetInventoryVersion: "target-v1");
        fixture.TargetClient.BeforeHeadRead = count =>
        {
            if (count == 1)
            {
                fixture.TargetClient.AddVersion(SecretName, "target-v2", BaselineValue);
            }
        };

        var result = await fixture.ApplyAsync();

        Assert.Equal("CONFLICT_TARGET_CHANGED_DURING_VALIDATION", result.Status);
        Assert.Equal(0, fixture.TargetClient.SetCount);
        Assert.Equal(0, fixture.Lease.SaveCount);
        Assert.Empty(fixture.Lease.State.PendingSecretWrites);
    }

    [Fact]
    public async Task Target_change_after_intent_clears_intent_without_writing()
    {
        using var fixture = CreateFixture(
            sourceVersions: [("source-v1", BaselineValue), ("source-v2", ChangedValue)],
            targetVersions: [("target-v1", BaselineValue)],
            sourceInventoryVersion: "source-v2",
            targetInventoryVersion: "target-v1");
        fixture.TargetClient.BeforeHeadRead = count =>
        {
            if (count == 2)
            {
                fixture.TargetClient.AddVersion(SecretName, "target-v2", BaselineValue);
            }
        };

        var result = await fixture.ApplyAsync();

        Assert.Equal("CONFLICT_PRECONDITION_CHANGED_BEFORE_WRITE", result.Status);
        Assert.Equal(0, fixture.TargetClient.SetCount);
        Assert.Equal(2, fixture.Lease.SaveCount);
        Assert.Empty(fixture.Lease.State.PendingSecretWrites);
        Assert.Equal("target-v1", fixture.Lease.State.SecretBaselines[SecretName].TargetVersion);
    }

    [Fact]
    public async Task Source_change_after_intent_clears_intent_without_writing()
    {
        using var fixture = CreateFixture(
            sourceVersions: [("source-v1", BaselineValue), ("source-v2", ChangedValue)],
            targetVersions: [("target-v1", BaselineValue)],
            sourceInventoryVersion: "source-v2",
            targetInventoryVersion: "target-v1");
        fixture.SourceClient.BeforeHeadRead = count =>
        {
            if (count == 1)
            {
                fixture.SourceClient.AddVersion(SecretName, "source-v3", "latest-source-value");
            }
        };

        var result = await fixture.ApplyAsync();

        Assert.Equal("CONFLICT_PRECONDITION_CHANGED_BEFORE_WRITE", result.Status);
        Assert.Equal(0, fixture.TargetClient.SetCount);
        Assert.Equal(2, fixture.Lease.SaveCount);
        Assert.Empty(fixture.Lease.State.PendingSecretWrites);
        Assert.Equal("target-v1", fixture.Lease.State.SecretBaselines[SecretName].TargetVersion);
    }

    private static string ComputeValueHmac(Fixture fixture, string value)
    {
        return fixture.Hmac.ComputeValue(fixture.Pair.PairId, SecretName, value);
    }

    private static Fixture CreateFixture(
        IReadOnlyList<(string Version, string Value)> sourceVersions,
        IReadOnlyList<(string Version, string Value)> targetVersions,
        string sourceInventoryVersion,
        string targetInventoryVersion)
    {
        var pair = CreatePair();
        var sourceClient = new MemorySecretVaultClient(pair.Source.Name);
        foreach (var (version, value) in sourceVersions)
        {
            sourceClient.AddVersion(SecretName, version, value);
        }

        var targetClient = new MemorySecretVaultClient(pair.Target.Name);
        foreach (var (version, value) in targetVersions)
        {
            targetClient.AddVersion(SecretName, version, value);
        }

        var hmac = CreateHmac();
        var sourceSecret = sourceClient.GetVersion(SecretName, sourceInventoryVersion);
        var targetSecret = targetClient.GetVersion(SecretName, targetInventoryVersion);
        var state = CreateState(pair);
        Assert.Equal(ComputeMetadataDigest(sourceSecret.Properties), ComputeMetadataDigest(targetSecret.Properties));
        if (string.Equals(sourceVersions[0].Value, targetSecret.Value, StringComparison.Ordinal))
        {
            Assert.True(SecretHmacService.ValueHmacEquals(
                hmac.ComputeValue(pair.PairId, SecretName, sourceVersions[0].Value),
                hmac.ComputeValue(pair.PairId, SecretName, targetSecret.Value)));
        }

        state.SecretBaselines[SecretName] = new SecretBaseline
        {
            ValueDomainVersion = SecretHmacService.ValueDomainVersion,
            MetadataDomainVersion = SecretHmacService.MetadataDomainVersion,
            SourceVersion = sourceVersions[0].Version,
            TargetVersion = targetVersions[0].Version,
            ValueHmac = hmac.ComputeValue(pair.PairId, SecretName, sourceVersions[0].Value),
            HmacKeyVersion = hmac.KeyVersion,
            MetadataDigest = ComputeMetadataDigest(sourceSecret.Properties),
            VerifiedAt = DateTimeOffset.UtcNow,
        };

        return new Fixture(
            pair,
            state,
            CreateInventory(pair.Source, [Summary(sourceSecret)]),
            CreateInventory(pair.Target, [Summary(targetSecret)]),
            sourceClient,
            targetClient,
            hmac);
    }

    private static SecretHmacService CreateHmac()
    {
        return SecretHmacService.Load(new RunnerOptions
        {
            SubscriptionId = "test-subscription",
            StorageAccountUri = new Uri("https://example.blob.core.windows.net/"),
            HmacKeyBase64 = Convert.ToBase64String(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray()),
            HmacKeyVersion = "test-key-v1",
        })!;
    }

    private static SecretSummary Summary(KeyVaultSecret secret)
    {
        var properties = secret.Properties;
        return new SecretSummary
        {
            Name = secret.Name,
            CurrentVersion = properties.Version!,
            Versions = [new ObjectVersionSummary { Version = properties.Version! }],
            Enabled = properties.Enabled,
            ContentType = properties.ContentType,
            NotBefore = properties.NotBefore,
            ExpiresOn = properties.ExpiresOn,
            Tags = new Dictionary<string, string>(properties.Tags, StringComparer.OrdinalIgnoreCase),
        };
    }

    private static string ComputeMetadataDigest(SecretProperties properties)
    {
        var tags = properties.Tags is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(properties.Tags, StringComparer.OrdinalIgnoreCase);
        return SecretHmacService.ComputeMetadata(
            properties.Enabled,
            properties.ContentType,
            properties.NotBefore,
            properties.ExpiresOn,
            tags);
    }

    private static VaultPair CreatePair()
    {
        var source = new VaultResource
        {
            Id = "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/source-vault",
            Name = "source-vault",
            Location = "eastus",
            ResourceGroup = "test-rg",
            Tags = [],
        };
        var target = new VaultResource
        {
            Id = "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/target-vault",
            Name = "target-vault",
            Location = "eastus",
            ResourceGroup = "test-rg",
            Tags = [],
        };
        return new VaultPair(source, target);
    }

    private static VaultInventory CreateInventory(VaultResource vault, IReadOnlyList<SecretSummary> secrets)
    {
        return new VaultInventory
        {
            VaultId = vault.Id,
            VaultName = vault.Name,
            Region = vault.Location,
            Authorization = new VaultAuthorizationSummary
            {
                UsesRbac = true,
                AccessPolicies = [],
                RoleAssignments = [],
                Warnings = [],
            },
            Secrets = secrets,
            Keys = [],
            Certificates = [],
            DeletedSecretNames = [],
            DeletedKeyNames = [],
            DeletedCertificateNames = [],
            Warnings = [],
        };
    }

    private static PairState CreateState(VaultPair pair)
    {
        return new PairState
        {
            PairId = pair.PairId,
            SourceVaultId = pair.Source.Id,
            TargetVaultId = pair.Target.Id,
        };
    }

    private sealed class Fixture(
        VaultPair pair,
        PairState state,
        VaultInventory sourceInventory,
        VaultInventory targetInventory,
        MemorySecretVaultClient sourceClient,
        MemorySecretVaultClient targetClient,
        SecretHmacService hmac) : IDisposable
    {
        public VaultPair Pair { get; } = pair;
        public PairState State { get; } = state;
        public VaultInventory SourceInventory { get; } = sourceInventory;
        public VaultInventory TargetInventory { get; } = targetInventory;
        public MemorySecretVaultClient SourceClient { get; } = sourceClient;
        public MemorySecretVaultClient TargetClient { get; } = targetClient;
        public SecretHmacService Hmac { get; } = hmac;
        public TestLease Lease { get; } = new(state);

        public void Dispose() => Hmac.Dispose();

        public async Task<PlanItem> ApplyAsync()
        {
            var plan = SyncPlanner.CreatePlan(Pair, State, SourceInventory, TargetInventory, hmacAvailable: true);
            var plannedSecret = Assert.Single(plan, item => item.ObjectType == "Secret");
            var executor = new SecretSyncExecutor(
                new MemorySecretVaultClientFactory(SourceClient, TargetClient),
                NullLogger<SecretSyncExecutor>.Instance);
            var results = await executor.ApplyAsync(
                Pair,
                Lease,
                "test-run",
                [plannedSecret],
                SourceInventory,
                TargetInventory,
                Hmac,
                CancellationToken.None);
            return Assert.Single(results);
        }
    }

    private sealed class MemorySecretVaultClientFactory(
        MemorySecretVaultClient source,
        MemorySecretVaultClient target) : ISecretSyncVaultClientFactory
    {
        public ISecretSyncVaultClient Create(VaultResource vault, bool isTarget) => isTarget ? target : source;
    }

    private sealed class MemorySecretVaultClient(string vaultName) : ISecretSyncVaultClient
    {
        private readonly Dictionary<string, List<KeyVaultSecret>> _secrets = new(StringComparer.OrdinalIgnoreCase);
        private int _writeVersion;

        public int SetCount { get; private set; }
        public int HeadReadCount { get; private set; }
        public Action<int>? BeforeHeadRead { get; set; }

        public void AddVersion(string name, string version, string value, bool? enabled = true, string? contentType = "text/plain")
        {
            var secret = CreateSecret(vaultName, name, version, value, enabled, contentType);
            if (!_secrets.TryGetValue(name, out var versions))
            {
                versions = [];
                _secrets[name] = versions;
            }

            var index = versions.FindIndex(item => item.Properties.Version == version);
            if (index >= 0)
            {
                versions[index] = secret;
            }
            else
            {
                versions.Add(secret);
            }
        }

        public KeyVaultSecret GetVersion(string name, string version)
        {
            return _secrets[name].Single(secret => secret.Properties.Version == version);
        }

        public Task<KeyVaultSecret> GetSecretAsync(string name, string? version, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_secrets.TryGetValue(name, out var versions) || versions.Count == 0)
            {
                throw new InvalidOperationException($"Missing test secret {name}.");
            }

            if (version is null)
            {
                HeadReadCount++;
                BeforeHeadRead?.Invoke(HeadReadCount);
                versions = _secrets[name];
                return Task.FromResult(Clone(versions[^1]));
            }

            return Task.FromResult(Clone(versions.Single(secret => secret.Properties.Version == version)));
        }

        public async IAsyncEnumerable<SecretProperties> GetPropertiesOfSecretsAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            foreach (var secretVersions in _secrets.Values)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return Clone(secretVersions[^1]).Properties;
                await Task.Yield();
            }
        }

        public async IAsyncEnumerable<DeletedSecret> GetDeletedSecretsAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            yield break;
        }

        public Task<KeyVaultSecret> SetSecretAsync(KeyVaultSecret secret, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SetCount++;
            var version = $"target-write-{++_writeVersion}";
            AddVersion(secret.Name, version, secret.Value, secret.Properties.Enabled, secret.Properties.ContentType);
            return Task.FromResult(Clone(GetVersion(secret.Name, version)));
        }

        public Task<SecretProperties> UpdateSecretPropertiesAsync(
            SecretProperties properties,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = GetVersion(properties.Name, properties.Version!);
            AddVersion(
                properties.Name,
                properties.Version!,
                current.Value,
                properties.Enabled,
                properties.ContentType);
            return Task.FromResult(Clone(GetVersion(properties.Name, properties.Version!)).Properties);
        }

        private static KeyVaultSecret CreateSecret(
            string vaultName,
            string name,
            string version,
            string value,
            bool? enabled,
            string? contentType)
        {
            var vaultUri = new Uri($"https://{vaultName}.vault.azure.net/");
            var properties = SecretModelFactory.SecretProperties(
                id: new Uri($"{vaultUri}secrets/{name}/{version}"),
                vaultUri: vaultUri,
                name: name,
                version: version,
                managed: false,
                keyId: null,
                createdOn: null,
                updatedOn: null,
                recoveryLevel: null);
            properties.Enabled = enabled;
            properties.ContentType = contentType;
            return SecretModelFactory.KeyVaultSecret(properties, value);
        }

        private static KeyVaultSecret Clone(KeyVaultSecret secret)
        {
            var clone = CreateSecret(
                secret.Properties.VaultUri!.Host.Split('.')[0],
                secret.Name,
                secret.Properties.Version!,
                secret.Value,
                secret.Properties.Enabled,
                secret.Properties.ContentType);
            clone.Properties.NotBefore = secret.Properties.NotBefore;
            clone.Properties.ExpiresOn = secret.Properties.ExpiresOn;
            clone.Properties.Tags.Clear();
            if (secret.Properties.Tags is not null)
            {
                foreach (var tag in secret.Properties.Tags)
                {
                    clone.Properties.Tags[tag.Key] = tag.Value;
                }
            }

            return clone;
        }
    }

    private sealed class TestLease(PairState state) : IPairStateLease
    {
        public PairState State { get; } = state;
        public int SaveCount { get; private set; }

        public void EnsureLeaseHeld()
        {
        }

        public Task SaveStateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SaveCount++;
            return Task.CompletedTask;
        }
    }
}
