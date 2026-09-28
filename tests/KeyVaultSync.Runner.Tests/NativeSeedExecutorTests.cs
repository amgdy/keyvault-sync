using System.Security.Cryptography;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using KeyVaultSync.Runner;
using KeyVaultSync.Runner.Security;
using KeyVaultSync.Runner.State;
using KeyVaultSync.Runner.Sync;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class NativeSeedExecutorTests
{
    private const string KeyName = "signing-key";
    private const string KeyVersion = "key-v1";
    private const string KeyFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string CertificateName = "service-certificate";
    private const string CertificateVersion = "certificate-v1";
    private const string CertificateFingerprint = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    private const string BackingKeyVersion = "backing-key-v1";
    private const string BackingSecretVersion = "backing-secret-v1";

    [Fact]
    public async Task Key_seed_restores_once_verifies_and_commits_the_baseline()
    {
        var (pair, sourceInventory, plan) = CreateKeySeed();
        var state = CreateState(pair);
        var lease = new TestLease(state);
        var sourceClient = new TestClient
        {
            Key = KeyObservation(KeyVersion),
        };
        var targetClient = new TestClient
        {
            RestoredKey = KeyObservation(KeyVersion),
        };
        targetClient.NameOccupiedResults.Enqueue(false);
        targetClient.NameOccupiedResults.Enqueue(false);

        var results = await CreateExecutor(sourceClient, targetClient).ApplyAsync(
            pair, lease, "run-key-seed", [plan], sourceInventory, CancellationToken.None);

        var result = Assert.Single(results);
        Assert.Equal("NATIVE_KEY_SEEDED_AND_VERIFIED", result.Status);
        Assert.Equal(1, sourceClient.KeyBackupCount);
        Assert.Equal(1, targetClient.KeyRestoreCount);
        Assert.Equal(2, lease.SaveCount);
        Assert.Empty(state.PendingKeySeeds);
        Assert.Equal(KeyVersion, state.KeySeedBaselines[KeyName].TargetVersion);
        Assert.All(sourceClient.BackupPayload, value => Assert.Equal(0, value));
        Assert.Equal(new byte[] { 1, 2, 3 }, targetClient.BackupReceivedAtRestore);
    }

    [Fact]
    public async Task Certificate_seed_restores_and_verifies_the_certificate_group_as_a_unit()
    {
        var (pair, sourceInventory, plan, sourceGroup) = CreateCertificateSeed();
        var state = CreateState(pair);
        var lease = new TestLease(state);
        var sourceClient = new TestClient
        {
            CertificateGroup = sourceGroup,
        };
        var targetClient = new TestClient
        {
            RestoredCertificateGroup = sourceGroup,
        };
        targetClient.NameOccupiedResults.Enqueue(false);
        targetClient.NameOccupiedResults.Enqueue(false);

        var results = await CreateExecutor(sourceClient, targetClient).ApplyAsync(
            pair, lease, "run-certificate-seed", [plan], sourceInventory, CancellationToken.None);

        var result = Assert.Single(results);
        Assert.Equal("NATIVE_CERTIFICATE_GROUP_SEEDED_AND_VERIFIED", result.Status);
        Assert.Equal(1, sourceClient.CertificateBackupCount);
        Assert.Equal(1, targetClient.CertificateRestoreCount);
        Assert.Equal(2, lease.SaveCount);
        Assert.Empty(state.PendingCertificateGroupSeeds);
        Assert.Equal(CertificateVersion, state.CertificateGroupSeedBaselines[CertificateName].TargetVersion);
        Assert.Equal(BackingKeyVersion, state.CertificateGroupSeedBaselines[CertificateName].BackingKeyVersion);
        Assert.Equal(BackingSecretVersion, state.CertificateGroupSeedBaselines[CertificateName].BackingSecretVersion);
        Assert.All(sourceClient.BackupPayload, value => Assert.Equal(0, value));
        Assert.Equal(new byte[] { 1, 2, 3 }, targetClient.BackupReceivedAtRestore);
    }

    [Fact]
    public async Task Ambiguous_restore_leaves_a_durable_intent_and_blocks_a_second_attempt()
    {
        var (pair, sourceInventory, plan) = CreateKeySeed();
        var state = CreateState(pair);
        var lease = new TestLease(state);
        var sourceClient = new TestClient
        {
            Key = KeyObservation(KeyVersion),
        };
        var targetClient = new TestClient
        {
            RestoreKeyException = new HttpRequestException("Simulated lost restore response."),
        };
        targetClient.NameOccupiedResults.Enqueue(false);
        targetClient.NameOccupiedResults.Enqueue(false);
        var executor = CreateExecutor(sourceClient, targetClient);

        var firstResult = Assert.Single(await executor.ApplyAsync(
            pair, lease, "run-ambiguous-seed", [plan], sourceInventory, CancellationToken.None));
        var sourceReadsAfterFirstAttempt = sourceClient.KeyReadCount;
        var secondResult = Assert.Single(await executor.ApplyAsync(
            pair, lease, "run-retry", [plan], sourceInventory, CancellationToken.None));

        Assert.Equal("NATIVE_SEED_OUTCOME_UNRESOLVED", firstResult.Status);
        Assert.Equal("BLOCKED_PENDING_NATIVE_SEED_RESOLUTION", secondResult.Status);
        Assert.Single(state.PendingKeySeeds);
        Assert.Empty(state.KeySeedBaselines);
        Assert.Equal(1, targetClient.KeyRestoreCount);
        Assert.Equal(1, lease.SaveCount);
        Assert.Equal(sourceReadsAfterFirstAttempt, sourceClient.KeyReadCount);
    }

    [Fact]
    public async Task Target_name_appearing_after_intent_is_not_overwritten()
    {
        var (pair, sourceInventory, plan) = CreateKeySeed();
        var state = CreateState(pair);
        var lease = new TestLease(state);
        var sourceClient = new TestClient
        {
            Key = KeyObservation(KeyVersion),
        };
        var targetClient = new TestClient();
        targetClient.NameOccupiedResults.Enqueue(false);
        targetClient.NameOccupiedResults.Enqueue(true);

        var result = Assert.Single(await CreateExecutor(sourceClient, targetClient).ApplyAsync(
            pair, lease, "run-target-collision", [plan], sourceInventory, CancellationToken.None));

        Assert.Equal("BLOCKED_TARGET_NAME_BECAME_OCCUPIED", result.Status);
        Assert.Equal(0, targetClient.KeyRestoreCount);
        Assert.Empty(state.PendingKeySeeds);
        Assert.Equal(2, lease.SaveCount);
    }

    [Fact]
    public async Task Source_head_change_after_intent_clears_intent_without_restoring()
    {
        var (pair, sourceInventory, plan) = CreateKeySeed();
        var state = CreateState(pair);
        var lease = new TestLease(state);
        var sourceClient = new TestClient
        {
            Key = KeyObservation(KeyVersion),
        };
        sourceClient.KeyHeadVersions.Enqueue(KeyVersion);
        sourceClient.KeyHeadVersions.Enqueue(KeyVersion);
        sourceClient.KeyHeadVersions.Enqueue("key-v2");
        var targetClient = new TestClient();
        targetClient.NameOccupiedResults.Enqueue(false);

        var result = Assert.Single(await CreateExecutor(sourceClient, targetClient).ApplyAsync(
            pair, lease, "run-source-change", [plan], sourceInventory, CancellationToken.None));

        Assert.Equal("BLOCKED_SOURCE_KEY_HEAD_CHANGED", result.Status);
        Assert.Equal(0, targetClient.KeyRestoreCount);
        Assert.Empty(state.PendingKeySeeds);
        Assert.Equal(2, lease.SaveCount);
    }

    [Fact]
    public async Task Intent_persistence_failure_prevents_restore()
    {
        var (pair, sourceInventory, plan) = CreateKeySeed();
        var state = CreateState(pair);
        var lease = new TestLease(state) { FailOnSave = 1 };
        var sourceClient = new TestClient
        {
            Key = KeyObservation(KeyVersion),
        };
        var targetClient = new TestClient();
        targetClient.NameOccupiedResults.Enqueue(false);

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => CreateExecutor(sourceClient, targetClient).ApplyAsync(
            pair, lease, "run-state-failure", [plan], sourceInventory, CancellationToken.None));

        Assert.Equal(0, targetClient.KeyRestoreCount);
        Assert.Single(state.PendingKeySeeds);
        Assert.Equal(1, lease.SaveCount);
        Assert.All(sourceClient.BackupPayload, value => Assert.Equal(0, value));
    }

    [Fact]
    public void Planner_blocks_native_seed_when_either_inventory_is_incomplete()
    {
        var (pair, sourceInventory, _) = CreateKeySeed();
        var state = CreateState(pair);
        var targetInventory = CreateInventory(pair.Target);

        var plan = SyncPlanner.CreatePlan(
            pair,
            state,
            sourceInventory with { Warnings = ["Key version listing failed."] },
            targetInventory,
            hmacAvailable: false);

        var keyPlan = Assert.Single(plan, item => item.ObjectType == "Key");
        Assert.Equal("BLOCKED_INCOMPLETE_INVENTORY", keyPlan.Status);
    }

    [Fact]
    public async Task Certificate_backing_secret_is_excluded_even_when_reference_is_missing()
    {
        var (pair, _, _) = CreateKeySeed();
        var backingSecretName = "unresolved-certificate";
        var sourceInventory = CreateInventory(pair.Source, secrets:
        [
            new SecretSummary
            {
                Name = backingSecretName,
                CurrentVersion = "secret-v1",
                Versions = [Version("secret-v1")],
            },
        ], certificates:
        [
            new CertificateSummary
            {
                Name = backingSecretName,
                CurrentVersion = "certificate-v1",
                Versions = [Version("certificate-v1")],
                KeyId = null,
                SecretId = null,
            },
        ]);
        var targetInventory = CreateInventory(pair.Target);
        var lease = new TestLease(CreateState(pair));
        using var hmac = SecretHmacService.Load(new RunnerOptions
        {
            SubscriptionId = "test-subscription",
            StorageAccountUri = new Uri("https://example.blob.core.windows.net/"),
            HmacKeyBase64 = Convert.ToBase64String(new byte[32]),
            HmacKeyVersion = "test-key-v1",
        })!;
        var executor = new SecretSyncExecutor(
            new TestCredential(),
            NullLogger<SecretSyncExecutor>.Instance);
        var plannedSecret = new PlanItem
        {
            ObjectType = "Secret",
            Name = backingSecretName,
            Action = "SetSecret",
            Status = "READY_FOR_APPLY_IF_NAME_STAYS_EMPTY",
            SourceVersion = "secret-v1",
        };

        var result = Assert.Single(await executor.ApplyAsync(
            pair, lease, "run-certificate-exclusion", [plannedSecret], sourceInventory, targetInventory, hmac, CancellationToken.None));

        Assert.Equal("CERTIFICATE_BACKING_SECRET_NOT_WRITTEN", result.Status);
        Assert.Equal(0, lease.SaveCount);
    }

    [Fact]
    public void Key_fingerprint_uses_only_public_rsa_components()
    {
        using var rsa = RSA.Create(2048);
        var privateJwk = new JsonWebKey(rsa, includePrivateParameters: true);
        var publicJwk = new JsonWebKey(rsa, includePrivateParameters: false);

        Assert.Equal(KeyVaultPublicFingerprint.Compute(publicJwk), KeyVaultPublicFingerprint.Compute(privateJwk));
    }

    [Fact]
    public void Key_fingerprint_supports_public_ec_components()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new JsonWebKey(ec, includePrivateParameters: false);

        Assert.NotNull(KeyVaultPublicFingerprint.Compute(key));
    }

    private static NativeSeedExecutor CreateExecutor(TestClient sourceClient, TestClient targetClient)
    {
        return new NativeSeedExecutor(
            new TestClientFactory(sourceClient, targetClient),
            NullLogger<NativeSeedExecutor>.Instance);
    }

    private static (VaultPair Pair, VaultInventory Source, PlanItem Plan) CreateKeySeed()
    {
        var pair = CreatePair();
        var key = new KeySummary
        {
            Name = KeyName,
            CurrentVersion = KeyVersion,
            Versions = [Version("key-v0"), Version(KeyVersion)],
            KeyType = "RSA",
            PublicFingerprintSha256 = KeyFingerprint,
        };
        var source = CreateInventory(pair.Source, keys: [key]);
        var plan = new PlanItem
        {
            ObjectType = "Key",
            Name = KeyName,
            Action = "NativeRestore",
            Status = "ELIGIBLE_ONE_TIME_SEED_IF_TARGET_STAYS_EMPTY",
            SourceVersion = KeyVersion,
        };
        return (pair, source, plan);
    }

    private static (VaultPair Pair, VaultInventory Source, PlanItem Plan, NativeCertificateGroupObservation Group) CreateCertificateSeed()
    {
        var pair = CreatePair();
        var certificate = new CertificateSummary
        {
            Name = CertificateName,
            CurrentVersion = CertificateVersion,
            Versions = [Version(CertificateVersion), Version("certificate-v0")],
            ThumbprintSha256 = CertificateFingerprint,
            KeyId = $"https://{pair.Source.Name}.vault.azure.net/keys/{CertificateName}/{BackingKeyVersion}",
            SecretId = $"https://{pair.Source.Name}.vault.azure.net/secrets/{CertificateName}/{BackingSecretVersion}",
        };
        var backingKey = new KeySummary
        {
            Name = CertificateName,
            CurrentVersion = BackingKeyVersion,
            Versions = [Version(BackingKeyVersion)],
            KeyType = "RSA",
            PublicFingerprintSha256 = KeyFingerprint,
        };
        var backingSecret = new SecretSummary
        {
            Name = CertificateName,
            CurrentVersion = BackingSecretVersion,
            Versions = [Version(BackingSecretVersion)],
        };
        var source = CreateInventory(pair.Source, secrets: [backingSecret], keys: [backingKey], certificates: [certificate]);
        var group = new NativeCertificateGroupObservation(
            CertificateName,
            CertificateVersion,
            CertificateFingerprint,
            CertificateName,
            BackingKeyVersion,
            "RSA",
            KeyFingerprint,
            CertificateName,
            BackingSecretVersion,
            [CertificateVersion, "certificate-v0"],
            [BackingKeyVersion],
            [BackingSecretVersion]);
        var plan = new PlanItem
        {
            ObjectType = "CertificateGroup",
            Name = CertificateName,
            Action = "NativeRestore",
            Status = "ELIGIBLE_ONE_TIME_SEED_IF_TARGET_GROUP_STAYS_EMPTY",
            SourceVersion = CertificateVersion,
        };
        return (pair, source, plan, group);
    }

    private static NativeKeyObservation KeyObservation(string version)
    {
        return new NativeKeyObservation(
            KeyName,
            version,
            "RSA",
            KeyFingerprint,
            ["key-v0", KeyVersion]);
    }

    private static VaultPair CreatePair()
    {
        var source = new VaultResource
        {
            Id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source",
            Name = "source",
            Location = "eastus",
            ResourceGroup = "rg",
            Tags = [],
        };
        var target = new VaultResource
        {
            Id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target",
            Name = "target",
            Location = "eastus",
            ResourceGroup = "rg",
            Tags = [],
        };
        return new VaultPair(source, target);
    }

    private static VaultInventory CreateInventory(
        VaultResource vault,
        IReadOnlyList<SecretSummary>? secrets = null,
        IReadOnlyList<KeySummary>? keys = null,
        IReadOnlyList<CertificateSummary>? certificates = null,
        IReadOnlyList<string>? warnings = null)
    {
        return new VaultInventory
        {
            VaultId = vault.Id,
            VaultName = vault.Name,
            Region = vault.Location,
            Authorization = new VaultAuthorizationSummary
            {
                UsesRbac = false,
                AccessPolicies = [],
                RoleAssignments = [],
                Warnings = [],
            },
            Secrets = secrets ?? [],
            Keys = keys ?? [],
            Certificates = certificates ?? [],
            DeletedSecretNames = [],
            DeletedKeyNames = [],
            DeletedCertificateNames = [],
            Warnings = warnings ?? [],
        };
    }

    private static ObjectVersionSummary Version(string version) => new() { Version = version };

    private static PairState CreateState(VaultPair pair)
    {
        return new PairState
        {
            PairId = pair.PairId,
            SourceVaultId = pair.Source.Id,
            TargetVaultId = pair.Target.Id,
        };
    }

    private sealed class TestClientFactory(TestClient source, TestClient target) : INativeSeedVaultClientFactory
    {
        public INativeSeedVaultClient Create(VaultResource vault, bool isTarget) => isTarget ? target : source;
    }

    private sealed class TestClient : INativeSeedVaultClient
    {
        public NativeKeyObservation Key { get; init; } = KeyObservation(KeyVersion);
        public NativeKeyObservation RestoredKey { get; init; } = KeyObservation(KeyVersion);
        public NativeCertificateGroupObservation CertificateGroup { get; init; } = EmptyCertificateGroup();
        public NativeCertificateGroupObservation RestoredCertificateGroup { get; init; } = EmptyCertificateGroup();
        public byte[] BackupPayload { get; } = [1, 2, 3];
        public Queue<string> KeyHeadVersions { get; } = new();
        public Queue<string> CertificateHeadVersions { get; } = new();
        public Queue<bool> NameOccupiedResults { get; } = new();
        public Exception? RestoreKeyException { get; init; }
        public bool NameOccupied { get; init; }
        public int KeyReadCount { get; private set; }
        public int KeyBackupCount { get; private set; }
        public int KeyRestoreCount { get; private set; }
        public int CertificateBackupCount { get; private set; }
        public int CertificateRestoreCount { get; private set; }
        public byte[]? BackupReceivedAtRestore { get; private set; }

        public Task<NativeKeyObservation> ReadKeyAsync(string name, string? version, CancellationToken cancellationToken)
        {
            KeyReadCount++;
            var observedVersion = version;
            if (observedVersion is null && KeyHeadVersions.TryDequeue(out var headVersion))
            {
                observedVersion = headVersion;
            }

            return Task.FromResult(Key with { Name = name, Version = observedVersion ?? Key.Version });
        }

        public Task<byte[]> BackupKeyAsync(string name, CancellationToken cancellationToken)
        {
            KeyBackupCount++;
            return Task.FromResult(BackupPayload);
        }

        public Task<NativeKeyObservation> RestoreKeyBackupAsync(string name, byte[] backup, CancellationToken cancellationToken)
        {
            KeyRestoreCount++;
            BackupReceivedAtRestore = backup.ToArray();
            if (RestoreKeyException is not null)
            {
                throw RestoreKeyException;
            }

            return Task.FromResult(RestoredKey with { Name = name });
        }

        public Task<NativeCertificateGroupObservation> ReadCertificateGroupAsync(string name, string? version, CancellationToken cancellationToken)
        {
            var observedVersion = version;
            if (observedVersion is null && CertificateHeadVersions.TryDequeue(out var headVersion))
            {
                observedVersion = headVersion;
            }

            return Task.FromResult(CertificateGroup with { Name = name, Version = observedVersion ?? CertificateGroup.Version });
        }

        public Task<byte[]> BackupCertificateAsync(string name, CancellationToken cancellationToken)
        {
            CertificateBackupCount++;
            return Task.FromResult(BackupPayload);
        }

        public Task<NativeCertificateGroupObservation> RestoreCertificateBackupAsync(string name, byte[] backup, CancellationToken cancellationToken)
        {
            CertificateRestoreCount++;
            BackupReceivedAtRestore = backup.ToArray();
            return Task.FromResult(RestoredCertificateGroup with { Name = name });
        }

        public Task<bool> HasAnyObjectNamedAsync(string name, CancellationToken cancellationToken)
        {
            return Task.FromResult(NameOccupiedResults.TryDequeue(out var occupied) ? occupied : NameOccupied);
        }

        private static NativeCertificateGroupObservation EmptyCertificateGroup()
        {
            return new NativeCertificateGroupObservation(
                CertificateName,
                CertificateVersion,
                CertificateFingerprint,
                CertificateName,
                BackingKeyVersion,
                "RSA",
                KeyFingerprint,
                CertificateName,
                BackingSecretVersion,
                [CertificateVersion],
                [BackingKeyVersion],
                [BackingSecretVersion]);
        }
    }

    private sealed class TestLease(PairState state) : IPairStateLease
    {
        public PairState State { get; } = state;
        public int SaveCount { get; private set; }
        public int? FailOnSave { get; init; }

        public void EnsureLeaseHeld()
        {
        }

        public Task SaveStateAsync(CancellationToken cancellationToken)
        {
            SaveCount++;
            if (SaveCount == FailOnSave)
            {
                throw new IOException("Simulated pair-state save failure.");
            }

            return Task.CompletedTask;
        }
    }

    private sealed class TestCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return new AccessToken("test-token", DateTimeOffset.UtcNow.AddMinutes(5));
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(GetToken(requestContext, cancellationToken));
        }
    }
}
