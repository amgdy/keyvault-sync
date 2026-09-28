using System.Net;
using System.Net.Http;
using System.Text.Json;
using Azure.Core;
using KeyVaultSync.Runner;
using KeyVaultSync.Runner.Azure;
using KeyVaultSync.Runner.Security;
using KeyVaultSync.Runner.Sync;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

/// <summary>Checks planning and execution safety gates without live Azure resources.</summary>
public sealed class SafetyPlanningTests
{
    [Fact]
    public void Pending_write_blocks_any_secret_retry()
    {
        var (pair, source, target) = CreatePair();
        var state = CreateState(pair);
        state.PendingSecretWrites["db-password"] = new SecretWriteIntent
        {
            RunId = "run-1",
            SourceVersion = "source-v2",
            ExpectedValueHmac = "value-hmac",
            ExpectedMetadataDigest = "metadata-digest",
            HmacKeyVersion = "key-version-1",
            TargetVersionBefore = "target-v1",
            CreatedAt = DateTimeOffset.UtcNow,
        };

        var plan = SyncPlanner.CreatePlan(pair, state, source, target, hmacAvailable: true);
        var secretItem = Assert.Single(plan, item => item.ObjectType == "Secret");

        Assert.Equal("BLOCKED_PENDING_WRITE_RESOLUTION", secretItem.Status);
        Assert.Equal("ResolvePendingWrite", secretItem.Action);
    }

    [Fact]
    public void Missing_target_with_baseline_is_not_recreated_automatically()
    {
        var (pair, source, _) = CreatePair();
        var target = CreateInventory(pair.Target, []);
        var state = CreateState(pair);
        state.SecretBaselines["db-password"] = new SecretBaseline
        {
            ValueDomainVersion = SecretHmacService.ValueDomainVersion,
            MetadataDomainVersion = SecretHmacService.MetadataDomainVersion,
            SourceVersion = "source-v1",
            TargetVersion = "target-v1",
            ValueHmac = "value-hmac",
            HmacKeyVersion = "key-version-1",
            MetadataDigest = "metadata-digest",
            VerifiedAt = DateTimeOffset.UtcNow,
        };

        var plan = SyncPlanner.CreatePlan(pair, state, source, target, hmacAvailable: true);
        var secretItem = Assert.Single(plan, item => item.ObjectType == "Secret");

        Assert.Equal("CONFLICT_PREVIOUS_TARGET_MISSING", secretItem.Status);
        Assert.Equal("None", secretItem.Action);
    }

    [Fact]
    public void Metadata_only_change_is_planned_for_guarded_verification()
    {
        var (pair, source, target) = CreatePair();
        var state = CreateState(pair);
        state.SecretBaselines["db-password"] = new SecretBaseline
        {
            ValueDomainVersion = SecretHmacService.ValueDomainVersion,
            MetadataDomainVersion = SecretHmacService.MetadataDomainVersion,
            SourceVersion = "source-v1",
            TargetVersion = "target-v1",
            ValueHmac = new string('A', 64),
            HmacKeyVersion = "key-version-1",
            MetadataDigest = "previous-metadata-digest",
            VerifiedAt = DateTimeOffset.UtcNow,
        };

        var plan = SyncPlanner.CreatePlan(pair, state, source, target, hmacAvailable: true);
        var secretItem = Assert.Single(plan, item => item.ObjectType == "Secret");

        Assert.Equal("VERIFY_TARGET_HMAC_THEN_APPLY_METADATA", secretItem.Status);
        Assert.Equal("UpdateSecretProperties", secretItem.Action);
    }

    [Fact]
    public void New_secret_is_eligible_only_when_hmac_is_available_and_target_is_absent()
    {
        var (pair, source, _) = CreatePair();
        var target = CreateInventory(pair.Target, []);

        var plan = SyncPlanner.CreatePlan(pair, CreateState(pair), source, target, hmacAvailable: true);
        var secretItem = Assert.Single(plan, item => item.ObjectType == "Secret");

        Assert.Equal("READY_FOR_APPLY_IF_NAME_STAYS_EMPTY", secretItem.Status);
        Assert.Equal("SetSecret", secretItem.Action);
    }

    [Fact]
    public void Soft_deleted_target_name_blocks_secret_write()
    {
        var (pair, source, _) = CreatePair();
        var target = CreateInventory(pair.Target, []) with
        {
            DeletedSecretNames = ["db-password"],
        };

        var plan = SyncPlanner.CreatePlan(pair, CreateState(pair), source, target, hmacAvailable: true);
        var secretItem = Assert.Single(plan, item => item.ObjectType == "Secret");

        Assert.Equal("BLOCKED_SOFT_DELETED_TARGET", secretItem.Status);
        Assert.Equal("SetSecret", secretItem.Action);
    }

    [Fact]
    public void Partial_inventory_is_reported_as_a_warning_plan_item()
    {
        var (pair, source, target) = CreatePair();
        var partialSource = source with
        {
            Warnings = ["Secret page could not be read."],
        };

        var plan = SyncPlanner.CreatePlan(pair, CreateState(pair), partialSource, target, hmacAvailable: true);
        var warning = Assert.Single(plan, item => item.ObjectType == "Inventory");

        Assert.Equal("INVENTORY_WARNING", warning.Status);
        Assert.Contains("Secret page could not be read.", warning.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Legacy_hmac_domain_baseline_requires_review()
    {
        var (pair, source, target) = CreatePair();
        var state = CreateState(pair);
        state.SecretBaselines["db-password"] = new SecretBaseline
        {
            ValueDomainVersion = "kvdr/secret/v1",
            MetadataDomainVersion = "kvdr/secret-metadata/v1",
            SourceVersion = "source-v1",
            TargetVersion = "target-v1",
            ValueHmac = new string('A', 64),
            HmacKeyVersion = "key-version-1",
            MetadataDigest = "metadata-digest",
            VerifiedAt = DateTimeOffset.UtcNow,
        };

        var plan = SyncPlanner.CreatePlan(pair, state, source, target, hmacAvailable: true);
        var secretItem = Assert.Single(plan, item => item.ObjectType == "Secret");

        Assert.Equal("CONFLICT_HMAC_DOMAIN_VERSION", secretItem.Status);
        Assert.Equal("RebaselineAfterReview", secretItem.Action);
    }

    [Fact]
    public void Hmac_value_comparison_rejects_malformed_and_different_values()
    {
        var expected = new string('A', 64);

        Assert.True(SecretHmacService.ValueHmacEquals(expected, new string('A', 64)));
        Assert.False(SecretHmacService.ValueHmacEquals(expected, new string('B', 64)));
        Assert.False(SecretHmacService.ValueHmacEquals(expected, "not-a-hmac"));
        Assert.False(SecretHmacService.ValueHmacEquals(expected, new string('Z', 64)));
        Assert.False(SecretHmacService.ValueHmacEquals(null, expected));
    }

    [Fact]
    public void Hmac_configuration_loads_a_32_byte_key_and_version()
    {
        var options = CreateHmacOptions(Convert.ToBase64String(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray()), "config-v2");

        using var hmac = SecretHmacService.Load(options);

        Assert.NotNull(hmac);
        Assert.Equal("config-v2", hmac.KeyVersion);
    }

    [Fact]
    public void Hmac_configuration_rejects_malformed_key()
    {
        var options = CreateHmacOptions("not-base64", "config-v1");

        var exception = Assert.Throws<InvalidOperationException>(() => LoadAndDisposeHmac(options));

        Assert.Contains("base64", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Hmac_configuration_rejects_key_that_is_not_32_bytes()
    {
        var options = CreateHmacOptions(Convert.ToBase64String(new byte[31]), "config-v1");

        var exception = Assert.Throws<InvalidOperationException>(() => LoadAndDisposeHmac(options));

        Assert.Contains("32 bytes", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Trace", LogLevel.Trace)]
    [InlineData("Debug", LogLevel.Debug)]
    [InlineData("Information", LogLevel.Information)]
    [InlineData("Warning", LogLevel.Warning)]
    [InlineData("Error", LogLevel.Error)]
    [InlineData("Critical", LogLevel.Critical)]
    public void Logging_configuration_accepts_each_standard_level(string configuredLevel, LogLevel expectedLevel)
    {
        Assert.True(TelemetryRuntime.TryParseMinimumLogLevel(configuredLevel, out var parsedLevel));
        Assert.Equal(expectedLevel, parsedLevel);
    }

    [Theory]
    [InlineData("None")]
    [InlineData("Verbose")]
    [InlineData("99")]
    public void Logging_configuration_rejects_unsupported_levels_and_defaults_to_information(string configuredLevel)
    {
        Assert.False(TelemetryRuntime.TryParseMinimumLogLevel(configuredLevel, out var parsedLevel));
        Assert.Equal(LogLevel.Information, parsedLevel);
    }

    [Fact]
    public void Metadata_digest_treats_missing_enabled_as_key_vault_default_true()
    {
        var withoutExplicitEnabled = SecretHmacService.ComputeMetadata(null, "text/plain", null, null, null);
        var explicitlyEnabled = SecretHmacService.ComputeMetadata(true, "text/plain", null, null, null);

        Assert.Equal(explicitlyEnabled, withoutExplicitEnabled);
    }

    [Fact]
    public void Mapped_sync_requires_no_runtime_mutation_switch_and_allows_missing_hmac()
    {
        var retiredSettings = new[]
        {
            "KEYVAULTSYNC_APPLY_SECRETS",
            "KEYVAULTSYNC_SEED_MISSING_KEYS_AND_CERTIFICATES",
            "KEYVAULTSYNC_SINGLE_WRITER_MODE",
        };
        var originalRetiredSettings = retiredSettings.ToDictionary(
            name => name,
            Environment.GetEnvironmentVariable,
            StringComparer.Ordinal);
        var originalHmacKey = Environment.GetEnvironmentVariable("KEYVAULTSYNC_HMAC_KEY");
        try
        {
            foreach (var name in retiredSettings)
            {
                Environment.SetEnvironmentVariable(name, null);
            }
            Environment.SetEnvironmentVariable("KEYVAULTSYNC_HMAC_KEY", null);

            var options = RunnerOptions.Parse(
            [
                "--subscription", "test-subscription",
                "--storage-account-uri", "https://example.blob.core.windows.net/",
            ]);
            Assert.Null(options.HmacKeyBase64);

            foreach (var retiredSwitch in new[]
            {
                "--apply-secrets",
                "--seed-missing-keys-and-certificates",
                "--single-writer-mode",
            })
            {
                var exception = Assert.Throws<ArgumentException>(() => RunnerOptions.Parse(
                [
                    "--subscription", "test-subscription",
                    "--storage-account-uri", "https://example.blob.core.windows.net/",
                    retiredSwitch,
                ]));
                Assert.Contains("no longer supported", exception.Message, StringComparison.OrdinalIgnoreCase);
            }

            foreach (var retiredSetting in retiredSettings)
            {
                Environment.SetEnvironmentVariable(retiredSetting, "false");
                var exception = Assert.Throws<ArgumentException>(() => RunnerOptions.Parse(
                [
                    "--subscription", "test-subscription",
                    "--storage-account-uri", "https://example.blob.core.windows.net/",
                ]));
                Assert.Contains(retiredSetting, exception.Message, StringComparison.Ordinal);
                Environment.SetEnvironmentVariable(retiredSetting, null);
            }
        }
        finally
        {
            foreach (var (name, value) in originalRetiredSettings)
            {
                Environment.SetEnvironmentVariable(name, value);
            }
            Environment.SetEnvironmentVariable("KEYVAULTSYNC_HMAC_KEY", originalHmacKey);
        }
    }

    [Theory]
    [InlineData("RBAC_INVENTORY_ONLY", false)]
    [InlineData("ACCESS_POLICY_INTENT_MATCH", false)]
    [InlineData("ACCESS_POLICY_INTENT_DIFFERS", true)]
    [InlineData("PERMISSION_MODEL_MISMATCH", true)]
    [InlineData("AUTHORIZATION_INVENTORY_INCOMPLETE", true)]
    public void Authorization_inventory_only_does_not_count_as_unapplied_work(string status, bool expected)
    {
        var plan = new[]
        {
            new PlanItem
            {
                ObjectType = "Authorization",
                Name = "source-vault",
                Action = "CompareDeclaredIntent",
                Status = status,
            },
        };

        Assert.Equal(expected, RunnerApplication.HasUnappliedWork(plan));
    }

    [Fact]
    public async Task Arm_discovery_retries_transient_get_transport_failure()
    {
        var handler = new FirstRequestFailsHandler();
        using var httpClient = new HttpClient(handler);
        var client = new ArmResourceClient(new TestCredential(), NullLogger<ArmResourceClient>.Instance, httpClient);
        var options = new RunnerOptions
        {
            SubscriptionId = "test-subscription",
            StorageAccountUri = new Uri("https://example.blob.core.windows.net/"),
        };

        var discovery = await client.DiscoverPairsAsync(options, CancellationToken.None);

        Assert.Equal(2, handler.RequestCount);
        Assert.Equal(0, discovery.DiscoveredVaultCount);
        Assert.Empty(discovery.Issues);
    }

    [Fact]
    public async Task Arm_discovery_skips_pair_when_source_has_disable_tag()
    {
        var sourceId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source";
        var targetId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target";
        var response = CreateVaultListJson(
            sourceId,
            new Dictionary<string, string>
            {
                ["sync-vault-id"] = targetId,
                [KeyVaultSyncResourceTags.SyncDisabled] = "true",
            },
            targetId,
            new Dictionary<string, string>());
        using var httpClient = new HttpClient(new StaticJsonHandler(response));
        var client = new ArmResourceClient(new TestCredential(), NullLogger<ArmResourceClient>.Instance, httpClient);

        var discovery = await client.DiscoverPairsAsync(CreateDiscoveryOptions(), CancellationToken.None);

        Assert.Empty(discovery.Pairs);
        Assert.Equal(1, discovery.DisabledPairCount);
        Assert.Contains("source", discovery.DisabledVaultNames, StringComparer.OrdinalIgnoreCase);
        Assert.Empty(discovery.Issues);
    }

    [Fact]
    public async Task Arm_discovery_skips_pair_when_target_has_disable_tag()
    {
        var sourceId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source";
        var targetId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target";
        var response = CreateVaultListJson(
            sourceId,
            new Dictionary<string, string> { ["sync-vault-id"] = targetId },
            targetId,
            new Dictionary<string, string> { [KeyVaultSyncResourceTags.SyncDisabled] = "true" });
        using var httpClient = new HttpClient(new StaticJsonHandler(response));
        var client = new ArmResourceClient(new TestCredential(), NullLogger<ArmResourceClient>.Instance, httpClient);

        var discovery = await client.DiscoverPairsAsync(CreateDiscoveryOptions(), CancellationToken.None);

        Assert.Empty(discovery.Pairs);
        Assert.Equal(1, discovery.DisabledPairCount);
        Assert.Contains("target", discovery.DisabledVaultNames, StringComparer.OrdinalIgnoreCase);
        Assert.Empty(discovery.Issues);
    }

    [Fact]
    public async Task Arm_discovery_admits_pair_when_disable_tag_is_absent()
    {
        var sourceId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source";
        var targetId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target";
        var response = CreateVaultListJson(
            sourceId,
            new Dictionary<string, string> { ["sync-vault-id"] = targetId },
            targetId,
            new Dictionary<string, string>());
        using var httpClient = new HttpClient(new StaticJsonHandler(response));
        var client = new ArmResourceClient(new TestCredential(), NullLogger<ArmResourceClient>.Instance, httpClient);

        var discovery = await client.DiscoverPairsAsync(CreateDiscoveryOptions(), CancellationToken.None);

        var pair = Assert.Single(discovery.Pairs);
        Assert.Equal(sourceId, pair.Source.Id);
        Assert.Equal(targetId, pair.Target.Id);
        Assert.Equal(0, discovery.DisabledPairCount);
        Assert.Empty(discovery.DisabledVaultNames);
        Assert.Empty(discovery.Issues);
    }

    [Fact]
    public async Task Arm_discovery_supports_multiple_targets_from_both_mapping_tag_directions()
    {
        var sourceId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source";
        var firstTargetId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target-one";
        var secondTargetId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target-two";
        var response = CreateVaultListJson(
            (sourceId, new Dictionary<string, string> { ["sync-vault-id"] = firstTargetId }),
            (firstTargetId, new Dictionary<string, string>()),
            (secondTargetId, new Dictionary<string, string>
            {
                [KeyVaultSyncResourceTags.SyncSourceKeyVaultId] = sourceId,
            }));
        using var httpClient = new HttpClient(new StaticJsonHandler(response));
        var client = new ArmResourceClient(new TestCredential(), NullLogger<ArmResourceClient>.Instance, httpClient);

        var discovery = await client.DiscoverPairsAsync(CreateDiscoveryOptions(), CancellationToken.None);

        Assert.Equal(2, discovery.Pairs.Count);
        Assert.Contains(discovery.Pairs, pair => pair.Source.Id == sourceId && pair.Target.Id == firstTargetId);
        Assert.Contains(discovery.Pairs, pair => pair.Source.Id == sourceId && pair.Target.Id == secondTargetId);
        Assert.Equal(2, discovery.Pairs.Select(pair => pair.PairId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Empty(discovery.Issues);
    }

    [Fact]
    public async Task Arm_discovery_collapses_duplicate_declarations_of_the_same_pair()
    {
        var sourceId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source";
        var targetId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target";
        var response = CreateVaultListJson(
            (sourceId, new Dictionary<string, string> { ["sync-vault-id"] = targetId }),
            (targetId, new Dictionary<string, string>
            {
                [KeyVaultSyncResourceTags.SyncSourceKeyVaultId] = sourceId.ToUpperInvariant(),
            }));
        using var httpClient = new HttpClient(new StaticJsonHandler(response));
        var client = new ArmResourceClient(new TestCredential(), NullLogger<ArmResourceClient>.Instance, httpClient);

        var discovery = await client.DiscoverPairsAsync(CreateDiscoveryOptions(), CancellationToken.None);

        Assert.Single(discovery.Pairs);
        Assert.Empty(discovery.Issues);
    }

    [Fact]
    public async Task Arm_discovery_rejects_multiple_sources_claiming_the_same_target()
    {
        var firstSourceId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source-one";
        var secondSourceId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source-two";
        var targetId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target";
        var response = CreateVaultListJson(
            (firstSourceId, new Dictionary<string, string> { ["sync-vault-id"] = targetId }),
            (secondSourceId, new Dictionary<string, string>()),
            (targetId, new Dictionary<string, string>
            {
                [KeyVaultSyncResourceTags.SyncSourceKeyVaultId] = secondSourceId,
            }));
        using var httpClient = new HttpClient(new StaticJsonHandler(response));
        var client = new ArmResourceClient(new TestCredential(), NullLogger<ArmResourceClient>.Instance, httpClient);

        var discovery = await client.DiscoverPairsAsync(CreateDiscoveryOptions(), CancellationToken.None);

        Assert.Empty(discovery.Pairs);
        Assert.Contains(discovery.Issues, issue => issue.Contains("multiple distinct sources", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Arm_discovery_rejects_chained_source_target_mappings_deterministically()
    {
        var firstId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source";
        var secondId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/middle";
        var thirdId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target";
        var response = CreateVaultListJson(
            (firstId, new Dictionary<string, string> { ["sync-vault-id"] = secondId }),
            (secondId, new Dictionary<string, string> { ["sync-vault-id"] = thirdId }),
            (thirdId, new Dictionary<string, string>()));
        using var httpClient = new HttpClient(new StaticJsonHandler(response));
        var client = new ArmResourceClient(new TestCredential(), NullLogger<ArmResourceClient>.Instance, httpClient);

        var discovery = await client.DiscoverPairsAsync(CreateDiscoveryOptions(), CancellationToken.None);

        Assert.Empty(discovery.Pairs);
        Assert.Single(discovery.Issues, issue => issue.Contains("both a source and a target", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Arm_discovery_logs_sync_id_and_pair_state_as_structured_properties()
    {
        var sourceId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source";
        var targetId = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target";
        var response = CreateVaultListJson(
            sourceId,
            new Dictionary<string, string> { ["sync-vault-id"] = targetId },
            targetId,
            new Dictionary<string, string>());
        using var httpClient = new HttpClient(new StaticJsonHandler(response));
        var logger = new RecordingLogger<ArmResourceClient>();
        var client = new ArmResourceClient(new TestCredential(), logger, httpClient);

        await client.DiscoverPairsAsync(CreateDiscoveryOptions(), CancellationToken.None);

        var sourceLog = Assert.Single(logger.Entries, entry => entry.EventId.Name == "KeyVaultDiscovered"
            && Equals(entry.Properties.GetValueOrDefault("KeyVaultName"), "source"));
        Assert.True(Assert.IsType<bool>(sourceLog.Properties["HasSyncId"]));
        Assert.Equal(targetId, sourceLog.Properties["SyncId"]);

        var pairLog = Assert.Single(logger.Entries, entry => entry.EventId.Name == "KeyVaultSyncPairEvaluated");
        Assert.True(Assert.IsType<bool>(pairLog.Properties["SyncEnabled"]));
        Assert.Equal(targetId, pairLog.Properties["SyncId"]);
        Assert.Equal("Enabled", pairLog.Properties["Decision"]);
    }

    private static (VaultPair Pair, VaultInventory Source, VaultInventory Target) CreatePair()
    {
        var sourceVault = new VaultResource
        {
            Id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/source",
            Name = "source",
            Location = "eastus",
            ResourceGroup = "rg",
            Tags = [],
        };
        var targetVault = new VaultResource
        {
            Id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target",
            Name = "target",
            Location = "eastus",
            ResourceGroup = "rg",
            Tags = [],
        };
        var pair = new VaultPair(sourceVault, targetVault);
        var source = CreateInventory(sourceVault,
        [
            new SecretSummary
            {
                Name = "db-password",
                CurrentVersion = "source-v1",
                Versions = [],
                Enabled = true,
                ContentType = "text/plain",
            },
        ]);
        var target = CreateInventory(targetVault,
        [
            new SecretSummary
            {
                Name = "db-password",
                CurrentVersion = "target-v1",
                Versions = [],
                Enabled = true,
                ContentType = "text/plain",
            },
        ]);

        return (pair, source, target);
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

    private static RunnerOptions CreateHmacOptions(string keyBase64, string keyVersion)
    {
        return new RunnerOptions
        {
            SubscriptionId = "test-subscription",
            StorageAccountUri = new Uri("https://example.blob.core.windows.net/"),
            HmacKeyBase64 = keyBase64,
            HmacKeyVersion = keyVersion,
        };
    }

    private static RunnerOptions CreateDiscoveryOptions()
    {
        return new RunnerOptions
        {
            SubscriptionId = "sub",
            StorageAccountUri = new Uri("https://example.blob.core.windows.net/"),
        };
    }

    private static string CreateVaultListJson(
        string sourceId,
        IReadOnlyDictionary<string, string> sourceTags,
        string targetId,
        IReadOnlyDictionary<string, string> targetTags)
    {
        return CreateVaultListJson((sourceId, sourceTags), (targetId, targetTags));
    }

    private static string CreateVaultListJson(params (string Id, IReadOnlyDictionary<string, string> Tags)[] vaults)
    {
        return JsonSerializer.Serialize(new
        {
            value = vaults
                .Select(vault => new
            {
                    id = vault.Id,
                    name = vault.Id.Split('/', StringSplitOptions.RemoveEmptyEntries)[^1],
                    type = "Microsoft.KeyVault/vaults",
                    location = "eastus",
                    tags = vault.Tags,
                })
                .ToArray(),
        });
    }

    private static void LoadAndDisposeHmac(RunnerOptions options)
    {
        using var hmac = SecretHmacService.Load(options);
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
                UsesRbac = false,
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

    private sealed class FirstRequestFailsHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            if (RequestCount == 1)
            {
                throw new HttpRequestException("Simulated transient socket failure.");
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"value\":[]}"),
            });
        }
    }

    private sealed class StaticJsonHandler(string content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(content),
            });
        }
    }

    private sealed record RecordedLogEntry(EventId EventId, LogLevel LogLevel, IReadOnlyDictionary<string, object?> Properties);

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<RecordedLogEntry> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var properties = state is IEnumerable<KeyValuePair<string, object?>> structuredState
                ? structuredState.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal)
                : new Dictionary<string, object?>(StringComparer.Ordinal);
            Entries.Add(new RecordedLogEntry(eventId, logLevel, properties));
        }
    }
}