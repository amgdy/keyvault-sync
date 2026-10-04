using System.Text;
using KeyVaultSync.Runner;
using KeyVaultSync.Runner.Azure;
using KeyVaultSync.Runner.Security;
using KeyVaultSync.Runner.State;
using KeyVaultSync.Runner.Sync;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class ObjectReplicationTests
{
    [Fact]
    public async Task Create_persists_intent_before_write_and_commits_verified_baseline()
    {
        var source = Snapshot("source://secrets/demo", "s1", "value");
        var targetClient = new FakeObjectClient("target://secrets");
        var lease = new FakeLease(NewState());
        targetClient.State = lease.State;
        var executor = new ObjectExecutor(
            new FakeObjectFactory(new FakeObjectClient("source://secrets", source), targetClient),
            NullLogger<ObjectExecutor>.Instance);
        using var signatures = LoadSignatures();

        var results = await executor.ApplyAsync(
            Pair(),
            lease,
            "run-1",
            [ObjectPlan("CreateObject", "s1")],
            signatures,
            CancellationToken.None);

        Assert.Equal("OBJECT_REPLICATED_AND_VERIFIED", Assert.Single(results).Status);
        Assert.Equal(2, lease.SaveCount);
        Assert.True(targetClient.IntentObservedBeforeWrite);
        Assert.Empty(lease.State.PendingObjectMutations);
        var baseline = Assert.Single(lease.State.ObjectBaselines).Value;
        Assert.Equal(ObjectSignatureService.DomainVersion, baseline.DomainVersion);
        Assert.Equal("s1", baseline.SourceVersion);
        Assert.Equal("t1", baseline.TargetVersion);
    }

    [Fact]
    public async Task Ambiguous_write_leaves_intent_and_is_not_retried()
    {
        var source = Snapshot("source://secrets/demo", "s1", "value");
        var targetClient = new FakeObjectClient("target://secrets")
        {
            WriteException = new TimeoutException("lost response"),
        };
        var lease = new FakeLease(NewState());
        targetClient.State = lease.State;
        var executor = new ObjectExecutor(
            new FakeObjectFactory(new FakeObjectClient("source://secrets", source), targetClient),
            NullLogger<ObjectExecutor>.Instance);
        using var signatures = LoadSignatures();

        var first = await executor.ApplyAsync(
            Pair(), lease, "run-1", [ObjectPlan("CreateObject", "s1")], signatures, CancellationToken.None);
        var second = await executor.ApplyAsync(
            Pair(), lease, "run-2", [ObjectPlan("CreateObject", "s1")], signatures, CancellationToken.None);

        Assert.Equal("AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", Assert.Single(first).Status);
        Assert.Equal("BLOCKED_UNRESOLVED_INTENT", Assert.Single(second).Status);
        Assert.Equal(1, targetClient.WriteCount);
        Assert.Single(lease.State.PendingObjectMutations);
    }

    [Fact]
    public async Task Reconcile_rejects_target_that_no_longer_matches_baseline()
    {
        var source = Snapshot("source://secrets/demo", "s2", "new");
        var target = Snapshot("target://secrets/demo", "t1", "changed-externally");
        using var signatures = LoadSignatures();
        var state = NewState();
        state.ObjectBaselines["Secret/demo"] = new ObjectBaseline
        {
            DomainVersion = ObjectSignatureService.DomainVersion,
            ObjectType = "Secret",
            ObjectId = "target://secrets/demo",
            SourceVersion = "s1",
            TargetVersion = "t1",
            SourceSignature = signatures.Compute(Snapshot("source://secrets/demo", "s1", "old").ToSignatureInput()),
            TargetSignature = signatures.Compute(Snapshot("target://secrets/demo", "t1", "old").ToSignatureInput()),
            HmacKeyVersion = signatures.KeyVersion,
            VerifiedAt = DateTimeOffset.UtcNow,
        };
        var targetClient = new FakeObjectClient("target://secrets", target);
        var executor = new ObjectExecutor(
            new FakeObjectFactory(new FakeObjectClient("source://secrets", source), targetClient),
            NullLogger<ObjectExecutor>.Instance);

        var results = await executor.ApplyAsync(
            Pair(), new FakeLease(state), "run-1", [ObjectPlan("ReconcileObject", "s2", "t1")],
            signatures, CancellationToken.None);

        Assert.Equal("CONFLICT_EXTERNALLY_MODIFIED", Assert.Single(results).Status);
        Assert.Equal(0, targetClient.WriteCount);
    }

    [Fact]
    public async Task Managed_target_is_soft_deleted_only_after_signature_verification()
    {
        var target = Snapshot("target://secrets/demo", "t1", "value");
        using var signatures = LoadSignatures();
        var state = NewState();
        state.ObjectBaselines["Secret/demo"] = new ObjectBaseline
        {
            DomainVersion = ObjectSignatureService.DomainVersion,
            ObjectType = "Secret",
            ObjectId = target.VersionlessObjectId,
            SourceVersion = "s1",
            TargetVersion = "t1",
            SourceSignature = "00".PadLeft(64, '0'),
            TargetSignature = signatures.Compute(target.ToSignatureInput()),
            HmacKeyVersion = signatures.KeyVersion,
            VerifiedAt = DateTimeOffset.UtcNow,
        };
        var targetClient = new FakeObjectClient("target://secrets", target) { State = state };
        var executor = new ObjectExecutor(
            new FakeObjectFactory(new FakeObjectClient("source://secrets"), targetClient),
            NullLogger<ObjectExecutor>.Instance);

        var results = await executor.ApplyAsync(
            Pair(), new FakeLease(state), "run-1",
            [ObjectPlan("DeleteObject", null, "t1")], signatures, CancellationToken.None);

        Assert.Equal("OBJECT_SOFT_DELETED_AND_VERIFIED", Assert.Single(results).Status);
        Assert.Equal(1, targetClient.DeleteCount);
        Assert.Empty(state.ObjectBaselines);
        Assert.Empty(state.PendingObjectMutations);
    }

    [Fact]
    public async Task Rbac_executor_never_deletes_runtime_identity_assignment()
    {
        var principal = Guid.NewGuid().ToString();
        var client = new FakeRbacClient();
        var executor = new RbacExecutor(client, principal, NullLogger<RbacExecutor>.Instance);
        var item = new PlanItem
        {
            ObjectType = "Authorization",
            Name = "assignment",
            Action = "DeleteRoleAssignment",
            Status = "READY_DELETE_ROLE_ASSIGNMENT",
            TargetScope = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/target",
            AssignmentId = Guid.NewGuid().ToString(),
            PrincipalId = principal,
            PrincipalType = "ServicePrincipal",
            RoleDefinitionId = "00482a5a-887f-4fb3-b363-3b7fe8e74483",
        };

        var result = Assert.Single(await executor.ApplyAsync([item], CancellationToken.None));

        Assert.Equal("RBAC_DELETE_SKIPPED_SYNC_IDENTITY", result.Status);
        Assert.Equal(0, client.DeleteCount);
    }

    [Fact]
    public void Planner_opens_delete_circuit_breaker_without_exact_approval()
    {
        var state = NewState();
        var targetSecrets = new List<SecretSummary>();
        for (var index = 0; index < ReplicationPlanner.BulkDeleteCountThreshold; index++)
        {
            var name = $"secret-{index:D2}";
            state.ObjectBaselines[$"Secret/{name}"] = Baseline(name);
            targetSecrets.Add(Secret(name, "t1"));
        }

        var plan = ReplicationPlanner.CreatePlan(
            Pair(),
            state,
            Inventory([], []),
            Inventory(targetSecrets, []),
            true,
            Guid.NewGuid().ToString(),
            DateTimeOffset.UtcNow);

        Assert.Equal(
            ReplicationPlanner.BulkDeleteCountThreshold,
            plan.Count(item => item.Status == "BLOCKED_DELETE_CIRCUIT_BREAKER"));
        Assert.DoesNotContain(plan, item => item.Action == "DeleteObject");
    }

    [Fact]
    public async Task Certificate_create_uses_the_same_intent_and_verification_boundary()
    {
        var source = Snapshot("source://certificates/demo", "s1", "pfx", "Certificate");
        var targetClient = new FakeObjectClient("target://certificates");
        var lease = new FakeLease(NewState());
        targetClient.State = lease.State;
        var executor = new ObjectExecutor(
            new FakeObjectFactory(new FakeObjectClient("source://certificates", source), targetClient),
            NullLogger<ObjectExecutor>.Instance);
        using var signatures = LoadSignatures();

        var result = Assert.Single(await executor.ApplyAsync(
            Pair(),
            lease,
            "run-1",
            [ObjectPlan("CreateObject", "s1", objectType: "Certificate")],
            signatures,
            CancellationToken.None));

        Assert.Equal("OBJECT_REPLICATED_AND_VERIFIED", result.Status);
        Assert.True(targetClient.IntentObservedBeforeWrite);
        Assert.Equal("Certificate", Assert.Single(lease.State.ObjectBaselines).Value.ObjectType);
    }

    [Fact]
    public void Signature_is_deterministic_and_binds_the_target_object_id()
    {
        using var signatures = LoadSignatures();
        var first = new ObjectSignatureInput
        {
            VersionlessObjectId = "https://target.vault.azure.net/secrets/demo",
            ObjectType = "Secret",
            Name = "demo",
            Material = Encoding.UTF8.GetBytes("value"),
            Enabled = true,
            Tags = new Dictionary<string, string> { ["b"] = "2", ["a"] = "1" },
        };
        var reordered = first with
        {
            Tags = new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" },
        };
        var differentTarget = first with
        {
            VersionlessObjectId = "https://other.vault.azure.net/secrets/demo",
        };

        Assert.Equal(signatures.Compute(first), signatures.Compute(reordered));
        Assert.NotEqual(signatures.Compute(first), signatures.Compute(differentTarget));
    }

    [Fact]
    public void Signature_service_rejects_non_256_bit_key_material()
    {
        var options = SignatureOptions() with
        {
            HmacKeyBase64 = Convert.ToBase64String(new byte[31]),
        };

        var exception = Assert.Throws<InvalidOperationException>(() => ObjectSignatureService.Load(options));

        Assert.Contains("exactly 32 bytes", exception.Message);
    }

    [Fact]
    public void Planner_blocks_object_writes_without_hmac_key()
    {
        var plan = ReplicationPlanner.CreatePlan(
            Pair(),
            NewState(),
            Inventory([Secret("demo", "s1")], []),
            Inventory([], []),
            false,
            Guid.NewGuid().ToString(),
            DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.ObjectType == "Secret" && item.Status == "BLOCKED_HMAC_KEY_NOT_CONFIGURED");
        Assert.DoesNotContain(plan, item => item.Action == "CreateObject");
    }

    [Fact]
    public void Planner_never_adopts_an_unmanaged_existing_target()
    {
        var plan = ReplicationPlanner.CreatePlan(
            Pair(),
            NewState(),
            Inventory([Secret("demo", "s1")], []),
            Inventory([Secret("demo", "t1")], []),
            true,
            Guid.NewGuid().ToString(),
            DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.ObjectType == "Secret" && item.Status == "CONFLICT_UNMANAGED_TARGET_EXISTS");
    }

    [Fact]
    public void Planner_reports_required_operator_action_for_non_exportable_material()
    {
        var certificate = new CertificateSummary
        {
            Name = "certificate",
            CurrentVersion = "c1",
            Versions = [new ObjectVersionSummary { Version = "c1" }],
            Exportable = false,
        };
        var key = new KeySummary
        {
            Name = "key",
            CurrentVersion = "k1",
            Versions = [new ObjectVersionSummary { Version = "k1" }],
        };
        var plan = ReplicationPlanner.CreatePlan(
            Pair(),
            NewState(),
            Inventory([], [certificate], [key]),
            Inventory([], []),
            true,
            Guid.NewGuid().ToString(),
            DateTimeOffset.UtcNow);

        Assert.Contains(plan, item =>
            item.ObjectType == "Certificate"
            && item.Status == "BLOCKED_CERTIFICATE_REISSUANCE_REQUIRED"
            && item.Detail!.Contains("Reissue", StringComparison.Ordinal));
        Assert.Contains(plan, item =>
            item.ObjectType == "Key"
            && item.Status == "BLOCKED_TARGET_KEY_PROVISIONING_REQUIRED"
            && item.Detail!.Contains("Provision", StringComparison.Ordinal));
    }

    [Fact]
    public void Key_scope_rbac_can_converge_after_a_target_key_is_independently_provisioned()
    {
        var pair = Pair();
        var sourceKey = new KeySummary
        {
            Name = "key",
            CurrentVersion = "source-version",
            Versions = [new ObjectVersionSummary { Version = "source-version" }],
        };
        var targetKey = new KeySummary
        {
            Name = "key",
            CurrentVersion = "target-version",
            Versions = [new ObjectVersionSummary { Version = "target-version" }],
        };
        var sourceAssignment = RoleAssignment(
            pair.Source.Id + "/keys/key",
            "principal",
            "12338af0-0e69-4776-bea7-57ae8d297424",
            "assignment");
        var plan = ReplicationPlanner.CreatePlan(
                pair,
                NewState(),
                Inventory([], [], [sourceKey], [sourceAssignment]),
                Inventory([], [], [targetKey]),
                true,
                Guid.NewGuid().ToString(),
                DateTimeOffset.UtcNow)
            .ToList();

        RunnerApplication.BlockDependentObjectRbac(plan, true);

        Assert.Contains(plan, item =>
            item.ObjectType == "Key"
            && item.Status == "BLOCKED_KEY_MATERIAL_EQUIVALENCE_UNVERIFIABLE");
        Assert.Contains(plan, item =>
            item.ObjectType == "Authorization"
            && item.Action == "CreateRoleAssignment"
            && item.Status == "READY_CREATE_ROLE_ASSIGNMENT");
    }

    [Fact]
    public void Key_scope_rbac_stays_blocked_until_the_target_key_exists()
    {
        var pair = Pair();
        var sourceKey = new KeySummary
        {
            Name = "key",
            CurrentVersion = "source-version",
            Versions = [new ObjectVersionSummary { Version = "source-version" }],
        };
        var sourceAssignment = RoleAssignment(
            pair.Source.Id + "/keys/key",
            "principal",
            "12338af0-0e69-4776-bea7-57ae8d297424",
            "assignment");
        var plan = ReplicationPlanner.CreatePlan(
                pair,
                NewState(),
                Inventory([], [], [sourceKey], [sourceAssignment]),
                Inventory([], []),
                true,
                Guid.NewGuid().ToString(),
                DateTimeOffset.UtcNow)
            .ToList();

        RunnerApplication.BlockDependentObjectRbac(plan, true);

        Assert.Contains(plan, item =>
            item.ObjectType == "Authorization"
            && item.Status == "BLOCKED_DEPENDENCY_FAILED");
    }

    [Fact]
    public void Planner_maps_and_deduplicates_allowed_object_scope_rbac()
    {
        var assignment = RoleAssignment(
            Pair().Source.Id + "/secrets/demo",
            "principal",
            "00482a5a-887f-4fb3-b363-3b7fe8e74483",
            "assignment");
        var plan = ReplicationPlanner.CreatePlan(
            Pair(),
            NewState(),
            Inventory([], [], roleAssignments: [assignment, assignment]),
            Inventory([], []),
            true,
            Guid.NewGuid().ToString(),
            DateTimeOffset.UtcNow);

        var create = Assert.Single(plan, item => item.Action == "CreateRoleAssignment");
        Assert.Equal(Pair().Target.Id + "/secrets/demo", create.TargetScope);
        Assert.Equal("READY_CREATE_ROLE_ASSIGNMENT", create.Status);
    }

    [Fact]
    public async Task Rbac_executor_creates_and_verifies_allowed_assignment()
    {
        var client = new FakeRbacClient();
        var executor = new RbacExecutor(client, "sync-principal", NullLogger<RbacExecutor>.Instance);
        var item = AuthorizationPlan("CreateRoleAssignment", "principal");

        var result = Assert.Single(await executor.ApplyAsync([item], CancellationToken.None));

        Assert.Equal("RBAC_ASSIGNMENT_CREATED_AND_VERIFIED", result.Status);
        Assert.Equal(1, client.PutCount);
    }

    [Fact]
    public async Task Rbac_executor_deletes_and_verifies_target_only_assignment()
    {
        var client = new FakeRbacClient();
        var item = AuthorizationPlan("DeleteRoleAssignment", "principal");
        client.Seed(item.TargetScope!, item.AssignmentId!);
        var executor = new RbacExecutor(client, "sync-principal", NullLogger<RbacExecutor>.Instance);

        var result = Assert.Single(await executor.ApplyAsync([item], CancellationToken.None));

        Assert.Equal("RBAC_ASSIGNMENT_DELETED_AND_VERIFIED", result.Status);
        Assert.Equal(1, client.DeleteCount);
    }

    [Fact]
    public async Task Rbac_executor_blocks_role_outside_allowlist()
    {
        var client = new FakeRbacClient();
        var executor = new RbacExecutor(client, "sync-principal", NullLogger<RbacExecutor>.Instance);
        var item = AuthorizationPlan("CreateRoleAssignment", "principal") with
        {
            RoleDefinitionId = Guid.NewGuid().ToString(),
        };

        var result = Assert.Single(await executor.ApplyAsync([item], CancellationToken.None));

        Assert.Equal("RBAC_ACTION_BLOCKED_ROLE_NOT_ALLOWED", result.Status);
        Assert.Equal(0, client.PutCount);
    }

    private static ObjectBaseline Baseline(string name) => new()
    {
        DomainVersion = ObjectSignatureService.DomainVersion,
        ObjectType = "Secret",
        ObjectId = $"target://secrets/{name}",
        SourceVersion = "s1",
        TargetVersion = "t1",
        SourceSignature = new string('A', 64),
        TargetSignature = new string('B', 64),
        HmacKeyVersion = "test-v1",
        VerifiedAt = DateTimeOffset.UtcNow,
    };

    private static PlanItem ObjectPlan(
        string action,
        string? sourceVersion,
        string? targetVersion = null,
        string objectType = "Secret") => new()
    {
        ObjectType = objectType,
        Name = "demo",
        Action = action,
        Status = "READY",
        SourceVersion = sourceVersion,
        TargetVersion = targetVersion,
    };

    private static ReplicatedObject Snapshot(
        string id,
        string version,
        string value,
        string objectType = "Secret") => new()
    {
        ObjectType = objectType,
        Name = "demo",
        Version = version,
        VersionlessObjectId = id,
        Payload = Encoding.UTF8.GetBytes(value),
        SignatureMaterial = Encoding.UTF8.GetBytes(value),
        Enabled = true,
    };

    private static RunnerOptions SignatureOptions() => new()
    {
        SubscriptionIds = [Guid.NewGuid().ToString()],
        StorageAccountUri = new Uri("https://state.blob.core.windows.net"),
        HmacKeyBase64 = Convert.ToBase64String(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray()),
        HmacKeyVersion = "test-v1",
    };

    private static ObjectSignatureService LoadSignatures() =>
        ObjectSignatureService.Load(SignatureOptions())!;

    private static PlanItem AuthorizationPlan(string action, string principalId) => new()
    {
        ObjectType = "Authorization",
        Name = principalId,
        Action = action,
        Status = "READY",
        TargetScope = Pair().Target.Id,
        AssignmentId = Guid.NewGuid().ToString(),
        PrincipalId = principalId,
        PrincipalType = "ServicePrincipal",
        RoleDefinitionId = "00482a5a-887f-4fb3-b363-3b7fe8e74483",
    };

    private static RoleAssignmentSummary RoleAssignment(
        string scope,
        string principalId,
        string roleDefinitionId,
        string assignmentId) => new()
    {
        Id = scope + "/providers/Microsoft.Authorization/roleAssignments/" + assignmentId,
        Scope = scope,
        PrincipalId = principalId,
        PrincipalType = "ServicePrincipal",
        RoleDefinitionId = roleDefinitionId,
    };

    private static VaultPair Pair() => new(
        Vault("source", "11111111-1111-1111-1111-111111111111"),
        Vault("target", "22222222-2222-2222-2222-222222222222"));

    private static VaultResource Vault(string name, string subscription) => new()
    {
        Id = $"/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}",
        Name = name,
        Location = "eastus",
        ResourceGroup = "rg",
        TenantId = "33333333-3333-3333-3333-333333333333",
        UsesRbacAuthorization = true,
        Tags = [],
    };

    private static PairState NewState() => new()
    {
        PairId = Pair().PairId,
        SourceVaultId = Pair().Source.Id,
        TargetVaultId = Pair().Target.Id,
    };

    private static SecretSummary Secret(string name, string version) => new()
    {
        Name = name,
        CurrentVersion = version,
        Versions = [new ObjectVersionSummary { Version = version }],
    };

    private static VaultInventory Inventory(
        IReadOnlyList<SecretSummary> secrets,
        IReadOnlyList<CertificateSummary> certificates,
        IReadOnlyList<KeySummary>? keys = null,
        IReadOnlyList<RoleAssignmentSummary>? roleAssignments = null) => new()
        {
            VaultId = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault",
            VaultName = "vault",
            Region = "eastus",
            Authorization = new VaultAuthorizationSummary
            {
                UsesRbac = true,
                AccessPolicies = [],
                RoleAssignments = roleAssignments ?? [],
                Warnings = [],
            },
            Secrets = secrets,
            Keys = keys ?? [],
            Certificates = certificates,
            DeletedSecretNames = [],
            DeletedKeyNames = [],
            DeletedCertificateNames = [],
            Warnings = [],
        };

    private sealed class FakeObjectFactory(
        IObjectReplicationVaultClient source,
        IObjectReplicationVaultClient target) : IObjectReplicationVaultClientFactory
    {
        public IObjectReplicationVaultClient Create(VaultResource vault, bool isTarget) => isTarget ? target : source;
    }

    private sealed class FakeObjectClient(
        string idPrefix,
        ReplicatedObject? current = null) : IObjectReplicationVaultClient
    {
        public Exception? WriteException { get; init; }
        public PairState? State { get; set; }
        public int WriteCount { get; private set; }
        public int DeleteCount { get; private set; }
        public bool IntentObservedBeforeWrite { get; private set; }

        public string GetVersionlessObjectId(string objectType, string name) => $"{idPrefix.TrimEnd('/')}/{name}";

        public Task<ReplicatedObject?> ReadAsync(
            string objectType,
            string name,
            string? version,
            CancellationToken cancellationToken)
        {
            if (current is null || (version is not null && current.Version != version))
            {
                return Task.FromResult<ReplicatedObject?>(null);
            }

            return Task.FromResult<ReplicatedObject?>(current);
        }

        public Task<ReplicatedObject> WriteAsync(ReplicatedObject source, CancellationToken cancellationToken)
        {
            WriteCount++;
            IntentObservedBeforeWrite = State?.PendingObjectMutations.Count > 0;
            if (WriteException is not null)
            {
                throw WriteException;
            }

            current = source with
            {
                Version = "t1",
                VersionlessObjectId = GetVersionlessObjectId(source.ObjectType, source.Name),
            };
            return Task.FromResult(current);
        }

        public Task DeleteAsync(string objectType, string name, CancellationToken cancellationToken)
        {
            DeleteCount++;
            current = null;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeLease(PairState state) : IPairStateLease
    {
        public PairState State { get; } = state;
        public int SaveCount { get; private set; }
        public void EnsureLeaseHeld() { }
        public Task SaveStateAsync(CancellationToken cancellationToken)
        {
            SaveCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeRbacClient : IArmRbacClient
    {
        private readonly HashSet<string> _assignments = new(StringComparer.OrdinalIgnoreCase);

        public int PutCount { get; private set; }
        public int DeleteCount { get; private set; }
        public void Seed(string targetScope, string assignmentId) => _assignments.Add(Key(targetScope, assignmentId));
        public Task PutAsync(RbacMutation mutation, CancellationToken cancellationToken)
        {
            PutCount++;
            _assignments.Add(Key(mutation.TargetScope, mutation.AssignmentId));
            return Task.CompletedTask;
        }
        public Task DeleteAsync(string targetScope, string assignmentId, CancellationToken cancellationToken)
        {
            DeleteCount++;
            _assignments.Remove(Key(targetScope, assignmentId));
            return Task.CompletedTask;
        }
        public Task<bool> ExistsAsync(string targetScope, string assignmentId, CancellationToken cancellationToken) =>
            Task.FromResult(_assignments.Contains(Key(targetScope, assignmentId)));

        private static string Key(string targetScope, string assignmentId) =>
            $"{targetScope.TrimEnd('/')}|{assignmentId}";
    }
}
