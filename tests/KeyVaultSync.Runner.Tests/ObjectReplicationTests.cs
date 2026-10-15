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
            [ObjectPlan("CreateObject", null)],
            signatures,
            CancellationToken.None);

        var result = Assert.Single(results);
        Assert.Equal("OBJECT_REPLICATED_AND_VERIFIED", result.Status);
        Assert.Equal("s1", result.SourceVersion);
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
            targetSecrets.Add(Secret(name));
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
            Inventory([Secret("demo")], []),
            Inventory([], []),
            false,
            Guid.NewGuid().ToString(),
            DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.ObjectType == "Secret" && item.Status == "BLOCKED_HMAC_KEY_NOT_CONFIGURED");
        Assert.DoesNotContain(plan, item => item.Action == "CreateObject");
    }

    [Fact]
    public void Planner_blocks_only_the_object_named_by_an_object_scoped_warning()
    {
        const string message = "Certificate metadata/backing references could not be read for ambiguous: HTTP 403.";
        var source = Inventory([Secret("ambiguous"), Secret("healthy")], []) with
        {
            Warnings = [message],
            ObjectWarnings = [new ObjectInventoryWarning("ambiguous", message)],
        };

        var plan = ReplicationPlanner.CreatePlan(
            Pair(), NewState(), source, Inventory([], []), true, Guid.NewGuid().ToString(), DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.Name == "ambiguous" && item.Status == "BLOCKED_INCOMPLETE_INVENTORY");
        Assert.Contains(plan, item => item.Name == "healthy" && item.Action == "CreateObject");
    }

    [Fact]
    public void Planner_blocks_deletion_of_a_target_object_with_an_object_scoped_warning()
    {
        const string message = "Certificate metadata/backing references could not be read for managed: HTTP 403.";
        var state = NewState();
        state.ObjectBaselines["Secret/managed"] = Baseline("managed");
        var target = Inventory([Secret("managed")], []) with
        {
            Warnings = [message],
            ObjectWarnings = [new ObjectInventoryWarning("managed", message)],
        };

        var plan = ReplicationPlanner.CreatePlan(
            Pair(), state, Inventory([], []), target, true, Guid.NewGuid().ToString(), DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.Name == "managed" && item.Status == "BLOCKED_INCOMPLETE_INVENTORY");
        Assert.DoesNotContain(plan, item => item.Action == "DeleteObject");
    }

    [Fact]
    public void Planner_blocks_all_objects_for_a_vault_level_warning()
    {
        var target = Inventory([], []) with { Warnings = ["Deleted-secret inventory is incomplete: HTTP 403."] };

        var plan = ReplicationPlanner.CreatePlan(
            Pair(), NewState(), Inventory([Secret("healthy")], []), target, true,
            Guid.NewGuid().ToString(), DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.Name == "healthy" && item.Status == "BLOCKED_INCOMPLETE_INVENTORY");
        Assert.DoesNotContain(plan, item => item.Action == "CreateObject");
    }

    [Fact]
    public void Planner_keeps_object_sync_when_only_authorization_inventory_is_incomplete()
    {
        const string message = "Object role-assignment inventory is incomplete: RequestFailedException.";
        var source = Inventory([Secret("healthy")], []);
        source = source with
        {
            Warnings = [message],
            Authorization = source.Authorization with { Warnings = [message] },
        };

        var plan = ReplicationPlanner.CreatePlan(
            Pair(), NewState(), source, Inventory([], []), true, Guid.NewGuid().ToString(), DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.Name == "healthy" && item.Action == "CreateObject");
        Assert.Contains(plan, item => item.Status == "BLOCKED_AUTHORIZATION_INVENTORY_INCOMPLETE");
    }

    [Fact]
    public void Planner_reports_unreadable_certificate_metadata_as_incomplete_inventory_not_reissuance()
    {
        const string message = "Certificate metadata/backing references could not be read for cert: HTTP 403.";
        var source = Inventory([], [new CertificateSummary { Name = "cert", CurrentVersion = "c1", Exportable = null }]) with
        {
            Warnings = [message],
            ObjectWarnings = [new ObjectInventoryWarning("cert", message)],
        };

        var plan = ReplicationPlanner.CreatePlan(
            Pair(), NewState(), source, Inventory([], []), true, Guid.NewGuid().ToString(), DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.Name == "cert" && item.Status == "BLOCKED_INCOMPLETE_INVENTORY");
        Assert.DoesNotContain(plan, item => item.Status == "BLOCKED_CERTIFICATE_REISSUANCE_REQUIRED");
    }

    [Fact]
    public void Planner_does_not_report_a_target_only_certificate_backing_secret_as_a_separate_secret()
    {
        var target = Inventory(
            [Secret("target-cert"), Secret("plain-collision")],
            [
                new CertificateSummary { Name = "target-cert", CurrentVersion = "c1", Exportable = true },
                new CertificateSummary { Name = "plain-collision", CurrentVersion = "c2", Exportable = true },
            ]);

        var plan = ReplicationPlanner.CreatePlan(
            Pair(), NewState(), Inventory([Secret("plain-collision")], []), target, true,
            Guid.NewGuid().ToString(), DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.ObjectType == "Certificate" && item.Name == "target-cert"
            && item.Status == "CONFLICT_UNMANAGED_TARGET_ONLY");
        Assert.DoesNotContain(plan, item => item.ObjectType == "Secret" && item.Name == "target-cert");
        // A plain source secret colliding with a target certificate stays visible as a secret conflict.
        Assert.Contains(plan, item => item.ObjectType == "Secret" && item.Name == "plain-collision");
    }

    [Fact]
    public async Task Executor_skips_only_the_object_whose_pre_mutation_read_fails()
    {
        var source = Snapshot("source://secrets/demo", "s1", "value");
        var sourceClient = new FakeObjectClient("source://secrets", source)
        {
            ReadFailureName = "disabled",
        };
        var targetClient = new FakeObjectClient("target://secrets");
        var lease = new FakeLease(NewState());
        targetClient.State = lease.State;
        var executor = new ObjectExecutor(new FakeObjectFactory(sourceClient, targetClient), NullLogger<ObjectExecutor>.Instance);
        using var signatures = LoadSignatures();

        var results = await executor.ApplyAsync(
            Pair(), lease, "run-1",
            [ObjectPlan("CreateObject", null) with { Name = "disabled" }, ObjectPlan("CreateObject", null)],
            signatures, CancellationToken.None);

        Assert.Equal("READ_FAILED_BEFORE_MUTATION", results[0].Status);
        Assert.Contains("HTTP 403", results[0].Detail);
        Assert.Equal("OBJECT_REPLICATED_AND_VERIFIED", results[1].Status);
        Assert.Equal(1, targetClient.WriteCount);
        Assert.Empty(lease.State.PendingObjectMutations);
    }

    [Fact]
    public async Task Executor_skips_only_the_object_whose_certificate_payload_is_invalid()
    {
        var targetClient = new FakeObjectClient("target://secrets");
        var lease = new FakeLease(NewState());
        var sourceClient = new FakeObjectClient("source://secrets", Snapshot("source://secrets/demo", "s1", "value"))
        {
            ReadFailureName = "broken",
            ReadFailure = new InvalidDataException("Certificate DER encoding is missing."),
        };
        var executor = new ObjectExecutor(new FakeObjectFactory(sourceClient, targetClient), NullLogger<ObjectExecutor>.Instance);
        using var signatures = LoadSignatures();

        var results = await executor.ApplyAsync(
            Pair(), lease, "run-1",
            [ObjectPlan("CreateObject", null) with { Name = "broken" }, ObjectPlan("CreateObject", null)],
            signatures, CancellationToken.None);

        Assert.Equal("READ_FAILED_BEFORE_MUTATION", results[0].Status);
        Assert.Equal("OBJECT_REPLICATED_AND_VERIFIED", results[1].Status);
        Assert.Empty(lease.State.PendingObjectMutations);
    }

    [Fact]
    public async Task Executor_reads_the_current_source_version_instead_of_the_planned_one()
    {
        var source = Snapshot("source://secrets/demo", "s2", "rotated");
        var targetClient = new FakeObjectClient("target://secrets");
        var lease = new FakeLease(NewState());
        var executor = new ObjectExecutor(
            new FakeObjectFactory(new FakeObjectClient("source://secrets", source), targetClient),
            NullLogger<ObjectExecutor>.Instance);
        using var signatures = LoadSignatures();

        var result = Assert.Single(await executor.ApplyAsync(
            Pair(), lease, "run-1", [ObjectPlan("CreateObject", "s1")], signatures, CancellationToken.None));

        Assert.Equal("OBJECT_REPLICATED_AND_VERIFIED", result.Status);
        Assert.Equal("s2", Assert.Single(lease.State.ObjectBaselines).Value.SourceVersion);
    }

    [Fact]
    public async Task Executor_reports_a_source_that_disappeared_after_planning()
    {
        var targetClient = new FakeObjectClient("target://secrets");
        var executor = new ObjectExecutor(
            new FakeObjectFactory(new FakeObjectClient("source://secrets"), targetClient),
            NullLogger<ObjectExecutor>.Instance);
        using var signatures = LoadSignatures();

        var result = Assert.Single(await executor.ApplyAsync(
            Pair(), new FakeLease(NewState()), "run-1", [ObjectPlan("CreateObject", null)], signatures, CancellationToken.None));

        Assert.Equal("STALE_PLAN_SOURCE_VERSION_UNAVAILABLE", result.Status);
        Assert.Equal(0, targetClient.WriteCount);
    }

    [Fact]
    public void Planner_blocks_a_source_whose_current_version_is_disabled()
    {
        var plan = ReplicationPlanner.CreatePlan(
            Pair(), NewState(), Inventory([Secret("disabled", enabled: false), Secret("healthy")], []), Inventory([], []),
            true, Guid.NewGuid().ToString(), DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.Name == "disabled" && item.Status == "BLOCKED_SOURCE_VERSION_DISABLED");
        Assert.Contains(plan, item => item.Name == "healthy" && item.Action == "CreateObject");
        Assert.DoesNotContain(plan, item => item.Name == "disabled" && item.Action != "None");
    }

    [Fact]
    public void Planner_treats_a_disabled_managed_target_as_externally_modified()
    {
        var state = NewState();
        state.ObjectBaselines["Secret/demo"] = Baseline("demo");

        var plan = ReplicationPlanner.CreatePlan(
            Pair(), state, Inventory([Secret("demo")], []), Inventory([Secret("demo", enabled: false)], []),
            true, Guid.NewGuid().ToString(), DateTimeOffset.UtcNow);

        Assert.Contains(plan, item => item.Name == "demo" && item.Status == "CONFLICT_EXTERNALLY_MODIFIED");
        Assert.DoesNotContain(plan, item => item.Action == "ReconcileObject");
    }

    [Fact]
    public void Planner_never_adopts_an_unmanaged_existing_target()
    {
        var plan = ReplicationPlanner.CreatePlan(
            Pair(),
            NewState(),
            Inventory([Secret("demo")], []),
            Inventory([Secret("demo")], []),
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
            Exportable = false,
        };
        var key = new KeySummary
        {
            Name = "key",
            CurrentVersion = "k1",
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
        };
        var targetKey = new KeySummary
        {
            Name = "key",
            CurrentVersion = "target-version",
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

    private static SecretSummary Secret(string name, bool? enabled = true) => new()
    {
        Name = name,
        Enabled = enabled,
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
        public string? ReadFailureName { get; init; }
        public Exception? ReadFailure { get; init; }
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
            if (name == ReadFailureName)
            {
                throw ReadFailure ?? new global::Azure.RequestFailedException(403, "Operation get is not allowed on a disabled secret.");
            }

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
