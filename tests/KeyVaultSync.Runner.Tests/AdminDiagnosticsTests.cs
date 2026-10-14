using KeyVaultSync.Runner;
using Microsoft.Extensions.Logging;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class AdminDiagnosticsTests
{
    public static TheoryData<string, string> KnownPlanStatuses => new()
    {
        { "INVENTORY_WARNING", "KVS-INV-PARTIAL" },
        { "BLOCKED_INCOMPLETE_INVENTORY", "KVS-PLAN-INCOMPLETE-INVENTORY" },
        { "BLOCKED_HMAC_KEY_NOT_CONFIGURED", "KVS-PLAN-HMAC-MISSING" },
        { "BLOCKED_UNRESOLVED_INTENT", "KVS-PLAN-UNRESOLVED-INTENT" },
        { "BLOCKED_SOFT_DELETED_TARGET", "KVS-PLAN-SOFT-DELETED-NAME" },
        { "BLOCKED_CERTIFICATE_REISSUANCE_REQUIRED", "KVS-PLAN-CERTIFICATE-NONEXPORTABLE" },
        { "BLOCKED_TARGET_KEY_PROVISIONING_REQUIRED", "KVS-PLAN-KEY-PROVISIONING" },
        { "BLOCKED_KEY_MATERIAL_EQUIVALENCE_UNVERIFIABLE", "KVS-PLAN-KEY-EQUIVALENCE" },
        { "BLOCKED_DELETE_CIRCUIT_BREAKER", "KVS-PLAN-DELETE-CIRCUIT" },
        { "BLOCKED_INCOMPATIBLE_BASELINE", "KVS-PLAN-INCOMPATIBLE-BASELINE" },
        { "BLOCKED_AUTHORIZATION_INVENTORY_INCOMPLETE", "KVS-PLAN-AUTH-INVENTORY" },
        { "BLOCKED_SYNC_IDENTITY_UNKNOWN", "KVS-RBAC-SYNC-IDENTITY-MISSING" },
        { "RBAC_DELETE_BLOCKED_SYNC_IDENTITY_UNKNOWN", "KVS-RBAC-SYNC-IDENTITY-MISSING" },
        { "BLOCKED_DEPENDENCY_FAILED", "KVS-PLAN-DEPENDENCY-FAILED" },
        { "CONFLICT_UNMANAGED_TARGET_EXISTS", "KVS-PLAN-UNMANAGED-TARGET" },
        { "CONFLICT_UNMANAGED_TARGET_ONLY", "KVS-PLAN-UNMANAGED-TARGET-ONLY" },
        { "CONFLICT_MANAGED_TARGET_MISSING", "KVS-PLAN-MANAGED-TARGET-MISSING" },
        { "CONFLICT_TARGET_APPEARED", "KVS-OBJECT-TARGET-APPEARED" },
        { "CONFLICT_EXTERNALLY_MODIFIED", "KVS-PLAN-EXTERNAL-MODIFICATION" },
        { "STALE_PLAN_SOURCE_VERSION_UNAVAILABLE", "KVS-OBJECT-STALE-SOURCE" },
        { "WRITE_FAILED_DEFINITIVELY", "KVS-OBJECT-WRITE-DEFINITIVE" },
        { "DELETE_FAILED_DEFINITIVELY", "KVS-OBJECT-DELETE-DEFINITIVE" },
        { "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", "KVS-OBJECT-AMBIGUOUS" },
        { "ROLE_DEFINITION_NOT_AVAILABLE", "KVS-RBAC-ROLE-DEFINITION" },
        { "RBAC_ACTION_FAILED", "KVS-RBAC-FAILED" },
        { "RBAC_ACTION_FAILED_VERIFICATION", "KVS-RBAC-VERIFY" },
        { "RBAC_ACTION_FAILED_INVALID_PLAN", "KVS-RBAC-INVALID-PLAN" },
        { "RBAC_ACTION_BLOCKED_ROLE_NOT_ALLOWED", "KVS-RBAC-ROLE-NOT-ALLOWED" },
        { "RBAC_DELETE_SKIPPED_SYNC_IDENTITY", "KVS-RBAC-SELF-PROTECTION" },
        { "SKIPPED_SYNC_IDENTITY_SELF_ASSIGNMENT", "KVS-RBAC-SELF-PROTECTION" },
        { "READY_CREATE_IF_TARGET_STAYS_EMPTY", "KVS-PLAN-READY-CREATE" },
        { "VERIFY_SIGNATURES_THEN_RECONCILE", "KVS-PLAN-READY-RECONCILE" },
        { "VERIFY_SIGNATURE_THEN_SOFT_DELETE", "KVS-PLAN-READY-DELETE" },
        { "READY_CREATE_ROLE_ASSIGNMENT", "KVS-RBAC-READY-CREATE" },
        { "READY_DELETE_ROLE_ASSIGNMENT", "KVS-RBAC-READY-DELETE" },
        { "IN_SYNC_SIGNATURE_VERIFIED", "KVS-OBJECT-IN-SYNC" },
        { "OBJECT_REPLICATED_AND_VERIFIED", "KVS-OBJECT-REPLICATED" },
        { "OBJECT_SOFT_DELETED_AND_VERIFIED", "KVS-OBJECT-DELETED" },
        { "RBAC_ASSIGNMENT_IN_SYNC", "KVS-RBAC-IN-SYNC" },
        { "RBAC_ASSIGNMENT_CREATED_AND_VERIFIED", "KVS-RBAC-CREATED" },
        { "RBAC_ASSIGNMENT_DELETED_AND_VERIFIED", "KVS-RBAC-DELETED" },
        { "RBAC_CREATED_AND_VERIFIED", "KVS-RBAC-CREATED" },
        { "RBAC_DELETED_AND_VERIFIED", "KVS-RBAC-DELETED" },
        { "RBAC_ALREADY_ABSENT", "KVS-RBAC-ALREADY-ABSENT" },
        { "RBAC_ASSIGNMENT_INTENT_MATCH", "KVS-RBAC-INTENT-MATCH" },
        { "ACCESS_POLICY_INTENT_MATCH", "KVS-ACCESS-POLICY-INTENT-MATCH" },
    };

    [Theory]
    [InlineData("Secret head version could not be determined for example.", "KVS-INV-SECRET-HEAD")]
    [InlineData("Certificate metadata/backing references could not be read for example: HTTP 403.", "KVS-INV-CERTIFICATE-METADATA")]
    [InlineData("Deleted-secret inventory is incomplete: HTTP 403.", "KVS-INV-DELETED-SECRETS")]
    [InlineData("Object role-assignment inventory is incomplete: RequestFailedException.", "KVS-INV-OBJECT-RBAC")]
    [InlineData("Role-assignment inventory is incomplete at /redacted: forbidden.", "KVS-INV-VAULT-RBAC")]
    [InlineData("A future warning category.", "KVS-INV-UNKNOWN")]
    public void ClassifyInventoryWarning_ReturnsStableCode(string warning, string expectedCode)
    {
        var diagnostic = AdminDiagnostics.ClassifyInventoryWarning(warning);

        Assert.Equal(expectedCode, diagnostic.Code);
        Assert.NotEmpty(diagnostic.AdminAction);
        Assert.DoesNotContain("example", diagnostic.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("example", diagnostic.AdminAction, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ClassifyRbacFailure_Forbidden_ReturnsPermissionGuidance()
    {
        var diagnostic = AdminDiagnostics.ClassifyRbacFailure(403, "AuthorizationFailed");

        Assert.Equal("KVS-RBAC-403", diagnostic.Code);
        Assert.Contains("Key Vault Data Access Administrator", diagnostic.AdminAction, StringComparison.Ordinal);
        Assert.Contains("deny assignments", diagnostic.AdminAction, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("/subscriptions/redacted/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault", "Vault")]
    [InlineData("/subscriptions/redacted/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault/secrets/name", "Secret")]
    [InlineData("/subscriptions/redacted/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault/keys/name", "Key")]
    public void GetAuthorizationScopeKind_ReturnsBoundedCategory(string scope, string expectedKind)
    {
        Assert.Equal(expectedKind, AdminDiagnostics.GetAuthorizationScopeKind(scope));
    }

    [Theory]
    [MemberData(nameof(KnownPlanStatuses))]
    public void ClassifyPlanStatus_ReturnsStableCode(string status, string expectedCode)
    {
        Assert.Equal(expectedCode, AdminDiagnostics.ClassifyPlanStatus(status).Code);
        Assert.NotEmpty(AdminDiagnostics.ClassifyPlanStatus(status).AdminAction);
    }

    [Theory]
    [InlineData("Enabled", "KVS-DISCOVERY-ENABLED")]
    [InlineData("InvalidSourceId", "KVS-DISCOVERY-INVALID-SOURCE-ID")]
    [InlineData("ChainedOrCyclicMapping", "KVS-DISCOVERY-CHAIN")]
    [InlineData("UnsupportedAuthorizationModel", "KVS-DISCOVERY-AUTH-MODEL")]
    public void ClassifyDiscoveryDecision_ReturnsStableCode(string decision, string expectedCode)
    {
        Assert.Equal(expectedCode, AdminDiagnostics.ClassifyDiscoveryDecision(decision).Code);
    }

    [Fact]
    public void HasUnappliedWork_AcceptsCurrentVerifiedRbacStatusNames()
    {
        var plan = new[]
        {
            PlanItem("RBAC_ASSIGNMENT_CREATED_AND_VERIFIED"),
            PlanItem("RBAC_ASSIGNMENT_DELETED_AND_VERIFIED"),
            PlanItem("RBAC_DELETE_SKIPPED_SYNC_IDENTITY"),
        };

        Assert.False(RunnerApplication.HasUnappliedWork(plan));
    }

    [Theory]
    [InlineData("KVS-RBAC-403", "Critical")]
    [InlineData("KVS-OBJECT-AMBIGUOUS", "Critical")]
    [InlineData("KVS-INV-SECRET-HEAD", "High")]
    [InlineData("KVS-PLAN-KEY-PROVISIONING", "Medium")]
    [InlineData("KVS-OBJECT-IN-SYNC", "None")]
    public void GetPriority_ReturnsBoundedOperatorPriority(string code, string expectedPriority)
    {
        Assert.Equal(expectedPriority, AdminDiagnostics.GetPriority(code));
    }

    [Fact]
    public void LogLifecycle_EmitsMachineReadableDecisionFields()
    {
        var logger = new RecordingLogger();

        AdminDiagnostics.LogLifecycle(logger, "Planning", "CompletedWithBlockedItems", "ReviewRequired");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(AdminDiagnostics.LifecycleEventId, entry.EventId);
        Assert.Equal("KVS-LIFECYCLE", entry.Properties["DiagnosticCode"]);
        Assert.Equal("Planning", entry.Properties["DiagnosticStage"]);
        Assert.Equal("CompletedWithBlockedItems", entry.Properties["DiagnosticOutcome"]);
        Assert.Equal("Evidence", entry.Properties["EvidenceType"]);
        Assert.Equal("ReviewRequired", entry.Properties["ActionDecision"]);
        Assert.Equal("High", entry.Properties["Confidence"]);
    }

    [Fact]
    public void LogPlanOutcomeGroups_EmitsBoundedDecisionSummary()
    {
        var logger = new RecordingLogger();

        AdminDiagnostics.LogPlanOutcomeGroups(
            logger,
            [PlanItem("BLOCKED_UNRESOLVED_INTENT") with { ObjectType = "Secret", Action = "ReconcileObject" }],
            "Execution");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal("KVS-PLAN-UNRESOLVED-INTENT", entry.Properties["DiagnosticCode"]);
        Assert.Equal("Execution", entry.Properties["DiagnosticStage"]);
        Assert.Equal("BLOCKED_UNRESOLVED_INTENT", entry.Properties["DiagnosticOutcome"]);
        Assert.Equal("Critical", entry.Properties["AdminPriority"]);
        Assert.Equal("Evidence", entry.Properties["EvidenceType"]);
        Assert.Equal("AdminReviewRequired", entry.Properties["ActionDecision"]);
        Assert.Equal("High", entry.Properties["Confidence"]);
    }

    [Fact]
    public void AnalyzerCatalog_ContainsEveryKnownRuntimeDiagnosticCode()
    {
        var analyzerPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",
            "tools", "keyvaultsync-log-analyzer.html"));
        var analyzer = File.ReadAllText(analyzerPath);
        var expectedCodes = KnownPlanStatuses
            .Select(row => (string)row[1])
            .Concat(new[]
            {
                "KVS-INV-SECRET-HEAD", "KVS-INV-CERTIFICATE-METADATA", "KVS-INV-DELETED-SECRETS",
                "KVS-INV-OBJECT-RBAC", "KVS-INV-VAULT-RBAC", "KVS-INV-UNKNOWN",
                "KVS-DISCOVERY-ENABLED", "KVS-DISCOVERY-SOURCE-DISABLED", "KVS-DISCOVERY-TARGET-DISABLED",
                "KVS-DISCOVERY-INVALID-SOURCE-ID", "KVS-DISCOVERY-TARGET-UNREADABLE",
                "KVS-DISCOVERY-SOURCE-UNREADABLE", "KVS-DISCOVERY-SELF-MAPPING", "KVS-DISCOVERY-CHAIN",
                "KVS-DISCOVERY-TENANT", "KVS-DISCOVERY-AUTH-MODEL", "KVS-DISCOVERY-UNKNOWN",
                "KVS-PAIR-COMPLETE", "KVS-PAIR-UNAPPLIED", "KVS-PAIR-PARTIAL-INVENTORY", "KVS-PAIR-LOCKED",
                "KVS-PAIR-PLANNING-BARRIER", "KVS-PAIR-CANCELLED", "KVS-PAIR-FAILED", "KVS-PAIR-INCOMPLETE", "KVS-PAIR-UNKNOWN",
                "KVS-RUN-COMPLETE", "KVS-RUN-NO-PAIRS", "KVS-RUN-PARTIAL", "KVS-RUN-CANCELLED",
                "KVS-RUN-FAILED", "KVS-RUN-INCOMPLETE", "KVS-RUN-UNKNOWN", "KVS-CONFIG-HMAC-INVALID", "KVS-STORAGE-INITIALIZE",
                "KVS-CONFIG-SUBSCRIPTIONS", "KVS-CONFIG-STORAGE-URI", "KVS-CONFIG-PRINCIPAL",
                "KVS-CONFIG-RETIRED", "KVS-CONFIG-COMMAND-LINE", "KVS-CONFIG-LOG-LEVEL",
                "KVS-STORAGE-RUN-RECORD", "KVS-STORAGE-PAIR-STATE", "KVS-STORAGE-LEASE-RENEW",
                "KVS-STORAGE-LEASE-RELEASE", "KVS-PAIR-SCAN-FAILED", "KVS-PAIR-EXECUTION-FAILED",
                "KVS-RUN-ORCHESTRATION-FAILED", "KVS-SYSTEM-FAILURE", "KVS-RBAC-403", "KVS-RBAC-429",
                "KVS-LIFECYCLE",
            })
            .Distinct(StringComparer.Ordinal);

        foreach (var diagnosticCode in expectedCodes)
        {
            Assert.Contains($"\"{diagnosticCode}\"", analyzer, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Analyzer_ContainsPrioritizationAndSanitizedExportContracts()
    {
        var analyzerPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",
            "tools", "keyvaultsync-log-analyzer.html"));
        var analyzer = File.ReadAllText(analyzerPath);

        Assert.Contains("function priorityForFinding(", analyzer, StringComparison.Ordinal);
        Assert.Contains("function deriveAssessment(", analyzer, StringComparison.Ordinal);
        Assert.Contains("function codeForPersistedFailure(", analyzer, StringComparison.Ordinal);
        Assert.Contains("function createSanitizedSummary(", analyzer, StringComparison.Ordinal);
        Assert.Contains("function downloadHtmlSummary(", analyzer, StringComparison.Ordinal);
        Assert.Contains("Inference · Recommended action", analyzer, StringComparison.Ordinal);
        Assert.Contains("sourceFile: \"[redacted]\"", analyzer, StringComparison.Ordinal);
        Assert.DoesNotContain("sourceFile: state.name", analyzer, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyzer_ReportsRedactableRunRecordAndOperationLocators()
    {
        var analyzerPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",
            "tools", "keyvaultsync-log-analyzer.html"));
        var analyzer = File.ReadAllText(analyzerPath);

        Assert.Contains("function runRecordFromTelemetry(", analyzer, StringComparison.Ordinal);
        Assert.Contains("function runRecordBlobName(", analyzer, StringComparison.Ordinal);
        Assert.Contains("function isTraceId(", analyzer, StringComparison.Ordinal);
        Assert.Contains("metric(\"Run record\", state.meta.runRecord ? displayEvidence(", analyzer, StringComparison.Ordinal);
        Assert.Contains("metric(\"Operation ID\", state.meta.operationId ? displayEvidence(", analyzer, StringComparison.Ordinal);
        Assert.Contains("(?:completed|ended) with status", analyzer, StringComparison.Ordinal);
    }

    private static PlanItem PlanItem(string status) => new()
    {
        ObjectType = "Authorization",
        Name = "redacted",
        Action = "None",
        Status = status,
    };

    private sealed class RecordingLogger : ILogger
    {
        public List<LogEntry> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var properties = state is IEnumerable<KeyValuePair<string, object?>> values
                ? values.Where(value => value.Key != "{OriginalFormat}")
                    .ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal)
                : [];
            Entries.Add(new LogEntry(eventId, properties));
        }
    }

    private sealed record LogEntry(EventId EventId, IReadOnlyDictionary<string, object?> Properties);
}
