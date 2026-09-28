using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Globalization;
using System.Diagnostics;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.State;

/// <summary>Persists run history and lease-protected pair state in separate private Blob containers.</summary>
/// <remarks>
/// Run history is replaceable diagnostic progress; pair state is authoritative ownership/intent data.
/// They are not saved in one transaction. No secret values or HMAC keys are stored, but identifiers,
/// authorization declarations, and fingerprints still require restricted storage access.
/// </remarks>
internal sealed class BlobStateStore
{
    private static readonly EventId ContainerInitializationStartedEventId = new(4000, "ContainerInitializationStarted");
    private static readonly EventId RunRecordPersistedEventId = new(4001, "RunRecordPersisted");
    private static readonly EventId PairLeaseAcquisitionEventId = new(4010, "PairLeaseAcquisition");

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly BlobContainerClient _stateContainer;
    private readonly BlobContainerClient _runsContainer;
    private readonly ILogger<BlobStateStore> _logger;
    private readonly ILoggerFactory _loggerFactory;

    /// <summary>Creates container clients without making network calls or validating storage permissions.</summary>
    /// <param name="serviceClient">Host-configured Blob service client and authentication pipeline.</param>
    /// <param name="options">Names of the pair-state and run-history containers.</param>
    /// <param name="loggerFactory">Host-owned factory used by this store and the renewable pair leases it creates.</param>
    public BlobStateStore(BlobServiceClient serviceClient, RunnerOptions options, ILoggerFactory loggerFactory)
    {
        _stateContainer = serviceClient.GetBlobContainerClient(options.StateContainer);
        _runsContainer = serviceClient.GetBlobContainerClient(options.RunsContainer);
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<BlobStateStore>();
    }

    /// <summary>Creates absent state/history containers with no public access, including for read-only scans.</summary>
    /// <param name="cancellationToken">Cancellation for container creation/existence requests.</param>
    /// <returns>A task completing when both initialization requests have succeeded.</returns>
    /// <remarks>CreateIfNotExists does not rewrite existing container access settings; deployment must secure existing storage.</remarks>
    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("blob.initialize-state-containers");
        _logger.LogInformation(ContainerInitializationStartedEventId,
            "Initializing run-history and pair-state Blob containers. {StateContainer}; {RunsContainer}.",
            _stateContainer.Name, _runsContainer.Name);
        var state = await _stateContainer.CreateIfNotExistsAsync(PublicAccessType.None, cancellationToken: cancellationToken);
        var runs = await _runsContainer.CreateIfNotExistsAsync(PublicAccessType.None, cancellationToken: cancellationToken);
        activity?.SetStatus(ActivityStatusCode.Ok);
        _logger.LogInformation("Blob state containers are ready. State created: {StateCreated}; runs created: {RunsCreated}.",
            state is not null, runs is not null);
    }

    /// <summary>Replaces the run's diagnostic JSON blob with the latest accumulated progress snapshot.</summary>
    /// <param name="record">Run record whose UTC start determines the yyyy/MM/dd partition and whose RunId is the filename.</param>
    /// <param name="cancellationToken">Cancellation for upload; callers may use None for a final failure/cancellation report.</param>
    /// <returns>A task completing after the upload is acknowledged.</returns>
    /// <remarks>
    /// Path: runs/yyyy/MM/dd/RunId.json. No pair lease/ETag is applied to this per-run history document.
    /// An upload failure propagates; a history record is not a substitute for a committed pair-state write.
    /// </remarks>
    public async Task WriteRunRecordAsync(RunRecord record, CancellationToken cancellationToken)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("blob.write-run-record");
        var partition = record.StartedAt.UtcDateTime.ToString("yyyy/MM/dd", CultureInfo.InvariantCulture);
        var path = $"runs/{partition}/{record.RunId}.json";
        var blob = _runsContainer.GetBlobClient(path);
        var content = BinaryData.FromObjectAsJson(record, JsonOptions);
        activity?.SetTag("sync.run_id", record.RunId);
        activity?.SetTag("storage.container", _runsContainer.Name);
        try
        {
            await blob.UploadAsync(content, overwrite: true, cancellationToken);
            activity?.SetStatus(ActivityStatusCode.Ok);
            _logger.LogInformation(RunRecordPersistedEventId,
                "Run progress record persisted. {RunId}; {Status}; {PairCount} pair records; container {ContainerName}.",
                record.RunId, record.Status, record.Pairs.Count, _runsContainer.Name);
        }
        catch (Exception exception)
        {
            RunnerTelemetry.RecordException(activity, exception);
            activity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
            _logger.LogError(exception, "Could not persist run record {RunId}.", record.RunId);
            throw;
        }
    }

    /// <summary>Creates state if absent, acquires a 60-second Blob lease, and loads state with its current ETag.</summary>
    /// <param name="pair">Current source/target mapping whose exact PairId determines the hashed state-blob path.</param>
    /// <param name="cancellationToken">Cancellation for initial creation, acquisition, and loading, not the later renewal loop.</param>
    /// <returns>An asynchronously disposable lease owner, or null for an HTTP 409 lease-acquisition conflict.</returns>
    /// <exception cref="InvalidDataException">State is empty or declares a newer unsupported schema.</exception>
    /// <exception cref="InvalidOperationException">The persisted source/target endpoints disagree with the current mapping.</exception>
    /// <remarks>
    /// Explicit older schema markers are upgraded in memory and persisted only on a later save; this does not
    /// rebaseline legacy HMAC domains. Other storage/deserialization errors propagate. On post-acquisition failure,
    /// release is attempted without hiding the original exception; an unreleased finite lease can expire.
    /// </remarks>
    public async Task<PairLease?> TryAcquirePairLeaseAsync(VaultPair pair, CancellationToken cancellationToken)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("blob.acquire-pair-lease");
        activity?.SetTag("sync.pair_id", pair.PairId);
        activity?.SetTag("vault.source.name", pair.Source.Name);
        activity?.SetTag("vault.target.name", pair.Target.Name);
        var leaseTimer = Stopwatch.StartNew();
        _logger.LogInformation(PairLeaseAcquisitionEventId,
            "Pair state lease acquisition started. {SourceVaultName} to {TargetVaultName}.", pair.Source.Name, pair.Target.Name);
        var pairKey = GetPairKey(pair.PairId);
        var blob = _stateContainer.GetBlobClient($"pairs/{pairKey}.json");
        var initialState = new PairState
        {
            PairId = pair.PairId,
            SourceVaultId = pair.Source.Id,
            TargetVaultId = pair.Target.Id,
        };

        try
        {
            // Conditional creation must never replace existing ownership or pending-intent data.
            // A competing creator is expected; load the existing record only after lease acquisition.
            await blob.UploadAsync(BinaryData.FromObjectAsJson(initialState, JsonOptions), overwrite: false, cancellationToken);
        }
        catch (RequestFailedException exception) when (exception.Status is 409 or 412)
        {
            // Another scan created the pair record first.
        }

        var leaseClient = blob.GetBlobLeaseClient();
        BlobLease lease;
        try
        {
            var response = await leaseClient.AcquireAsync(TimeSpan.FromSeconds(60), cancellationToken: cancellationToken);
            lease = response.Value;
        }
        catch (RequestFailedException exception) when (exception.Status == 409)
        {
            activity?.SetStatus(ActivityStatusCode.Ok, "Lease already held");
            leaseTimer.Stop();
            _logger.LogInformation("Pair lease is already held for {PairId}; this scan will skip the pair.", pair.PairId);
            return null;
        }

        try
        {
            var download = await blob.DownloadContentAsync(cancellationToken);
            var state = download.Value.Content.ToObjectFromJson<PairState>(JsonOptions)
                ?? throw new InvalidDataException($"Pair state blob for {pair.PairId} is empty.");

            if (state.SchemaVersion > PairState.CurrentSchemaVersion)
            {
                throw new InvalidDataException($"Pair state schema {state.SchemaVersion} is newer than this runner supports.");
            }

            if (state.SchemaVersion < PairState.CurrentSchemaVersion)
            {
                // Only the state marker is advanced here. Missing baseline domain versions retain
                // their "unknown" defaults, so planner/executor checks still require manual review.
                state.SchemaVersion = PairState.CurrentSchemaVersion;
                _logger.LogWarning("Upgraded pair-state schema for {PairId}; legacy HMAC baselines without a domain version remain blocked until reviewed.", pair.PairId);
            }

            if (!state.SourceVaultId.Equals(pair.Source.Id, StringComparison.OrdinalIgnoreCase)
                || !state.TargetVaultId.Equals(pair.Target.Id, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Stored pair mapping for {pair.Source.Name} changed. Refusing to reuse prior state against a new target.");
            }

            activity?.SetStatus(ActivityStatusCode.Ok);
            leaseTimer.Stop();
            activity?.SetTag("pair_state.schema_version", state.SchemaVersion);
            activity?.SetTag("pair_state.baseline_count", state.SecretBaselines.Count);
            activity?.SetTag("pair_state.pending_write_count", state.PendingSecretWrites.Count);
            _logger.LogInformation(PairLeaseAcquisitionEventId,
                "Pair state lease acquired. {PairId}; state schema {SchemaVersion}; {BaselineCount} secret baselines; {PendingWriteCount} pending writes; waited {DurationMs} ms.",
                pair.PairId, state.SchemaVersion, state.SecretBaselines.Count, state.PendingSecretWrites.Count, leaseTimer.Elapsed.TotalMilliseconds);
            return new PairLease(blob, leaseClient, lease.LeaseId, download.Value.Details.ETag, state,
                _loggerFactory.CreateLogger<PairLease>());
        }
        catch
        {
            try
            {
                await leaseClient.ReleaseAsync(cancellationToken: cancellationToken);
            }
            catch
            {
                // Preserve the original error; the lease will expire if release is unavailable.
            }

            throw;
        }
    }

    /// <summary>Returns lowercase hex SHA-256 of the exact UTF-8 pair identity for a stable, path-safe blob filename.</summary>
    /// <remarks>This is addressing, not a secret HMAC. No casing normalization occurs; changing identity text changes the path.</remarks>
    private static string GetPairKey(string pairId)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(pairId));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

/// <summary>Exposes the lease-protected state operations required by guarded mutation executors.</summary>
internal interface IPairStateLease
{
    /// <summary>Gets mutable working state; changes are not durable until SaveStateAsync succeeds.</summary>
    PairState State { get; }

    /// <summary>Rejects further work when the background renewal loop has reported a failure.</summary>
    void EnsureLeaseHeld();

    /// <summary>Persists state only while the lease ID and observed Blob ETag still match.</summary>
    Task SaveStateAsync(CancellationToken cancellationToken);
}

/// <summary>Owns renewal and conditional persistence for one acquired pair-state Blob lease.</summary>
/// <remarks>
/// <para>Use one owner sequentially with await using. Mutate State, then explicitly save; disposal never commits state.
/// A lease coordinates cooperating users of this blob, not external Key Vault writers or service-side mutations.</para>
/// <para>Renewal failure is recorded for later guards. The storage service enforces lease ID/ETag on state writes;
/// Key Vault has no equivalent fencing token for this lease, so the single-writer permission model remains essential.</para>
/// </remarks>
internal sealed class PairLease : IAsyncDisposable, IPairStateLease
{
    private static readonly EventId PairLeaseLifecycleEventId = new(4011, "PairLeaseLifecycle");
    private static readonly EventId PairStatePersistedEventId = new(4020, "PairStatePersisted");
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly BlobClient _blob;
    private readonly BlobLeaseClient _leaseClient;
    private readonly ILogger<PairLease> _logger;
    private readonly CancellationTokenSource _renewalCancellation = new();
    private readonly Task _renewalTask;
    private readonly Stopwatch _leaseTimer = Stopwatch.StartNew();
    private ETag _etag;
    private Exception? _renewalError;

    /// <summary>Takes ownership of an acquired lease and immediately starts its independent renewal loop.</summary>
    /// <param name="blob">State blob whose content was read after acquisition.</param>
    /// <param name="leaseClient">Client already associated with the acquired lease.</param>
    /// <param name="leaseId">Storage lease credential applied to writes; never include it in diagnostics.</param>
    /// <param name="etag">ETag from the downloaded content, used to reject stale state replacement.</param>
    /// <param name="state">Deserialized/validated mutable state owned by this pair operation.</param>
    /// <param name="logger">Logger carrying the outer run/pair correlation scopes.</param>
    public PairLease(BlobClient blob, BlobLeaseClient leaseClient, string leaseId, ETag etag, PairState state, ILogger<PairLease> logger)
    {
        _blob = blob;
        _leaseClient = leaseClient;
        _logger = logger;
        LeaseId = leaseId;
        _etag = etag;
        State = state;
        _renewalTask = RenewLeaseLoopAsync(_renewalCancellation.Token);
    }

    /// <summary>Gets the lease credential used for conditional Blob writes; it is not a Key Vault write token.</summary>
    public string LeaseId { get; }
    /// <summary>Gets mutable working state; changes are not durable until SaveStateAsync succeeds.</summary>
    public PairState State { get; }

    /// <summary>Rejects further work when the background renewal loop has already reported a failure.</summary>
    /// <exception cref="InvalidOperationException">A renewal failure is known to this instance.</exception>
    /// <remarks>This is a local cached-failure check, not a live lease query or a guarantee against lease loss after the check.</remarks>
    public void EnsureLeaseHeld()
    {
        if (_renewalError is not null)
        {
            throw new InvalidOperationException("The pair-state Blob lease was lost; stop all further work for this pair.", _renewalError);
        }
    }

    /// <summary>Persists the entire working state only if the lease ID and last observed Blob ETag still match.</summary>
    /// <param name="cancellationToken">Cancellation for the conditional upload.</param>
    /// <returns>A task completing after state was acknowledged and the next-write ETag was updated.</returns>
    /// <remarks>
    /// Used for intents, verified baselines, and scan checkpoints, not just the last-scan timestamp. A thrown
    /// storage error must stop dependent mutations; never force an overwrite or assume in-memory state is durable.
    /// The caller must not issue concurrent saves or modify State during serialization/upload.
    /// </remarks>
    public async Task SaveStateAsync(CancellationToken cancellationToken)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("blob.save-pair-checkpoint");
        EnsureLeaseHeld();
        var conditions = new BlobRequestConditions
        {
            // Lease ID protects against another owner; ETag protects against overwriting an
            // unexpected state version. Both conditions matter and must travel with every save.
            LeaseId = LeaseId,
            IfMatch = _etag,
        };
        var options = new BlobUploadOptions
        {
            Conditions = conditions,
        };
        activity?.SetTag("sync.pair_id", State.PairId);
        try
        {
            var response = await _blob.UploadAsync(BinaryData.FromObjectAsJson(State, JsonOptions), options, cancellationToken);
            _etag = response.Value.ETag;
            activity?.SetStatus(ActivityStatusCode.Ok);
            activity?.SetTag("pair_state.schema_version", State.SchemaVersion);
            activity?.SetTag("pair_state.baseline_count", State.SecretBaselines.Count);
            activity?.SetTag("pair_state.pending_write_count", State.PendingSecretWrites.Count);
            _logger.LogInformation(PairStatePersistedEventId,
                "Pair state persisted. {PairId}; last complete run {LastCompleteRunId}; {BaselineCount} secret baselines; {PendingWriteCount} pending writes.",
                State.PairId, State.LastCompleteRunId, State.SecretBaselines.Count, State.PendingSecretWrites.Count);
        }
        catch (Exception exception)
        {
            RunnerTelemetry.RecordException(activity, exception);
            activity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
            _logger.LogError(exception, "Could not save checkpoint for pair {PairId}.", State.PairId);
            throw;
        }
    }

    /// <summary>Renews the 60-second lease every 20 seconds until disposal, caching the first renewal failure.</summary>
    /// <remarks>
    /// This lifetime token is separate from the run token so cleanup controls renewal shutdown. Failure ends the loop;
    /// it does not reacquire a lease or cancel an already in-flight Key Vault request. Guards observe the cached error.
    /// </remarks>
    private async Task RenewLeaseLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(20));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                await _leaseClient.RenewAsync(cancellationToken: cancellationToken);
                _logger.LogDebug(PairLeaseLifecycleEventId,
                    "Pair state lease renewed. {PairId}; elapsed lease time {ElapsedMs} ms.",
                    State.PairId, _leaseTimer.Elapsed.TotalMilliseconds);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _renewalError = exception;
            _logger.LogError(exception, "Blob lease renewal failed for pair {PairId}.", State.PairId);
        }
    }

    /// <summary>Stops/awaits renewal and attempts release independently of the cancelled run token.</summary>
    /// <returns>A value task completing after cleanup; release failures are warned and left to finite lease expiration.</returns>
    /// <remarks>No state is saved or rolled back here. Pending intents remain for recovery; cleanup does not replay mutations.</remarks>
    public async ValueTask DisposeAsync()
    {
        _renewalCancellation.Cancel();
        try
        {
            await _renewalTask;
        }
        catch
        {
            // The lease release below determines whether cleanup succeeded.
        }

        _leaseTimer.Stop();
        try
        {
            await _leaseClient.ReleaseAsync(cancellationToken: CancellationToken.None);
            _logger.LogInformation(PairLeaseLifecycleEventId,
                "Pair state lease released. {PairId}; lease held for {ElapsedMs} ms.",
                State.PairId, _leaseTimer.Elapsed.TotalMilliseconds);
        }
        catch
        {
            // The lease expires automatically if release cannot reach Storage.
            _logger.LogWarning("Could not release Blob lease for pair {PairId}; it will expire automatically.", State.PairId);
        }

        _renewalCancellation.Dispose();
    }
}
