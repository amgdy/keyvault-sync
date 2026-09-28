using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace KeyVaultSync.Runner.Security;

/// <summary>Computes keyed secret-value HMACs and unkeyed canonical managed-metadata digests.</summary>
/// <remarks>
/// <para>Value fingerprints bind a secret to its pair, object type, and name; they are not encryption.
/// Metadata digests compare non-value properties and deliberately do not need the HMAC key.</para>
/// <para>The caller owns the service for one run and must dispose it. Never log this service's key,
/// value inputs, or returned fingerprints. State stores fingerprints, not the underlying key or secret value.</para>
/// </remarks>
internal sealed class SecretHmacService : IDisposable
{
    /// <summary>The value encoding/domain version persisted with baselines; encoding changes require a new version and review.</summary>
    public const string ValueDomainVersion = "keyvaultsync/secret/v2";
    /// <summary>The separate canonical metadata format version, not the configured key's rotation/version label.</summary>
    public const string MetadataDomainVersion = "keyvaultsync/secret-metadata/v2";

    private readonly byte[] _key;

    /// <summary>Takes ownership of an already validated decoded key buffer so disposal can zero that buffer.</summary>
    private SecretHmacService(byte[] key, string keyVersion)
    {
        _key = key;
        KeyVersion = keyVersion;
    }

    /// <summary>Gets the non-secret operator label used to reject baselines created with a different configured key version.</summary>
    public string KeyVersion { get; }

    /// <summary>Loads an optional 256-bit HMAC key from resolved protected application configuration.</summary>
    /// <param name="options">Configuration carrying a Base64 key and a nonblank version label; neither is loaded from Blob state.</param>
    /// <returns>A caller-owned service, or null when no key is configured; the caller enforces apply-mode requirements.</returns>
    /// <exception cref="InvalidOperationException">Base64 is invalid, the decoded key is not 32 bytes, or its version label is blank.</exception>
    /// <remarks>
    /// Decoded bytes are cleared on validation failure. This method does not generate, rotate, fetch, or persist keys,
    /// and changing configuration never automatically authorizes a new baseline for existing targets.
    /// </remarks>
    public static SecretHmacService? Load(RunnerOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.HmacKeyBase64))
        {
            return null;
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(options.HmacKeyBase64);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException("The configured HMAC key must contain a base64-encoded 256-bit key.", exception);
        }

        if (key.Length != 32)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new InvalidOperationException("The configured HMAC key must decode to exactly 32 bytes.");
        }

        if (string.IsNullOrWhiteSpace(options.HmacKeyVersion))
        {
            CryptographicOperations.ZeroMemory(key);
            throw new InvalidOperationException("The configured HMAC key version must not be empty.");
        }

        return new SecretHmacService(key, options.HmacKeyVersion);
    }

    /// <summary>Computes an HMAC-SHA-256 bound to the current format, directional pair, Secret type, name, and value.</summary>
    /// <param name="pairId">Exact directional pair string; its casing/encoding is significant to the fingerprint.</param>
    /// <param name="secretName">Exact object name, preventing a fingerprint from being reused for a different secret.</param>
    /// <param name="value">Plaintext value held only for computation; never place it in diagnostic messages.</param>
    /// <returns>A 64-character uppercase hexadecimal HMAC suitable for protected baseline/intent state.</returns>
    /// <remarks>Fields are length-prefixed UTF-8, not delimiter-joined. Call only before disposal.</remarks>
    public string ComputeValue(string pairId, string secretName, string value)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _key);
        // Domain and object identity prevent cross-pair/name reuse of equal-value fingerprints.
        // Length prefixes distinguish fields even when input text contains separators or newlines.
        AppendField(hmac, Encoding.UTF8.GetBytes(ValueDomainVersion));
        AppendField(hmac, Encoding.UTF8.GetBytes(pairId));
        AppendField(hmac, "Secret"u8);
        AppendField(hmac, Encoding.UTF8.GetBytes(secretName));
        AppendField(hmac, Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hmac.GetHashAndReset());
    }

    /// <summary>Compares well-formed 32-byte hexadecimal HMACs using fixed-time byte comparison.</summary>
    /// <param name="expected">The committed or expected fingerprint; null/malformed values are rejected.</param>
    /// <param name="actual">The newly computed fingerprint; null/malformed values are rejected.</param>
    /// <returns>True only when both encodings are valid and their decoded bytes match.</returns>
    /// <remarks>Format/length checks short-circuit; fixed-time comparison applies to valid equal-length decoded hashes.</remarks>
    public static bool ValueHmacEquals(string? expected, string? actual)
    {
        if (expected is null || actual is null)
        {
            return false;
        }

        if (expected.Length != 64 || actual.Length != 64)
        {
            return false;
        }

        try
        {
            var expectedBytes = Convert.FromHexString(expected);
            var actualBytes = Convert.FromHexString(actual);
            return expectedBytes.Length == 32
                && actualBytes.Length == 32
                && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Computes SHA-256 over a canonical sequence of the properties managed by secret synchronization.</summary>
    /// <param name="enabled">Enabled state; null is normalized to true to match the default service behavior.</param>
    /// <param name="contentType">Content type, with null represented by the format's literal null marker.</param>
    /// <param name="notBefore">Optional timestamp normalized to UTC round-trip text.</param>
    /// <param name="expiresOn">Optional timestamp normalized to UTC round-trip text.</param>
    /// <param name="tags">Tags sorted by ordinal key; null is equivalent to an empty collection.</param>
    /// <returns>A 64-character uppercase hexadecimal metadata digest; it authenticates no secret value.</returns>
    /// <remarks>
    /// Names, IDs, versions, and service creation/update timestamps are excluded. Tag casing and values are preserved.
    /// The v2 format uses literal <c>&lt;null&gt;</c> for absent scalar values; do not silently change canonicalization
    /// or encoding without a domain-version/recovery decision for stored baselines.
    /// </remarks>
    public static string ComputeMetadata(
        bool? enabled,
        string? contentType,
        DateTimeOffset? notBefore,
        DateTimeOffset? expiresOn,
        IReadOnlyDictionary<string, string>? tags)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendField(hash, Encoding.UTF8.GetBytes(MetadataDomainVersion));
        AppendField(hash, enabled == false ? "false"u8 : "true"u8);
        AppendField(hash, Encoding.UTF8.GetBytes(contentType ?? "<null>"));
        AppendField(hash, Encoding.UTF8.GetBytes(notBefore?.ToUniversalTime().ToString("O") ?? "<null>"));
        AppendField(hash, Encoding.UTF8.GetBytes(expiresOn?.ToUniversalTime().ToString("O") ?? "<null>"));
        foreach (var tag in (tags ?? new Dictionary<string, string>()).OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            AppendField(hash, Encoding.UTF8.GetBytes(tag.Key));
            AppendField(hash, Encoding.UTF8.GetBytes(tag.Value));
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    /// <summary>Zeros the decoded key buffer owned by this instance; callers must not compute with it afterward.</summary>
    /// <remarks>
    /// This does not erase environment/configuration strings, secret strings returned by the SDK, or temporary
    /// UTF-8 value arrays. Managed-memory lifetime is not a general secure-erasure guarantee.
    /// </remarks>
    public void Dispose() => CryptographicOperations.ZeroMemory(_key);

    /// <summary>Appends a four-byte big-endian byte length followed by the bytes, preserving field boundaries.</summary>
    /// <remarks>The encoding is shared by both fingerprint formats and is part of their persisted version contract.</remarks>
    private static void AppendField(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }
}
