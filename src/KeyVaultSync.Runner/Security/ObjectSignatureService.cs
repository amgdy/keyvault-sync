using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace KeyVaultSync.Runner.Security;

/// <summary>The exact value-bearing object state covered by the versioned integrity signature.</summary>
internal sealed record ObjectSignatureInput
{
    /// <summary>Gets the versionless target or source object URI that binds the signature to one logical object.</summary>
    public required string VersionlessObjectId { get; init; }
    /// <summary>Gets the supported object type.</summary>
    public required string ObjectType { get; init; }
    /// <summary>Gets the object name.</summary>
    public required string Name { get; init; }
    /// <summary>Gets the secret, canonical certificate, or public-key fingerprint bytes.</summary>
    public required ReadOnlyMemory<byte>? Material { get; init; }
    /// <summary>Gets normalized content-type metadata.</summary>
    public string? ContentType { get; init; }
    /// <summary>Gets the explicit enabled state.</summary>
    public bool? Enabled { get; init; }
    /// <summary>Gets the optional activation time.</summary>
    public DateTimeOffset? NotBefore { get; init; }
    /// <summary>Gets the optional expiration time.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }
    /// <summary>Gets tags that will be signed in ordinal key order.</summary>
    public IReadOnlyDictionary<string, string> Tags { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
}

/// <summary>Computes the version-independent integrity signature used for managed Key Vault objects.</summary>
/// <remarks>
/// The versionless object identifier is a signed field, not the HMAC key. Values, JWK/PFX bytes, tags,
/// and signatures must never be logged or exported as telemetry.
/// </remarks>
internal sealed class ObjectSignatureService : IDisposable
{
    /// <summary>Gets the persisted signature-domain identifier.</summary>
    /// <remarks>
    /// The certificate signature contract changed to exclude the non-deterministic PKCS#12 container,
    /// but the domain version is intentionally unchanged: certificate verification could never succeed
    /// under the previous contract, so no certificate baseline exists to invalidate. The secret and key
    /// contracts are untouched, and bumping the version would block their committed baselines.
    /// </remarks>
    public const string DomainVersion = "keyvaultsync/object/v3";
    private const string Absent = "<absent>";

    private readonly byte[] _key;

    private ObjectSignatureService(byte[] key, string keyVersion)
    {
        _key = key;
        KeyVersion = keyVersion;
    }

    /// <summary>Gets the operator-managed label identifying the active HMAC key.</summary>
    public string KeyVersion { get; }

    /// <summary>Loads and validates protected HMAC configuration, or returns null when it is absent.</summary>
    public static ObjectSignatureService? Load(RunnerOptions options)
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

        return new ObjectSignatureService(key, options.HmacKeyVersion);
    }

    /// <summary>Signs the exact canonical object envelope for <see cref="DomainVersion"/>.</summary>
    public string Compute(ObjectSignatureInput input)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _key);
        Append(hmac, DomainVersion);
        Append(hmac, input.VersionlessObjectId);
        Append(hmac, input.ObjectType);
        Append(hmac, input.Name);
        if (input.Material is { } material)
        {
            Append(hmac, material.Span);
        }
        else
        {
            Append(hmac, Absent);
        }

        Append(hmac, input.ContentType ?? Absent);
        Append(hmac, input.Enabled?.ToString().ToLowerInvariant() ?? Absent);
        Append(hmac, FormatTimestamp(input.NotBefore));
        Append(hmac, FormatTimestamp(input.ExpiresOn));
        foreach (var tag in input.Tags.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            Append(hmac, tag.Key);
            Append(hmac, tag.Value);
        }

        return Convert.ToHexString(hmac.GetHashAndReset());
    }

    /// <summary>Compares two hexadecimal SHA-256 signatures in fixed time.</summary>
    public static bool Equals(string? expected, string? actual)
    {
        if (expected is null || actual is null || expected.Length != 64 || actual.Length != 64)
        {
            return false;
        }

        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(expected),
                Convert.FromHexString(actual));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Clears the in-memory HMAC key.</summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_key);
    }

    private static void Append(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Append(hash, bytes);
        CryptographicOperations.ZeroMemory(bytes);
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static string FormatTimestamp(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("O") ?? Absent;
}
