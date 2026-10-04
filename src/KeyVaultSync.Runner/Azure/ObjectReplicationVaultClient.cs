using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using KeyVaultSync.Runner.Security;

namespace KeyVaultSync.Runner.Azure;

/// <summary>Owns the value-bearing representation of one exact Key Vault object version.</summary>
/// <remarks>
/// Dispose instances promptly so sensitive payload and signature buffers are zeroed. Versionless IDs bind
/// signatures to one logical object; <see cref="Version"/> identifies the exact version that was read.
/// </remarks>
internal sealed record ReplicatedObject : IDisposable
{
    /// <summary>Gets the supported object type.</summary>
    public required string ObjectType { get; init; }
    /// <summary>Gets the Key Vault object name.</summary>
    public required string Name { get; init; }
    /// <summary>Gets the exact data-plane version.</summary>
    public required string Version { get; init; }
    /// <summary>Gets the versionless data-plane object URI used by the HMAC contract.</summary>
    public required string VersionlessObjectId { get; init; }
    /// <summary>Gets the owned secret value, PFX, or public-key fingerprint bytes.</summary>
    public required byte[] Payload { get; init; }
    /// <summary>Gets the owned canonical material signed for integrity verification.</summary>
    public required byte[] SignatureMaterial { get; init; }
    /// <summary>Gets content-type metadata when the object exposes it.</summary>
    public string? ContentType { get; init; }
    /// <summary>Gets the object's explicit enabled state.</summary>
    public bool? Enabled { get; init; }
    /// <summary>Gets the optional activation time.</summary>
    public DateTimeOffset? NotBefore { get; init; }
    /// <summary>Gets the optional expiration time.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }
    /// <summary>Gets the case-preserving tag snapshot.</summary>
    public IReadOnlyDictionary<string, string> Tags { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
    /// <summary>Gets the source certificate policy required for PFX import.</summary>
    public CertificatePolicy? CertificatePolicy { get; init; }

    /// <summary>Projects this object into the versioned signature domain.</summary>
    public ObjectSignatureInput ToSignatureInput() => new()
    {
        VersionlessObjectId = VersionlessObjectId,
        ObjectType = ObjectType,
        Name = Name,
        Material = SignatureMaterial,
        ContentType = ContentType,
        Enabled = Enabled,
        NotBefore = NotBefore,
        ExpiresOn = ExpiresOn,
        Tags = Tags,
    };

    /// <summary>Clears all owned sensitive byte buffers.</summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Payload);
        if (!ReferenceEquals(Payload, SignatureMaterial))
        {
            CryptographicOperations.ZeroMemory(SignatureMaterial);
        }

        GC.SuppressFinalize(this);
    }
}

/// <summary>Creates retry-aware value-bearing clients for source reads and target mutations.</summary>
internal interface IObjectReplicationVaultClientFactory
{
    /// <summary>Creates a client for one vault; target clients disable SDK retries.</summary>
    IObjectReplicationVaultClient Create(VaultResource vault, bool isTarget);
}

/// <summary>Provides exact reads and the supported Key Vault object mutations used by <c>ObjectExecutor</c>.</summary>
internal interface IObjectReplicationVaultClient
{
    /// <summary>Builds the versionless data-plane URI for signature binding.</summary>
    string GetVersionlessObjectId(string objectType, string name);
    /// <summary>Reads the current or requested exact version, returning null when it is absent.</summary>
    Task<ReplicatedObject?> ReadAsync(string objectType, string name, string? version, CancellationToken cancellationToken);
    /// <summary>Writes one supported source object and reads back the exact created version.</summary>
    Task<ReplicatedObject> WriteAsync(ReplicatedObject sourceObject, CancellationToken cancellationToken);
    /// <summary>Soft-deletes one named object and waits for the delete operation to finish.</summary>
    Task DeleteAsync(string objectType, string name, CancellationToken cancellationToken);
}

/// <summary>Builds Azure SDK clients with retries disabled on every target data-plane client.</summary>
internal sealed class ObjectReplicationVaultClientFactory(TokenCredential credential) : IObjectReplicationVaultClientFactory
{
    /// <inheritdoc />
    public IObjectReplicationVaultClient Create(VaultResource vault, bool isTarget)
    {
        var uri = VaultInventoryScanner.BuildVaultUri(vault.Id);
        var secretOptions = new SecretClientOptions();
        var keyOptions = new KeyClientOptions();
        var certificateOptions = new CertificateClientOptions();
        if (isTarget)
        {
            secretOptions.Retry.MaxRetries = 0;
            keyOptions.Retry.MaxRetries = 0;
            certificateOptions.Retry.MaxRetries = 0;
        }

        return new ObjectReplicationVaultClient(
            uri,
            new SecretClient(uri, credential, secretOptions),
            new KeyClient(uri, credential, keyOptions),
            new CertificateClient(uri, credential, certificateOptions));
    }
}

/// <summary>
/// Reads value-bearing objects and performs single-attempt target writes or soft deletes.
/// Eligibility, baseline checks, and pending intent are owned by <c>ObjectExecutor</c>.
/// </summary>
internal sealed class ObjectReplicationVaultClient(
    Uri vaultUri,
    SecretClient secretClient,
    KeyClient keyClient,
    CertificateClient certificateClient) : IObjectReplicationVaultClient
{
    /// <inheritdoc />
    public string GetVersionlessObjectId(string objectType, string name)
    {
        var collection = objectType switch
        {
            "Secret" => "secrets",
            "Certificate" => "certificates",
            "Key" => "keys",
            _ => throw new ArgumentException($"Unsupported object type '{objectType}'.", nameof(objectType)),
        };
        return $"{vaultUri.AbsoluteUri.TrimEnd('/')}/{collection}/{Uri.EscapeDataString(name)}";
    }

    /// <inheritdoc />
    public async Task<ReplicatedObject?> ReadAsync(
        string objectType,
        string name,
        string? version,
        CancellationToken cancellationToken)
    {
        try
        {
            return objectType switch
            {
                "Secret" => await ReadSecretAsync(name, version, cancellationToken),
                "Certificate" => await ReadCertificateAsync(name, version, cancellationToken),
                "Key" => await ReadKeyAsync(name, version, cancellationToken),
                _ => throw new ArgumentException($"Unsupported object type '{objectType}'.", nameof(objectType)),
            };
        }
        catch (RequestFailedException exception) when (exception.Status == 404)
        {
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<ReplicatedObject> WriteAsync(
        ReplicatedObject sourceObject,
        CancellationToken cancellationToken)
    {
        return sourceObject.ObjectType switch
        {
            "Secret" => await WriteSecretAsync(sourceObject, cancellationToken),
            "Certificate" => await WriteCertificateAsync(sourceObject, cancellationToken),
            "Key" => throw new InvalidOperationException(
                "Azure Key Vault does not expose existing private key material for cross-vault replication."),
            _ => throw new ArgumentException(
                $"Unsupported object type '{sourceObject.ObjectType}'.",
                nameof(sourceObject)),
        };
    }

    /// <inheritdoc />
    public async Task DeleteAsync(string objectType, string name, CancellationToken cancellationToken)
    {
        switch (objectType)
        {
            case "Secret":
                await (await secretClient.StartDeleteSecretAsync(name, cancellationToken))
                    .WaitForCompletionAsync(cancellationToken);
                break;
            case "Certificate":
                await (await certificateClient.StartDeleteCertificateAsync(name, cancellationToken))
                    .WaitForCompletionAsync(cancellationToken);
                break;
            case "Key":
                await (await keyClient.StartDeleteKeyAsync(name, cancellationToken))
                    .WaitForCompletionAsync(cancellationToken);
                break;
            default:
                throw new ArgumentException($"Unsupported object type '{objectType}'.", nameof(objectType));
        }
    }

    private async Task<ReplicatedObject> ReadSecretAsync(
        string name,
        string? version,
        CancellationToken cancellationToken)
    {
        var secret = (await secretClient.GetSecretAsync(name, version, cancellationToken: cancellationToken)).Value;
        var payload = Encoding.UTF8.GetBytes(secret.Value);
        return new ReplicatedObject
        {
            ObjectType = "Secret",
            Name = name,
            Version = secret.Properties.Version ?? string.Empty,
            VersionlessObjectId = GetVersionlessObjectId("Secret", name),
            Payload = payload,
            SignatureMaterial = payload,
            ContentType = secret.Properties.ContentType,
            Enabled = secret.Properties.Enabled,
            NotBefore = secret.Properties.NotBefore,
            ExpiresOn = secret.Properties.ExpiresOn,
            Tags = CopyTags(secret.Properties.Tags),
        };
    }

    private async Task<ReplicatedObject> ReadCertificateAsync(
        string name,
        string? version,
        CancellationToken cancellationToken)
    {
        var currentCertificate = (await certificateClient.GetCertificateAsync(name, cancellationToken)).Value;
        KeyVaultCertificate requestedCertificate = version is null
            ? currentCertificate
            : (await certificateClient.GetCertificateVersionAsync(name, version, cancellationToken)).Value;
        var certificatePolicy = currentCertificate.Policy;
        if (certificatePolicy?.Exportable != true)
        {
            throw new InvalidOperationException("Certificate private key material is not exportable.");
        }

        var secretReference = ParseReference(requestedCertificate.SecretId, "secrets")
            ?? throw new InvalidDataException("Certificate backing secret reference is missing or malformed.");
        var backingSecret = (await secretClient.GetSecretAsync(
            secretReference.Name,
            secretReference.Version,
            cancellationToken: cancellationToken)).Value;
        // Exportable certificates expose their PFX through the version-matched backing secret.
        byte[] pfx;
        try
        {
            pfx = Convert.FromBase64String(backingSecret.Value);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("Exportable certificate backing secret is not a base64 PFX payload.", exception);
        }

        // PKCS#12 containers re-encode non-deterministically (random salts, IVs, bag ordering), so the
        // exported PFX bytes differ between vaults even when the certificate and key pair are identical.
        // The signature therefore covers the canonical policy and the DER-encoded X.509 certificate, which
        // are stable across export and import. Key-pair equivalence is implied: Key Vault only returns a
        // certificate whose stored private key matches the certificate's public key.
        var certificateDer = requestedCertificate.Cer
            ?? throw new InvalidDataException("Certificate DER encoding is missing.");
        var policyBytes = CertificatePolicyCanonicalizer.Encode(certificatePolicy);
        var signatureMaterial = CertificatePolicyCanonicalizer.ComposeSignatureMaterial(policyBytes, certificateDer);
        return new ReplicatedObject
        {
            ObjectType = "Certificate",
            Name = name,
            Version = requestedCertificate.Properties.Version ?? string.Empty,
            VersionlessObjectId = GetVersionlessObjectId("Certificate", name),
            Payload = pfx,
            SignatureMaterial = signatureMaterial,
            ContentType = certificatePolicy.ContentType?.ToString(),
            Enabled = requestedCertificate.Properties.Enabled,
            NotBefore = requestedCertificate.Properties.NotBefore,
            ExpiresOn = requestedCertificate.Properties.ExpiresOn,
            Tags = CopyTags(requestedCertificate.Properties.Tags),
            CertificatePolicy = certificatePolicy,
        };
    }

    private async Task<ReplicatedObject> ReadKeyAsync(
        string name,
        string? version,
        CancellationToken cancellationToken)
    {
        var keyBundle = (await keyClient.GetKeyAsync(name, version, cancellationToken)).Value;
        var publicFingerprint = KeyVaultPublicFingerprint.Compute(keyBundle.Key) ?? "<unavailable>";
        var payload = Encoding.UTF8.GetBytes(publicFingerprint);
        return new ReplicatedObject
        {
            ObjectType = "Key",
            Name = name,
            Version = keyBundle.Properties.Version ?? string.Empty,
            VersionlessObjectId = GetVersionlessObjectId("Key", name),
            Payload = payload,
            SignatureMaterial = payload,
            ContentType = keyBundle.Key.KeyType.ToString(),
            Enabled = keyBundle.Properties.Enabled,
            NotBefore = keyBundle.Properties.NotBefore,
            ExpiresOn = keyBundle.Properties.ExpiresOn,
            Tags = CopyTags(keyBundle.Properties.Tags),
        };
    }

    private async Task<ReplicatedObject> WriteSecretAsync(
        ReplicatedObject sourceObject,
        CancellationToken cancellationToken)
    {
        var secret = new KeyVaultSecret(sourceObject.Name, Encoding.UTF8.GetString(sourceObject.Payload))
        {
            Properties =
            {
                ContentType = sourceObject.ContentType,
                Enabled = sourceObject.Enabled,
                NotBefore = sourceObject.NotBefore,
                ExpiresOn = sourceObject.ExpiresOn,
            },
        };
        foreach (var tag in sourceObject.Tags)
        {
            secret.Properties.Tags[tag.Key] = tag.Value;
        }

        var written = (await secretClient.SetSecretAsync(secret, cancellationToken)).Value;
        return await ReadSecretAsync(sourceObject.Name, written.Properties.Version, cancellationToken);
    }

    private async Task<ReplicatedObject> WriteCertificateAsync(
        ReplicatedObject sourceObject,
        CancellationToken cancellationToken)
    {
        var options = new ImportCertificateOptions(sourceObject.Name, sourceObject.Payload)
        {
            Policy = sourceObject.CertificatePolicy
                ?? throw new InvalidOperationException("Certificate replication requires the source policy."),
            Enabled = sourceObject.Enabled,
        };
        foreach (var tag in sourceObject.Tags)
        {
            options.Tags[tag.Key] = tag.Value;
        }

        var written = (await certificateClient.ImportCertificateAsync(options, cancellationToken)).Value;
        return await ReadCertificateAsync(sourceObject.Name, written.Properties.Version, cancellationToken);
    }

    private static Dictionary<string, string> CopyTags(IDictionary<string, string> tags) =>
        new(tags, StringComparer.Ordinal);

    private static (string Name, string Version)? ParseReference(Uri? identifier, string collection)
    {
        if (identifier is null)
        {
            return null;
        }

        var segments = identifier.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var index = 0; index + 2 < segments.Length; index++)
        {
            if (segments[index].Equals(collection, StringComparison.OrdinalIgnoreCase))
            {
                return (Uri.UnescapeDataString(segments[index + 1]), Uri.UnescapeDataString(segments[index + 2]));
            }
        }

        return null;
    }
}

/// <summary>Produces a stable byte representation of managed certificate policy fields.</summary>
internal static class CertificatePolicyCanonicalizer
{
    /// <summary>
    /// Composes the certificate signature material from the canonical policy encoding and the
    /// DER-encoded X.509 certificate.
    /// </summary>
    /// <remarks>
    /// The exported PKCS#12 (PFX) container is deliberately excluded. Key Vault re-encodes PFX
    /// payloads non-deterministically, so including those bytes makes post-write verification fail
    /// for every replicated certificate even when the certificate and key pair are identical.
    /// </remarks>
    public static byte[] ComposeSignatureMaterial(byte[] policyBytes, byte[] certificateDer)
    {
        ArgumentNullException.ThrowIfNull(policyBytes);
        ArgumentNullException.ThrowIfNull(certificateDer);

        var material = new byte[4 + policyBytes.Length + certificateDer.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(material, policyBytes.Length);
        policyBytes.CopyTo(material.AsSpan(4));
        certificateDer.CopyTo(material.AsSpan(4 + policyBytes.Length));
        return material;
    }

    /// <summary>Encodes policy fields in ordinal order for certificate signatures.</summary>
    public static byte[] Encode(CertificatePolicy policy)
    {
        static string Join<T>(IEnumerable<T>? values) =>
            values is null
                ? string.Empty
                : string.Join(",", values.Select(value => value is null ? string.Empty : value.ToString()).Order(StringComparer.Ordinal));

        var san = policy.SubjectAlternativeNames;
        var fields = new[]
        {
            policy.KeyType?.ToString() ?? string.Empty,
            policy.ReuseKey?.ToString() ?? string.Empty,
            policy.Exportable?.ToString() ?? string.Empty,
            policy.KeyCurveName?.ToString() ?? string.Empty,
            policy.KeySize?.ToString() ?? string.Empty,
            policy.Subject ?? string.Empty,
            san is null ? string.Empty : string.Join(",", san.DnsNames.Order(StringComparer.Ordinal)),
            san is null ? string.Empty : string.Join(",", san.Emails.Order(StringComparer.Ordinal)),
            san is null ? string.Empty : string.Join(",", san.UserPrincipalNames.Order(StringComparer.Ordinal)),
            policy.IssuerName ?? string.Empty,
            policy.ContentType?.ToString() ?? string.Empty,
            policy.CertificateType ?? string.Empty,
            policy.CertificateTransparency?.ToString() ?? string.Empty,
            policy.ValidityInMonths?.ToString() ?? string.Empty,
            policy.Enabled?.ToString() ?? string.Empty,
            Join(policy.KeyUsage),
            Join(policy.EnhancedKeyUsage),
            string.Join(",", policy.LifetimeActions
                .Select(action => $"{action.Action}:{action.DaysBeforeExpiry}:{action.LifetimePercentage}")
                .Order(StringComparer.Ordinal)),
        };
        return Encoding.UTF8.GetBytes(string.Join("\n", fields));
    }
}
