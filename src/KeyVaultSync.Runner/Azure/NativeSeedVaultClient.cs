using System.Security.Cryptography;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using KeyVaultSync.Runner.Sync;

namespace KeyVaultSync.Runner.Azure;

internal sealed class NativeSeedVaultClientFactory(TokenCredential credential) : INativeSeedVaultClientFactory
{
    public INativeSeedVaultClient Create(VaultResource vault, bool isTarget)
    {
        var vaultUri = VaultInventoryScanner.BuildVaultUri(vault.Id);
        var keyOptions = new KeyClientOptions();
        var certificateOptions = new CertificateClientOptions();
        var secretOptions = new SecretClientOptions();
        if (isTarget)
        {
            keyOptions.Retry.MaxRetries = 0;
            certificateOptions.Retry.MaxRetries = 0;
            secretOptions.Retry.MaxRetries = 0;
        }

        return new NativeSeedVaultClient(
            vaultUri,
            new KeyClient(vaultUri, credential, keyOptions),
            new CertificateClient(vaultUri, credential, certificateOptions),
            new SecretClient(vaultUri, credential, secretOptions));
    }
}

internal sealed class NativeSeedVaultClient(
    Uri vaultUri,
    KeyClient keyClient,
    CertificateClient certificateClient,
    SecretClient secretClient) : INativeSeedVaultClient
{
    public async Task<NativeKeyObservation> ReadKeyAsync(string name, string? version, CancellationToken cancellationToken)
    {
        var response = await keyClient.GetKeyAsync(name, version, cancellationToken);
        var key = response.Value;
        var versions = new List<string>();
        await foreach (var keyVersion in keyClient.GetPropertiesOfKeyVersionsAsync(name, cancellationToken))
        {
            if (!string.IsNullOrWhiteSpace(keyVersion.Version))
            {
                versions.Add(keyVersion.Version);
            }
        }

        return new NativeKeyObservation(
            name,
            key.Properties.Version ?? string.Empty,
            key.Key.KeyType.ToString(),
            KeyVaultPublicFingerprint.Compute(key.Key),
            versions);
    }

    public async Task<byte[]> BackupKeyAsync(string name, CancellationToken cancellationToken)
    {
        var response = await keyClient.BackupKeyAsync(name, cancellationToken);
        return response.Value;
    }

    public async Task<NativeKeyObservation> RestoreKeyBackupAsync(
        string name,
        byte[] backup,
        CancellationToken cancellationToken)
    {
        var response = await keyClient.RestoreKeyBackupAsync(backup, cancellationToken);
        var version = response.Value.Properties.Version;
        if (string.IsNullOrWhiteSpace(version))
        {
            throw new InvalidDataException("Key Vault did not return a version for the restored key.");
        }

        var restored = await ReadKeyAsync(name, version, cancellationToken);
        if (!string.Equals(restored.Version, version, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The exact restored key version could not be read back.");
        }

        return restored;
    }

    public async Task<NativeCertificateGroupObservation> ReadCertificateGroupAsync(
        string name,
        string? version,
        CancellationToken cancellationToken)
    {
        string? observedVersion;
        byte[]? certificateDer;
        Uri? keyId;
        Uri? secretId;
        if (version is null)
        {
            var response = await certificateClient.GetCertificateAsync(name, cancellationToken);
            observedVersion = response.Value.Properties.Version;
            certificateDer = response.Value.Cer;
            keyId = response.Value.KeyId;
            secretId = response.Value.SecretId;
        }
        else
        {
            var response = await certificateClient.GetCertificateVersionAsync(name, version, cancellationToken);
            observedVersion = response.Value.Properties.Version;
            certificateDer = response.Value.Cer;
            keyId = response.Value.KeyId;
            secretId = response.Value.SecretId;
        }

        var certificateVersions = new List<string>();
        await foreach (var certificateVersion in certificateClient.GetPropertiesOfCertificateVersionsAsync(name, cancellationToken))
        {
            if (!string.IsNullOrWhiteSpace(certificateVersion.Version))
            {
                certificateVersions.Add(certificateVersion.Version);
            }
        }

        var keyReference = ParseObjectReference(keyId, "keys");
        var secretReference = ParseObjectReference(secretId, "secrets");
        string? backingKeyType = null;
        string? backingKeyFingerprint = null;
        IReadOnlyList<string> backingKeyVersions = [];
        IReadOnlyList<string> backingSecretVersions = [];
        if (keyReference is not null)
        {
            var key = await keyClient.GetKeyAsync(keyReference.Name, keyReference.Version, cancellationToken);
            backingKeyType = key.Value.Key.KeyType.ToString();
            backingKeyFingerprint = KeyVaultPublicFingerprint.Compute(key.Value.Key);
            var versions = new List<string>();
            await foreach (var keyVersion in keyClient.GetPropertiesOfKeyVersionsAsync(keyReference.Name, cancellationToken))
            {
                if (!string.IsNullOrWhiteSpace(keyVersion.Version))
                {
                    versions.Add(keyVersion.Version);
                }
            }

            backingKeyVersions = versions;
        }

        if (secretReference is not null)
        {
            var versions = new List<string>();
            await foreach (var secretVersion in secretClient.GetPropertiesOfSecretVersionsAsync(secretReference.Name, cancellationToken))
            {
                if (!string.IsNullOrWhiteSpace(secretVersion.Version))
                {
                    versions.Add(secretVersion.Version);
                }
            }

            backingSecretVersions = versions;
        }

        return new NativeCertificateGroupObservation(
            name,
            observedVersion ?? string.Empty,
            certificateDer is { Length: > 0 } ? Convert.ToHexString(SHA256.HashData(certificateDer)) : null,
            keyReference?.Name,
            keyReference?.Version,
            backingKeyType,
            backingKeyFingerprint,
            secretReference?.Name,
            secretReference?.Version,
            certificateVersions,
            backingKeyVersions,
            backingSecretVersions);
    }

    public async Task<byte[]> BackupCertificateAsync(string name, CancellationToken cancellationToken)
    {
        var response = await certificateClient.BackupCertificateAsync(name, cancellationToken);
        return response.Value;
    }

    public async Task<NativeCertificateGroupObservation> RestoreCertificateBackupAsync(
        string name,
        byte[] backup,
        CancellationToken cancellationToken)
    {
        var response = await certificateClient.RestoreCertificateBackupAsync(backup, cancellationToken);
        var version = response.Value.Properties.Version;
        if (string.IsNullOrWhiteSpace(version))
        {
            throw new InvalidDataException("Key Vault did not return a version for the restored certificate.");
        }

        var restored = await ReadCertificateGroupAsync(name, version, cancellationToken);
        if (!string.Equals(restored.Version, version, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The exact restored certificate version could not be read back.");
        }

        return restored;
    }

    public async Task<bool> HasAnyObjectNamedAsync(string name, CancellationToken cancellationToken)
    {
        await foreach (var secret in secretClient.GetPropertiesOfSecretsAsync(cancellationToken))
        {
            if (secret.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        await foreach (var key in keyClient.GetPropertiesOfKeysAsync(cancellationToken))
        {
            if (key.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        await foreach (var certificate in certificateClient.GetPropertiesOfCertificatesAsync(false, cancellationToken))
        {
            if (certificate.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        await foreach (var secret in secretClient.GetDeletedSecretsAsync(cancellationToken))
        {
            if (secret.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        await foreach (var key in keyClient.GetDeletedKeysAsync(cancellationToken))
        {
            if (key.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        await foreach (var certificate in certificateClient.GetDeletedCertificatesAsync(false, cancellationToken))
        {
            if (certificate.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private NativeObjectReference? ParseObjectReference(Uri? identifier, string expectedCollection)
    {
        if (identifier is null
            || identifier.Scheme != Uri.UriSchemeHttps
            || !identifier.Authority.Equals(vaultUri.Authority, StringComparison.OrdinalIgnoreCase)
            || identifier.Query.Length != 0
            || identifier.Fragment.Length != 0)
        {
            return null;
        }

        var segments = identifier.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 3
            || !segments[0].Equals(expectedCollection, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var name = Uri.UnescapeDataString(segments[1]);
        var version = Uri.UnescapeDataString(segments[2]);
        return string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(version)
            ? null
            : new NativeObjectReference(name, version);
    }

    private sealed record NativeObjectReference(string Name, string Version);
}
