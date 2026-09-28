using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using KeyVaultSync.Runner.Sync;

namespace KeyVaultSync.Runner.Azure;

internal interface ISecretSyncVaultClientFactory
{
    ISecretSyncVaultClient Create(VaultResource vault, bool isTarget);
}

internal interface ISecretSyncVaultClient
{
    Task<KeyVaultSecret> GetSecretAsync(string name, string? version, CancellationToken cancellationToken);
    IAsyncEnumerable<SecretProperties> GetPropertiesOfSecretsAsync(CancellationToken cancellationToken);
    IAsyncEnumerable<DeletedSecret> GetDeletedSecretsAsync(CancellationToken cancellationToken);
    Task<KeyVaultSecret> SetSecretAsync(KeyVaultSecret secret, CancellationToken cancellationToken);
    Task<SecretProperties> UpdateSecretPropertiesAsync(SecretProperties properties, CancellationToken cancellationToken);
}

internal sealed class SecretSyncVaultClientFactory(TokenCredential credential) : ISecretSyncVaultClientFactory
{
    public ISecretSyncVaultClient Create(VaultResource vault, bool isTarget)
    {
        var options = new SecretClientOptions();
        if (isTarget)
        {
            // A lost write response may hide a successful SetSecret, which would create another
            // version if retried. This also disables retries on target reads.
            options.Retry.MaxRetries = 0;
        }

        var vaultUri = VaultInventoryScanner.BuildVaultUri(vault.Id);
        return new SecretSyncVaultClient(new SecretClient(vaultUri, credential, options));
    }
}

internal sealed class SecretSyncVaultClient(SecretClient client) : ISecretSyncVaultClient
{
    public async Task<KeyVaultSecret> GetSecretAsync(string name, string? version, CancellationToken cancellationToken)
    {
        return (await client.GetSecretAsync(name, version, cancellationToken: cancellationToken)).Value;
    }

    public IAsyncEnumerable<SecretProperties> GetPropertiesOfSecretsAsync(CancellationToken cancellationToken)
    {
        return client.GetPropertiesOfSecretsAsync(cancellationToken);
    }

    public IAsyncEnumerable<DeletedSecret> GetDeletedSecretsAsync(CancellationToken cancellationToken)
    {
        return client.GetDeletedSecretsAsync(cancellationToken);
    }

    public async Task<KeyVaultSecret> SetSecretAsync(KeyVaultSecret secret, CancellationToken cancellationToken)
    {
        return (await client.SetSecretAsync(secret, cancellationToken)).Value;
    }

    public async Task<SecretProperties> UpdateSecretPropertiesAsync(
        SecretProperties properties,
        CancellationToken cancellationToken)
    {
        return (await client.UpdateSecretPropertiesAsync(properties, cancellationToken)).Value;
    }
}
