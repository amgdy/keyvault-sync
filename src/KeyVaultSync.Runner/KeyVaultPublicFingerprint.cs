using System.Security.Cryptography;
using System.Text.Json;
using Azure.Security.KeyVault.Keys;

namespace KeyVaultSync.Runner;

/// <summary>Computes a stable fingerprint from public asymmetric JWK components without reading private material.</summary>
internal static class KeyVaultPublicFingerprint
{
    public static string? Compute(JsonWebKey key)
    {
        var hasRsaComponents = key.N is { Length: > 0 } || key.E is { Length: > 0 };
        var hasEcComponents = key.CurveName is not null
            || key.X is { Length: > 0 }
            || key.Y is { Length: > 0 };
        if (hasRsaComponents == hasEcComponents)
        {
            return null;
        }

        object publicComponents;
        if (hasRsaComponents)
        {
            if (key.N is not { Length: > 0 } || key.E is not { Length: > 0 })
            {
                return null;
            }

            publicComponents = new
            {
                KeyType = key.KeyType.ToString(),
                Modulus = key.N,
                Exponent = key.E,
            };
        }
        else
        {
            if (key.CurveName is null
                || key.X is not { Length: > 0 }
                || key.Y is not { Length: > 0 })
            {
                return null;
            }

            publicComponents = new
            {
                KeyType = key.KeyType.ToString(),
                Curve = key.CurveName.ToString(),
                X = key.X,
                Y = key.Y,
            };
        }

        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(publicComponents)));
    }
}
