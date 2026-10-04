using System.Buffers.Binary;
using System.Text;
using KeyVaultSync.Runner.Azure;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

/// <summary>
/// Guards the certificate signature contract against the PKCS#12 instability that previously made
/// post-write verification fail for every replicated certificate.
/// </summary>
public sealed class CertificateSignatureMaterialTests
{
    private static readonly byte[] Policy = Encoding.UTF8.GetBytes("RSA|False|True|CN=KeyVaultSync");
    private static readonly byte[] CertificateDer = [0x30, 0x82, 0x01, 0x0A, 0x02, 0x01, 0x05];

    [Fact]
    public void Signature_material_is_deterministic_for_identical_policy_and_certificate()
    {
        var first = CertificatePolicyCanonicalizer.ComposeSignatureMaterial(Policy, CertificateDer);
        var second = CertificatePolicyCanonicalizer.ComposeSignatureMaterial([.. Policy], [.. CertificateDer]);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Signature_material_length_excludes_the_pfx_container()
    {
        var material = CertificatePolicyCanonicalizer.ComposeSignatureMaterial(Policy, CertificateDer);

        // A PFX payload would add its own bytes; the material is exactly the framed policy plus the DER.
        Assert.Equal(4 + Policy.Length + CertificateDer.Length, material.Length);
        Assert.Equal(Policy.Length, BinaryPrimitives.ReadInt32BigEndian(material));
        Assert.Equal(Policy, material[4..(4 + Policy.Length)]);
        Assert.Equal(CertificateDer, material[(4 + Policy.Length)..]);
    }

    [Fact]
    public void Signature_material_changes_when_the_certificate_changes()
    {
        var original = CertificatePolicyCanonicalizer.ComposeSignatureMaterial(Policy, CertificateDer);
        var altered = CertificatePolicyCanonicalizer.ComposeSignatureMaterial(
            Policy,
            [0x30, 0x82, 0x01, 0x0A, 0x02, 0x01, 0x06]);

        Assert.NotEqual(original, altered);
    }

    [Fact]
    public void Signature_material_changes_when_the_policy_changes()
    {
        var original = CertificatePolicyCanonicalizer.ComposeSignatureMaterial(Policy, CertificateDer);
        var altered = CertificatePolicyCanonicalizer.ComposeSignatureMaterial(
            Encoding.UTF8.GetBytes("EC|False|True|CN=KeyVaultSync"),
            CertificateDer);

        Assert.NotEqual(original, altered);
    }

    [Fact]
    public void Length_prefix_prevents_policy_and_certificate_boundary_collisions()
    {
        var first = CertificatePolicyCanonicalizer.ComposeSignatureMaterial([0x01, 0x02], [0x03, 0x04]);
        var second = CertificatePolicyCanonicalizer.ComposeSignatureMaterial([0x01], [0x02, 0x03, 0x04]);

        Assert.NotEqual(first, second);
    }
}
