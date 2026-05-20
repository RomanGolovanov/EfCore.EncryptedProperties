using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EfCore.EncryptedProperties.Providers;

internal sealed class PfxRsaKeyMaterial
{
    private PfxRsaKeyMaterial(X509Certificate2 certificate, RSA rsa)
    {
        Certificate = certificate;
        Rsa = rsa;
    }

    public X509Certificate2 Certificate { get; }
    public RSA Rsa { get; }

    public static PfxRsaKeyMaterial LoadFromFile(
        string filePath,
        string? password,
        X509KeyStorageFlags keyStorageFlags)
    {
        if (!File.Exists(filePath))
            throw new InvalidOperationException($"PFX RSA key file '{filePath}' was not found.");

        try
        {
#if NET9_0_OR_GREATER
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                filePath,
                password,
                keyStorageFlags);
#else
            var certificate = new X509Certificate2(
                filePath,
                password,
                keyStorageFlags);
#endif

            return FromCertificate(certificate, filePath);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException($"PFX RSA key file '{filePath}' could not be loaded.", ex);
        }
    }

    public static PfxRsaKeyMaterial LoadFromBytes(
        byte[] bytes,
        string source,
        string? password,
        X509KeyStorageFlags keyStorageFlags)
    {
        try
        {
#if NET9_0_OR_GREATER
            var certificate = X509CertificateLoader.LoadPkcs12(
                bytes,
                password,
                keyStorageFlags);
#else
            var certificate = new X509Certificate2(
                bytes,
                password,
                keyStorageFlags);
#endif

            return FromCertificate(certificate, source);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException($"PFX RSA key '{source}' could not be loaded.", ex);
        }
    }

    private static PfxRsaKeyMaterial FromCertificate(X509Certificate2 certificate, string source)
    {
        if (!certificate.HasPrivateKey)
            throw new InvalidOperationException($"PFX RSA key '{source}' does not contain a private key.");

        var rsa = certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException($"PFX RSA key '{source}' does not contain an RSA private key.");

        return new PfxRsaKeyMaterial(certificate, rsa);
    }
}
