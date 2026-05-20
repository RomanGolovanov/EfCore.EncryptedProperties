using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EfCore.EncryptedProperties.Providers;

namespace EfCore.EncryptedProperties.Tests.Providers;

public sealed class X509StoreRsaKeyProviderTests : IDisposable
{
    private readonly List<X509Certificate2> _createdCertificates = new();
    private readonly List<string> _thumbprints = new();

    [Fact]
    public void Constructor_NormalizesCurrentCertificateThumbprint()
    {
        var provider = new X509StoreRsaKeyProvider(
            new X509StoreRsaKeyProviderOptions
            {
                CurrentCertificateThumbprint = "00:11 22-33 44:55 66-77 88:99 AA-BB CC:DD EE-FF 00:11 22-33"
            });

        Assert.Equal(
            "x509store:CurrentUser:My:00112233445566778899AABBCCDDEEFF00112233",
            provider.KeyId);
    }

    [Fact]
    public void Constructor_InvalidCurrentCertificateThumbprint_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new X509StoreRsaKeyProvider(
                new X509StoreRsaKeyProviderOptions
                {
                    CurrentCertificateThumbprint = "001122"
                }));

        Assert.Contains("SHA-1 thumbprint", ex.Message);
    }

    public void Dispose()
    {
        RemoveCreatedCertificates();

        foreach (var certificate in _createdCertificates)
            certificate.Dispose();
    }

    [Fact]
    public async Task WrapUnwrap_RoundTrip()
    {
        var certificate = AddCertificate();
        var provider = CreateProvider(certificate);
        var plaintext = RandomNumberGenerator.GetBytes(32);

        var wrapped = await provider.WrapKeyAsync(plaintext);
        var unwrapped = await provider.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
        Assert.Equal("RSA-OAEP-256", wrapped.Algorithm);
        Assert.Equal(
            $"x509store:CurrentUser:My:{certificate.Thumbprint}",
            wrapped.RsaKeyId);
    }

    [Fact]
    public async Task Rotation_UnwrapsWithStoredHistoricalCertificateId()
    {
        var oldCertificate = AddCertificate();
        var newCertificate = AddCertificate();
        var oldProvider = CreateProvider(oldCertificate);
        var newProvider = CreateProvider(newCertificate);
        var plaintext = RandomNumberGenerator.GetBytes(32);

        var wrapped = await oldProvider.WrapKeyAsync(plaintext);
        var unwrapped = await newProvider.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);
        var newWrapped = await newProvider.WrapKeyAsync(plaintext);

        Assert.Equal(plaintext, unwrapped);
        Assert.Equal(
            $"x509store:CurrentUser:My:{oldCertificate.Thumbprint}",
            wrapped.RsaKeyId);
        Assert.Equal(
            $"x509store:CurrentUser:My:{newCertificate.Thumbprint}",
            newWrapped.RsaKeyId);
    }

    [Fact]
    public async Task WrapKeyAsync_MissingCurrentCertificate_Throws()
    {
        var provider = new X509StoreRsaKeyProvider(
            new X509StoreRsaKeyProviderOptions
            {
                CurrentCertificateThumbprint = "00112233445566778899AABBCCDDEEFF00112233"
            });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32)).AsTask());

        Assert.Contains("was not found", ex.Message);
        Assert.Contains("CurrentUser\\My", ex.Message);
    }

    [Fact]
    public async Task WrapKeyAsync_CurrentCertificateWithoutPrivateKey_Throws()
    {
        var certificate = AddCertificate(includePrivateKey: false);
        var provider = CreateProvider(certificate);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32)).AsTask());

        Assert.Contains("does not have an RSA private key", ex.Message);
    }

    [Fact]
    public async Task WrapKeyAsync_ExpiredCurrentCertificate_Throws()
    {
        var certificate = AddCertificate(
            notBefore: DateTimeOffset.UtcNow.AddDays(-10),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var provider = CreateProvider(certificate);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32)).AsTask());

        Assert.Contains("is not valid at the current time", ex.Message);
    }

    [Fact]
    public async Task UnwrapKeyAsync_ExpiredHistoricalCertificate_Succeeds()
    {
        var certificate = AddCertificate(
            notBefore: DateTimeOffset.UtcNow.AddDays(-10),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var wrappingProvider = CreateProvider(certificate, validateCurrentCertificateTime: false);
        var decryptProvider = CreateProvider(certificate);
        var plaintext = RandomNumberGenerator.GetBytes(32);

        var wrapped = await wrappingProvider.WrapKeyAsync(plaintext);
        var unwrapped = await decryptProvider.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
    }

    private X509StoreRsaKeyProvider CreateProvider(
        X509Certificate2 certificate,
        bool validateCurrentCertificateTime = true)
    {
        return new X509StoreRsaKeyProvider(
            new X509StoreRsaKeyProviderOptions
            {
                CurrentCertificateThumbprint = certificate.Thumbprint,
                ValidateCurrentCertificateTime = validateCurrentCertificateTime
            });
    }

    private X509Certificate2 AddCertificate(
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool includePrivateKey = true)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN=EfCore.EncryptedProperties Test {Guid.NewGuid():N}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment,
                critical: true));

        using var certificate = request.CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-5),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(1));

        var storeCertificate = LoadStoreCertificate(certificate, includePrivateKey);

        AddToStore(storeCertificate);
        _createdCertificates.Add(storeCertificate);
        _thumbprints.Add(storeCertificate.Thumbprint!);
        return storeCertificate;
    }

    private static X509Certificate2 LoadStoreCertificate(
        X509Certificate2 certificate,
        bool includePrivateKey)
    {
        if (includePrivateKey)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12(
                certificate.Export(X509ContentType.Pfx, string.Empty),
                string.Empty,
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet,
                Pkcs12LoaderLimits.Defaults);
#else
            return new X509Certificate2(
                certificate.Export(X509ContentType.Pfx, string.Empty),
                string.Empty,
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);
#endif
        }

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
#else
        return new X509Certificate2(certificate.Export(X509ContentType.Cert));
#endif
    }

    private static void AddToStore(X509Certificate2 certificate)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
    }

    private void RemoveCreatedCertificates()
    {
        if (_thumbprints.Count == 0)
            return;

        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            foreach (var thumbprint in _thumbprints.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var matches = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    validOnly: false);
                store.RemoveRange(matches);
            }
        }
        catch (CryptographicException)
        {
            // Best-effort cleanup; the test failure that caused this matters more.
        }
    }
}
