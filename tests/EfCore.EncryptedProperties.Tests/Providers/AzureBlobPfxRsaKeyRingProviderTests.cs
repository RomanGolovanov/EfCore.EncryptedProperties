using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EfCore.EncryptedProperties.Providers;
using EfCore.EncryptedProperties.Tests.TestDoubles;

namespace EfCore.EncryptedProperties.Tests.Providers;

public sealed class AzureBlobPfxRsaKeyRingProviderTests
{
    [Fact]
    public async Task WrapUnwrap_RoundTrip_LoadsCurrentPfxBlob()
    {
        var container = new InMemoryBlobContainerClient();
        container.SetBlob("certs/rsa-v1.pfx", CreatePfxBytes("test-password"));
        var provider = CreateProvider(
            container,
            "rsa-v1",
            "certs",
            ("rsa-v1", "rsa-v1.pfx", "test-password"));
        var plaintext = RandomNumberGenerator.GetBytes(32);

        var wrapped = await provider.WrapKeyAsync(plaintext);
        var unwrapped = await provider.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
        Assert.Equal("rsa-v1", wrapped.RsaKeyId);
        Assert.Equal("RSA-OAEP-256", wrapped.Algorithm);
    }

    [Fact]
    public async Task UnwrapKeyAsync_UnwrapsHistoricalPfxBlob()
    {
        var container = new InMemoryBlobContainerClient();
        container.SetBlob("rsa-v1.pfx", CreatePfxBytes("old-password"));
        container.SetBlob("rsa-v2.pfx", CreatePfxBytes("current-password"));
        var oldProvider = CreateProvider(
            container,
            "rsa-v1",
            null,
            ("rsa-v1", "rsa-v1.pfx", "old-password"));
        var rotatingProvider = CreateProvider(
            container,
            "rsa-v2",
            null,
            ("rsa-v1", "rsa-v1.pfx", "old-password"),
            ("rsa-v2", "rsa-v2.pfx", "current-password"));
        var plaintext = RandomNumberGenerator.GetBytes(32);
        var wrappedWithOldKey = await oldProvider.WrapKeyAsync(plaintext);

        var unwrapped = await rotatingProvider.UnwrapKeyAsync(
            wrappedWithOldKey.Ciphertext,
            wrappedWithOldKey.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
    }

    [Fact]
    public async Task WrapKeyAsync_MissingCurrentPfxBlob_Throws()
    {
        var container = new InMemoryBlobContainerClient();
        var provider = CreateProvider(
            container,
            "rsa-v1",
            null,
            ("rsa-v1", "missing.pfx", "test-password"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32)).AsTask());

        Assert.Contains("was not found", ex.Message);
        Assert.Contains("missing.pfx", ex.Message);
    }

    [Fact]
    public async Task WrapKeyAsync_WrongPassword_Throws()
    {
        var container = new InMemoryBlobContainerClient();
        container.SetBlob("rsa-v1.pfx", CreatePfxBytes("correct-password"));
        var provider = CreateProvider(
            container,
            "rsa-v1",
            null,
            ("rsa-v1", "rsa-v1.pfx", "wrong-password"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32)).AsTask());

        Assert.Contains("could not be loaded", ex.Message);
    }

    [Fact]
    public void Constructor_DuplicateKeyId_Throws()
    {
        var container = new InMemoryBlobContainerClient();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CreateProvider(
                container,
                "rsa-v1",
                null,
                ("rsa-v1", "a.pfx", null),
                ("rsa-v1", "b.pfx", null)));

        Assert.Contains("configured more than once", ex.Message);
    }

    [Fact]
    public void Constructor_CurrentKeyNotConfigured_Throws()
    {
        var container = new InMemoryBlobContainerClient();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CreateProvider(container, "rsa-v2", null, ("rsa-v1", "rsa-v1.pfx", null)));

        Assert.Contains("Current RSA key 'rsa-v2'", ex.Message);
    }

    [Fact]
    public async Task WrapKeyAsync_NormalizesBlobPrefixAndBlobName()
    {
        var container = new InMemoryBlobContainerClient();
        container.SetBlob("tenant-a/nested/rsa-v1.pfx", CreatePfxBytes("test-password"));
        var provider = CreateProvider(
            container,
            "rsa-v1",
            "\\tenant-a\\",
            ("rsa-v1", "/nested\\rsa-v1.pfx", "test-password"));

        await provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32));

        Assert.Equal(1, container.GetDownloadCount("tenant-a/nested/rsa-v1.pfx"));
    }

    [Fact]
    public async Task WrapKeyAsync_CachesLoadedPfxBlob()
    {
        var container = new InMemoryBlobContainerClient();
        container.SetBlob("rsa-v1.pfx", CreatePfxBytes("test-password"));
        var provider = CreateProvider(
            container,
            "rsa-v1",
            null,
            ("rsa-v1", "rsa-v1.pfx", "test-password"));

        await provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32));
        await provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32));

        Assert.Equal(1, container.GetDownloadCount("rsa-v1.pfx"));
    }

    private static AzureBlobPfxRsaKeyRingProvider CreateProvider(
        InMemoryBlobContainerClient container,
        string currentKeyId,
        string? blobPrefix,
        params (string KeyId, string BlobName, string? Password)[] keys)
    {
        var options = new AzureBlobPfxRsaKeyRingProviderOptions
        {
            ContainerClient = container,
            CurrentKeyId = currentKeyId,
            BlobPrefix = blobPrefix
        };

        foreach (var key in keys)
            options.AddKey(key.KeyId, key.BlobName, key.Password);

        return new AzureBlobPfxRsaKeyRingProvider(options);
    }

    private static byte[] CreatePfxBytes(string password)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=EfCore.EncryptedProperties.Tests",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment,
                critical: false));

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        return certificate.Export(X509ContentType.Pfx, password);
    }
}
