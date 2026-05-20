using System.Security.Cryptography;
using EfCore.EncryptedProperties.Providers;
using EfCore.EncryptedProperties.Tests.TestDoubles;

namespace EfCore.EncryptedProperties.Tests.Providers;

public sealed class AzureBlobRsaKeyRingProviderTests
{
    [Fact]
    public async Task WrapUnwrap_RoundTrip_LoadsCurrentPemBlob()
    {
        var container = new InMemoryBlobContainerClient();
        using var rsa = RSA.Create(2048);
        container.SetBlob("keys/rsa-v1.pem", rsa.ExportRSAPrivateKeyPem());
        var provider = CreateProvider(container, "rsa-v1", "keys", ("rsa-v1", "rsa-v1.pem"));
        var plaintext = RandomNumberGenerator.GetBytes(32);

        var wrapped = await provider.WrapKeyAsync(plaintext);
        var unwrapped = await provider.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
        Assert.Equal("rsa-v1", wrapped.RsaKeyId);
        Assert.Equal("RSA-OAEP-256", wrapped.Algorithm);
    }

    [Fact]
    public async Task MissingCurrentPemBlob_IsCreatedAndPersisted()
    {
        var container = new InMemoryBlobContainerClient();
        var provider = CreateProvider(container, "rsa-v1", null, ("rsa-v1", "rsa-v1.pem"));
        var plaintext = RandomNumberGenerator.GetBytes(32);

        var wrapped = await provider.WrapKeyAsync(plaintext);
        var reloadedProvider = CreateProvider(container, "rsa-v1", null, ("rsa-v1", "rsa-v1.pem"));
        var unwrapped = await reloadedProvider.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);

        Assert.True(container.ContainsBlob("rsa-v1.pem"));
        Assert.Contains("RSA PRIVATE KEY", container.GetBlobText("rsa-v1.pem"));
        Assert.Equal(plaintext, unwrapped);
    }

    [Fact]
    public async Task UnwrapKeyAsync_UnwrapsHistoricalPemBlob()
    {
        var container = new InMemoryBlobContainerClient();
        using var oldRsa = RSA.Create(2048);
        using var currentRsa = RSA.Create(2048);
        container.SetBlob("rsa-v1.pem", oldRsa.ExportRSAPrivateKeyPem());
        container.SetBlob("rsa-v2.pem", currentRsa.ExportRSAPrivateKeyPem());
        var oldProvider = CreateProvider(container, "rsa-v1", null, ("rsa-v1", "rsa-v1.pem"));
        var rotatingProvider = CreateProvider(
            container,
            "rsa-v2",
            null,
            ("rsa-v1", "rsa-v1.pem"),
            ("rsa-v2", "rsa-v2.pem"));
        var plaintext = RandomNumberGenerator.GetBytes(32);
        var wrappedWithOldKey = await oldProvider.WrapKeyAsync(plaintext);

        var unwrapped = await rotatingProvider.UnwrapKeyAsync(
            wrappedWithOldKey.Ciphertext,
            wrappedWithOldKey.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
    }

    [Fact]
    public async Task UnwrapKeyAsync_UnknownKeyId_Throws()
    {
        var container = new InMemoryBlobContainerClient();
        using var rsa = RSA.Create(2048);
        container.SetBlob("rsa-v1.pem", rsa.ExportRSAPrivateKeyPem());
        var provider = CreateProvider(container, "rsa-v1", null, ("rsa-v1", "rsa-v1.pem"));
        var wrapped = await provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.UnwrapKeyAsync(wrapped.Ciphertext, "rsa-missing").AsTask());

        Assert.Contains("rsa-missing", ex.Message);
        Assert.Contains("Azure Blob key ring", ex.Message);
    }

    [Fact]
    public async Task UnwrapKeyAsync_MissingHistoricalPemBlob_Throws()
    {
        var container = new InMemoryBlobContainerClient();
        using var currentRsa = RSA.Create(2048);
        container.SetBlob("rsa-v2.pem", currentRsa.ExportRSAPrivateKeyPem());
        var provider = CreateProvider(
            container,
            "rsa-v2",
            null,
            ("rsa-v1", "rsa-v1.pem"),
            ("rsa-v2", "rsa-v2.pem"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.UnwrapKeyAsync(RandomNumberGenerator.GetBytes(256), "rsa-v1").AsTask());

        Assert.Contains("historical key 'rsa-v1'", ex.Message);
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
                ("rsa-v1", "a.pem"),
                ("rsa-v1", "b.pem")));

        Assert.Contains("configured more than once", ex.Message);
    }

    [Fact]
    public void Constructor_CurrentKeyNotConfigured_Throws()
    {
        var container = new InMemoryBlobContainerClient();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CreateProvider(container, "rsa-v2", null, ("rsa-v1", "rsa-v1.pem")));

        Assert.Contains("Current RSA key 'rsa-v2'", ex.Message);
    }

    [Fact]
    public async Task WrapKeyAsync_NormalizesBlobPrefixAndBlobName()
    {
        var container = new InMemoryBlobContainerClient();
        var provider = CreateProvider(
            container,
            "rsa-v1",
            "\\tenant-a\\",
            ("rsa-v1", "/nested\\rsa-v1.pem"));

        await provider.WrapKeyAsync(RandomNumberGenerator.GetBytes(32));

        Assert.True(container.ContainsBlob("tenant-a/nested/rsa-v1.pem"));
    }

    [Fact]
    public async Task WrapKeyAsync_WhenConcurrentCurrentUploadWins_DownloadsPersistedKey()
    {
        var container = new InMemoryBlobContainerClient();
        using var winningRsa = RSA.Create(2048);
        var winningPem = winningRsa.ExportRSAPrivateKeyPem();
        container.QueueUploadFailure(
            "keys/rsa-v1.pem",
            status: 409,
            beforeThrow: () => container.SetBlob("keys/rsa-v1.pem", winningPem));
        var provider = CreateProvider(container, "rsa-v1", "keys", ("rsa-v1", "rsa-v1.pem"));
        var plaintext = RandomNumberGenerator.GetBytes(32);

        var wrapped = await provider.WrapKeyAsync(plaintext);
        var unwrapped = winningRsa.Decrypt(wrapped.Ciphertext, RSAEncryptionPadding.OaepSHA256);

        Assert.Equal(plaintext, unwrapped);
    }

    private static AzureBlobRsaKeyRingProvider CreateProvider(
        InMemoryBlobContainerClient container,
        string currentKeyId,
        string? blobPrefix,
        params (string KeyId, string BlobName)[] keys)
    {
        var options = new AzureBlobRsaKeyRingProviderOptions
        {
            ContainerClient = container,
            CurrentKeyId = currentKeyId,
            BlobPrefix = blobPrefix,
            CreateContainerIfNotExists = true
        };

        foreach (var key in keys)
            options.AddKey(key.KeyId, key.BlobName);

        return new AzureBlobRsaKeyRingProvider(options);
    }
}
