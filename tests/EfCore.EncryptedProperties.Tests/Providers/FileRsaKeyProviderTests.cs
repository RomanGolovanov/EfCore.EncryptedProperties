using EfCore.EncryptedProperties.Providers;

namespace EfCore.EncryptedProperties.Tests.Providers;

public sealed class FileRsaKeyProviderTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    [Fact]
    public async Task WrapUnwrap_RoundTrip()
    {
        var path = Path.Combine(_tempDir, "key.pem");
        var provider = new FileRsaKeyProvider(path, "test-key");
        var plaintext = new byte[32];
        Random.Shared.NextBytes(plaintext);

        var wrapped = await provider.WrapKeyAsync(plaintext);
        var unwrapped = await provider.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
    }

    [Fact]
    public async Task CreatesKeyFile_OnFirstUse()
    {
        var path = Path.Combine(_tempDir, "key.pem");
        _ = new FileRsaKeyProvider(path, "test-key");

        Assert.True(File.Exists(path));
        var pem = await File.ReadAllTextAsync(path);
        Assert.Contains("RSA PRIVATE KEY", pem);
    }

    [Fact]
    public async Task LoadsExistingKeyFile_UnwrapSucceeds()
    {
        var path = Path.Combine(_tempDir, "key.pem");

        // First provider generates and persists the key
        var first = new FileRsaKeyProvider(path, "test-key");
        var plaintext = new byte[32];
        Random.Shared.NextBytes(plaintext);
        var wrapped = await first.WrapKeyAsync(plaintext);

        // Second provider loads the same key from file
        var second = new FileRsaKeyProvider(path, "test-key");
        var unwrapped = await second.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
    }

    [Fact]
    public async Task KeyRing_WrapUnwrap_RoundTrip()
    {
        var path = Path.Combine(_tempDir, "rsa-v1.pem");
        var options = new FileRsaKeyRingProviderOptions
        {
            CurrentKeyId = "rsa-v1"
        };
        options.AddKey("rsa-v1", path);

        var provider = new FileRsaKeyRingProvider(options);
        var plaintext = new byte[32];
        Random.Shared.NextBytes(plaintext);

        var wrapped = await provider.WrapKeyAsync(plaintext);
        var unwrapped = await provider.UnwrapKeyAsync(wrapped.Ciphertext, wrapped.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
    }

    [Fact]
    public async Task KeyRing_UnwrapsHistoricalKey()
    {
        var oldPath = Path.Combine(_tempDir, "rsa-v1.pem");
        var currentPath = Path.Combine(_tempDir, "rsa-v2.pem");
        var oldProvider = new FileRsaKeyProvider(oldPath, "rsa-v1");
        var plaintext = new byte[32];
        Random.Shared.NextBytes(plaintext);
        var wrappedWithOldKey = await oldProvider.WrapKeyAsync(plaintext);

        var options = new FileRsaKeyRingProviderOptions
        {
            CurrentKeyId = "rsa-v2"
        };
        options.AddKey("rsa-v1", oldPath);
        options.AddKey("rsa-v2", currentPath);

        var provider = new FileRsaKeyRingProvider(options);
        var unwrapped = await provider.UnwrapKeyAsync(
            wrappedWithOldKey.Ciphertext,
            wrappedWithOldKey.RsaKeyId);

        Assert.Equal(plaintext, unwrapped);
    }

    [Fact]
    public async Task KeyRing_WrapKeyAsync_ReturnsCurrentKeyId()
    {
        var oldPath = Path.Combine(_tempDir, "rsa-v1.pem");
        var currentPath = Path.Combine(_tempDir, "rsa-v2.pem");
        _ = new FileRsaKeyProvider(oldPath, "rsa-v1");
        var options = new FileRsaKeyRingProviderOptions
        {
            CurrentKeyId = "rsa-v2"
        };
        options.AddKey("rsa-v1", oldPath);
        options.AddKey("rsa-v2", currentPath);
        var provider = new FileRsaKeyRingProvider(options);
        var plaintext = new byte[32];
        Random.Shared.NextBytes(plaintext);

        var wrapped = await provider.WrapKeyAsync(plaintext);

        Assert.Equal("rsa-v2", wrapped.RsaKeyId);
    }

    [Fact]
    public async Task KeyRing_CreatesCurrentKeyFile_OnFirstUse()
    {
        var currentPath = Path.Combine(_tempDir, "rsa-v2.pem");
        var options = new FileRsaKeyRingProviderOptions
        {
            CurrentKeyId = "rsa-v2"
        };
        options.AddKey("rsa-v2", currentPath);

        _ = new FileRsaKeyRingProvider(options);

        Assert.True(File.Exists(currentPath));
        var pem = await File.ReadAllTextAsync(currentPath);
        Assert.Contains("RSA PRIVATE KEY", pem);
    }

    [Fact]
    public void KeyRing_MissingHistoricalKeyFile_Throws()
    {
        var currentPath = Path.Combine(_tempDir, "rsa-v2.pem");
        var missingHistoricalPath = Path.Combine(_tempDir, "rsa-v1.pem");
        _ = new FileRsaKeyProvider(currentPath, "rsa-v2");
        var options = new FileRsaKeyRingProviderOptions
        {
            CurrentKeyId = "rsa-v2"
        };
        options.AddKey("rsa-v2", currentPath);
        options.AddKey("rsa-v1", missingHistoricalPath);

        var ex = Assert.Throws<InvalidOperationException>(() => new FileRsaKeyRingProvider(options));

        Assert.Contains("historical key 'rsa-v1'", ex.Message);
    }

    [Fact]
    public void KeyRing_DuplicateKeyId_Throws()
    {
        var path1 = Path.Combine(_tempDir, "rsa-v1-a.pem");
        var path2 = Path.Combine(_tempDir, "rsa-v1-b.pem");
        var options = new FileRsaKeyRingProviderOptions
        {
            CurrentKeyId = "rsa-v1"
        };
        options.AddKey("rsa-v1", path1);
        options.AddKey("rsa-v1", path2);

        var ex = Assert.Throws<InvalidOperationException>(() => new FileRsaKeyRingProvider(options));

        Assert.Contains("configured more than once", ex.Message);
    }

    [Fact]
    public async Task KeyRing_UnknownUnwrapKeyId_Throws()
    {
        var currentPath = Path.Combine(_tempDir, "rsa-v1.pem");
        var options = new FileRsaKeyRingProviderOptions
        {
            CurrentKeyId = "rsa-v1"
        };
        options.AddKey("rsa-v1", currentPath);
        var provider = new FileRsaKeyRingProvider(options);
        var plaintext = new byte[32];
        Random.Shared.NextBytes(plaintext);
        var wrapped = await provider.WrapKeyAsync(plaintext);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.UnwrapKeyAsync(wrapped.Ciphertext, "rsa-missing").AsTask());

        Assert.Contains("rsa-missing", ex.Message);
    }
}
