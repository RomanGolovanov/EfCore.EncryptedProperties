using EfCore.EncryptedProperties.Providers;

namespace EfCore.EncryptedProperties.Tests.Providers;

public sealed class FileRsaKeyProviderTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);

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
}
