using Azure.Core;
using EfCore.EncryptedProperties.Providers;

namespace EfCore.EncryptedProperties.Tests.Providers;

public sealed class AzureKeyVaultRsaKeyProviderTests
{
    [Fact]
    public void Constructor_UsesKeyNameAsCurrentKeyId()
    {
        var provider = new AzureKeyVaultRsaKeyProvider(
            new Uri("https://vault.example/keys/customer-key"),
            new ThrowingTokenCredential());

        Assert.Equal("customer-key", provider.KeyId);
        Assert.Equal("RSA-OAEP-256", provider.Algorithm);
    }

    [Fact]
    public void Constructor_AcceptsVersionedKeyUri()
    {
        var provider = new AzureKeyVaultRsaKeyProvider(
            new Uri("https://vault.example/keys/customer-key/1234567890abcdef"),
            new ThrowingTokenCredential());

        Assert.Equal("customer-key", provider.KeyId);
    }

    [Fact]
    public void Constructor_InvalidKeyUri_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new AzureKeyVaultRsaKeyProvider(
                new Uri("https://vault.example/secrets/customer-key"),
                new ThrowingTokenCredential()));

        Assert.Contains("Key Vault key URI", ex.Message);
    }

    [Fact]
    public void Constructor_NullArguments_Throw()
    {
        var credential = new ThrowingTokenCredential();

        Assert.Throws<ArgumentNullException>(() =>
            new AzureKeyVaultRsaKeyProvider(null!, credential));
        Assert.Throws<ArgumentNullException>(() =>
            new AzureKeyVaultRsaKeyProvider(new Uri("https://vault.example/keys/customer-key"), null!));
    }

    [Fact]
    public async Task UnwrapKeyAsync_BlankRsaKeyId_ThrowsBeforeCallingAzure()
    {
        var provider = new AzureKeyVaultRsaKeyProvider(
            new Uri("https://vault.example/keys/customer-key"),
            new ThrowingTokenCredential());

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            provider.UnwrapKeyAsync(Array.Empty<byte>(), " ").AsTask());

        Assert.Contains("RSA key ID", ex.Message);
    }

    private sealed class ThrowingTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken)
            => throw new NotSupportedException("Tests should not call Azure.");

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken)
            => throw new NotSupportedException("Tests should not call Azure.");
    }
}
