using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Providers;

namespace EfCore.EncryptedProperties.Testing;

public sealed class FakeRsaKeyProvider : IRsaKeyProvider
{
    private readonly InMemoryRsaKeyProvider _inner;

    public FakeRsaKeyProvider() : this("test-rsa-key-v1")
    {
    }

    public FakeRsaKeyProvider(string keyId)
    {
        _inner = new InMemoryRsaKeyProvider(RSA.Create(2048), keyId);
    }

    public string KeyId => _inner.KeyId;
    public string Algorithm => _inner.Algorithm;

    public ValueTask<RsaKeyWrapResult> WrapKeyAsync(byte[] plaintext, CancellationToken cancellationToken = default)
        => _inner.WrapKeyAsync(plaintext, cancellationToken);

    public ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default)
        => _inner.UnwrapKeyAsync(ciphertext, rsaKeyId, cancellationToken);
}
