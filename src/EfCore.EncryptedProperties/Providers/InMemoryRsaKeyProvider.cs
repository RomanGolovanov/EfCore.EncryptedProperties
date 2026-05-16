using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.Providers;

public sealed class InMemoryRsaKeyProvider : IRsaKeyProvider
{
    private readonly RSA _rsa;

    public InMemoryRsaKeyProvider(RSA rsa, string keyId)
    {
        _rsa = rsa;
        KeyId = keyId;
    }

    public string KeyId { get; }
    public string Algorithm => "RSA-OAEP-256";

    public ValueTask<RsaKeyWrapResult> WrapKeyAsync(byte[] plaintext, CancellationToken cancellationToken = default)
    {
        var result = _rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<RsaKeyWrapResult>(new RsaKeyWrapResult(result, KeyId, Algorithm));
    }

    public ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default)
    {
        if (!string.Equals(rsaKeyId, KeyId, StringComparison.Ordinal))
            throw new InvalidOperationException($"RSA key '{rsaKeyId}' does not match configured key '{KeyId}'.");

        var result = _rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<byte[]>(result);
    }
}
