using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.Providers;

public sealed class FilePfxRsaKeyProvider : IRsaKeyProvider
{
    private const string AlgorithmName = "RSA-OAEP-256";
    private readonly PfxRsaKeyMaterial _key;

    public FilePfxRsaKeyProvider(
        string filePath,
        string keyId,
        string? password = null,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.EphemeralKeySet)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("PFX RSA key file path cannot be null or whitespace.", nameof(filePath));

        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(keyId));

        KeyId = keyId;
        _key = PfxRsaKeyMaterial.LoadFromFile(filePath, password, keyStorageFlags);
    }

    public string KeyId { get; }
    public string Algorithm => AlgorithmName;

    public ValueTask<RsaKeyWrapResult> WrapKeyAsync(
        byte[] plaintext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        cancellationToken.ThrowIfCancellationRequested();

        var ciphertext = _key.Rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<RsaKeyWrapResult>(new RsaKeyWrapResult(ciphertext, KeyId, Algorithm));
    }

    public ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (!string.Equals(rsaKeyId, KeyId, StringComparison.Ordinal))
            throw new InvalidOperationException($"RSA key '{rsaKeyId}' does not match configured key '{KeyId}'.");

        cancellationToken.ThrowIfCancellationRequested();

        var plaintext = _key.Rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<byte[]>(plaintext);
    }
}
