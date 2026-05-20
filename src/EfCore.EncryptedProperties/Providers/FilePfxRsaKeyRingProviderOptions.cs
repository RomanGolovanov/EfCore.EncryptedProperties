using System.Security.Cryptography.X509Certificates;

namespace EfCore.EncryptedProperties.Providers;

public sealed class FilePfxRsaKeyRingProviderOptions
{
    private readonly List<FilePfxRsaKeyRingProviderKey> _keys = new();

    public string? CurrentKeyId { get; set; }
    public X509KeyStorageFlags KeyStorageFlags { get; set; } = X509KeyStorageFlags.EphemeralKeySet;
    public IReadOnlyList<FilePfxRsaKeyRingProviderKey> Keys => _keys;

    public FilePfxRsaKeyRingProviderOptions AddKey(
        string keyId,
        string filePath,
        string? password = null)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(keyId));

        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("PFX RSA key file path cannot be null or whitespace.", nameof(filePath));

        _keys.Add(new FilePfxRsaKeyRingProviderKey(keyId, filePath, password));
        return this;
    }
}

public sealed record FilePfxRsaKeyRingProviderKey(
    string KeyId,
    string FilePath,
    string? Password);
