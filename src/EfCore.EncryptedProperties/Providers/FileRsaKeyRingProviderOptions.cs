namespace EfCore.EncryptedProperties.Providers;

public sealed class FileRsaKeyRingProviderOptions
{
    private readonly List<FileRsaKeyRingProviderKey> _keys = new();

    public string? CurrentKeyId { get; set; }
    public int KeySizeInBits { get; set; } = 2048;
    public IReadOnlyList<FileRsaKeyRingProviderKey> Keys => _keys;

    public FileRsaKeyRingProviderOptions AddKey(string keyId, string filePath)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(keyId));

        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("RSA key file path cannot be null or whitespace.", nameof(filePath));

        _keys.Add(new FileRsaKeyRingProviderKey(keyId, filePath));
        return this;
    }
}

public sealed record FileRsaKeyRingProviderKey(string KeyId, string FilePath);
