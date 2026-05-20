using Azure.Storage.Blobs;

namespace EfCore.EncryptedProperties.Providers;

public sealed class AzureBlobRsaKeyRingProviderOptions
{
    private readonly List<AzureBlobRsaKeyRingProviderKey> _keys = new();

    public BlobContainerClient? ContainerClient { get; set; }
    public string? BlobPrefix { get; set; }
    public string? CurrentKeyId { get; set; }
    public int KeySizeInBits { get; set; } = 2048;
    public bool CreateContainerIfNotExists { get; set; }
    public IReadOnlyList<AzureBlobRsaKeyRingProviderKey> Keys => _keys;

    public AzureBlobRsaKeyRingProviderOptions AddKey(string keyId, string blobName)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(keyId));

        if (string.IsNullOrWhiteSpace(blobName))
            throw new ArgumentException("RSA key blob name cannot be null or whitespace.", nameof(blobName));

        _keys.Add(new AzureBlobRsaKeyRingProviderKey(keyId, blobName));
        return this;
    }
}

public sealed record AzureBlobRsaKeyRingProviderKey(string KeyId, string BlobName);
