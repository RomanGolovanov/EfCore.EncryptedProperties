using System.Security.Cryptography.X509Certificates;
using Azure.Storage.Blobs;

namespace EfCore.EncryptedProperties.Providers;

public sealed class AzureBlobPfxRsaKeyRingProviderOptions
{
    private readonly List<AzureBlobPfxRsaKeyRingProviderKey> _keys = new();

    public BlobContainerClient? ContainerClient { get; set; }
    public string? BlobPrefix { get; set; }
    public string? CurrentKeyId { get; set; }
    public X509KeyStorageFlags KeyStorageFlags { get; set; } = X509KeyStorageFlags.EphemeralKeySet;
    public IReadOnlyList<AzureBlobPfxRsaKeyRingProviderKey> Keys => _keys;

    public AzureBlobPfxRsaKeyRingProviderOptions AddKey(
        string keyId,
        string blobName,
        string? password = null)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(keyId));

        if (string.IsNullOrWhiteSpace(blobName))
            throw new ArgumentException("PFX RSA key blob name cannot be null or whitespace.", nameof(blobName));

        _keys.Add(new AzureBlobPfxRsaKeyRingProviderKey(keyId, blobName, password));
        return this;
    }
}

public sealed record AzureBlobPfxRsaKeyRingProviderKey(
    string KeyId,
    string BlobName,
    string? Password);
