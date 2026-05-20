using System.Security.Cryptography;
using Azure;
using Azure.Storage.Blobs;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.KeyManagement;

namespace EfCore.EncryptedProperties.Providers;

public sealed class AzureBlobPfxRsaKeyRingProvider : IRsaKeyProvider
{
    private const string AlgorithmName = "RSA-OAEP-256";

    private readonly BlobContainerClient _containerClient;
    private readonly Dictionary<string, AzureBlobPfxRsaKeyRingProviderKey> _configuredKeys;
    private readonly Dictionary<string, PfxRsaKeyMaterial> _keys = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private readonly string _blobPrefix;

    public AzureBlobPfxRsaKeyRingProvider(AzureBlobPfxRsaKeyRingProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        KeyId = ValidateOptions(options);
        _containerClient = options.ContainerClient!;
        _blobPrefix = AzureBlobKeyChainStorage.NormalizeBlobPrefix(options.BlobPrefix);
        KeyStorageFlags = options.KeyStorageFlags;
        _configuredKeys = options.Keys.ToDictionary(
            key => key.KeyId,
            key => key with { BlobName = NormalizeBlobName(key.BlobName) },
            StringComparer.Ordinal);
    }

    public string KeyId { get; }
    public string Algorithm => AlgorithmName;
    private System.Security.Cryptography.X509Certificates.X509KeyStorageFlags KeyStorageFlags { get; }

    public async ValueTask<RsaKeyWrapResult> WrapKeyAsync(
        byte[] plaintext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        cancellationToken.ThrowIfCancellationRequested();

        var key = await GetKeyAsync(KeyId, cancellationToken);
        var ciphertext = key.Rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        return new RsaKeyWrapResult(ciphertext, KeyId, Algorithm);
    }

    public async ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (string.IsNullOrWhiteSpace(rsaKeyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(rsaKeyId));

        cancellationToken.ThrowIfCancellationRequested();

        var key = await GetKeyAsync(rsaKeyId, cancellationToken);
        return key.Rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
    }

    private async ValueTask<PfxRsaKeyMaterial> GetKeyAsync(
        string keyId,
        CancellationToken cancellationToken)
    {
        if (!_configuredKeys.ContainsKey(keyId))
            throw new InvalidOperationException($"RSA key '{keyId}' is not configured in the Azure Blob PFX key ring.");

        if (_keys.TryGetValue(keyId, out var loadedKey))
            return loadedKey;

        await _loadLock.WaitAsync(cancellationToken);
        try
        {
            if (_keys.TryGetValue(keyId, out loadedKey))
                return loadedKey;

            loadedKey = await LoadKeyAsync(keyId, cancellationToken);
            _keys.Add(keyId, loadedKey);
            return loadedKey;
        }
        finally
        {
            _loadLock.Release();
        }
    }

    private async ValueTask<PfxRsaKeyMaterial> LoadKeyAsync(
        string keyId,
        CancellationToken cancellationToken)
    {
        var configuredKey = _configuredKeys[keyId];
        var blobName = $"{_blobPrefix}{configuredKey.BlobName}";
        var blobClient = _containerClient.GetBlobClient(blobName);

        try
        {
            var response = await blobClient.DownloadContentAsync(cancellationToken);
            return PfxRsaKeyMaterial.LoadFromBytes(
                response.Value.Content.ToArray(),
                blobName,
                configuredKey.Password,
                KeyStorageFlags);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            throw new InvalidOperationException($"PFX RSA key blob '{blobName}' for key '{keyId}' was not found.", ex);
        }
    }

    private static string ValidateOptions(AzureBlobPfxRsaKeyRingProviderOptions options)
    {
        if (options.ContainerClient is null)
            throw new ArgumentException("Azure Blob container client must be configured.", nameof(options));

        if (string.IsNullOrWhiteSpace(options.CurrentKeyId))
            throw new ArgumentException("Current RSA key ID cannot be null or whitespace.", nameof(options));

        var keyIds = new HashSet<string>(StringComparer.Ordinal);
        var currentKeyConfigured = false;

        foreach (var configuredKey in options.Keys)
        {
            if (string.IsNullOrWhiteSpace(configuredKey.KeyId))
                throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(options));

            if (string.IsNullOrWhiteSpace(configuredKey.BlobName))
                throw new ArgumentException("PFX RSA key blob name cannot be null or whitespace.", nameof(options));

            if (!keyIds.Add(configuredKey.KeyId))
                throw new InvalidOperationException($"RSA key '{configuredKey.KeyId}' is configured more than once.");

            if (string.Equals(configuredKey.KeyId, options.CurrentKeyId, StringComparison.Ordinal))
                currentKeyConfigured = true;
        }

        if (!currentKeyConfigured)
            throw new InvalidOperationException($"Current RSA key '{options.CurrentKeyId}' is not configured in the Azure Blob PFX key ring.");

        return options.CurrentKeyId;
    }

    private static string NormalizeBlobName(string blobName)
        => blobName.Replace('\\', '/').TrimStart('/');
}
