using System.Security.Cryptography;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.KeyManagement;

namespace EfCore.EncryptedProperties.Providers;

public sealed class AzureBlobRsaKeyRingProvider : IRsaKeyProvider
{
    private const string AlgorithmName = "RSA-OAEP-256";

    private readonly BlobContainerClient _containerClient;
    private readonly Dictionary<string, string> _blobNames;
    private readonly Dictionary<string, RSA> _keys = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private readonly string _blobPrefix;
    private readonly bool _createContainerIfNotExists;
    private readonly int _keySizeInBits;
    private int _containerInitialized;

    public AzureBlobRsaKeyRingProvider(AzureBlobRsaKeyRingProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        KeyId = ValidateOptions(options);
        _containerClient = options.ContainerClient!;
        _blobPrefix = AzureBlobKeyChainStorage.NormalizeBlobPrefix(options.BlobPrefix);
        _createContainerIfNotExists = options.CreateContainerIfNotExists;
        _keySizeInBits = options.KeySizeInBits;
        _blobNames = options.Keys.ToDictionary(
            key => key.KeyId,
            key => NormalizeBlobName(key.BlobName),
            StringComparer.Ordinal);
    }

    public string KeyId { get; }
    public string Algorithm => AlgorithmName;

    public async ValueTask<RsaKeyWrapResult> WrapKeyAsync(
        byte[] plaintext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        cancellationToken.ThrowIfCancellationRequested();

        var key = await GetKeyAsync(KeyId, cancellationToken);
        var ciphertext = key.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
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
        return key.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
    }

    private async ValueTask<RSA> GetKeyAsync(string keyId, CancellationToken cancellationToken)
    {
        if (!_blobNames.ContainsKey(keyId))
            throw new InvalidOperationException($"RSA key '{keyId}' is not configured in the Azure Blob key ring.");

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

    private async ValueTask<RSA> LoadKeyAsync(string keyId, CancellationToken cancellationToken)
    {
        await EnsureContainerAsync(cancellationToken);

        var blobClient = _containerClient.GetBlobClient(GetBlobName(keyId));
        try
        {
            return await DownloadPemKeyAsync(blobClient, cancellationToken);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            if (!string.Equals(keyId, KeyId, StringComparison.Ordinal))
                throw new InvalidOperationException($"RSA key blob '{blobClient.Name}' for historical key '{keyId}' was not found.", ex);

            return await CreateCurrentKeyAsync(blobClient, cancellationToken);
        }
    }

    private async ValueTask<RSA> CreateCurrentKeyAsync(
        BlobClient blobClient,
        CancellationToken cancellationToken)
    {
        var currentKey = RSA.Create(_keySizeInBits);
        var pem = currentKey.ExportRSAPrivateKeyPem();

        try
        {
            await blobClient.UploadAsync(
                BinaryData.FromString(pem),
                new BlobUploadOptions
                {
                    Conditions = new BlobRequestConditions { IfNoneMatch = ETag.All }
                },
                cancellationToken);

            return currentKey;
        }
        catch (RequestFailedException ex) when (ex.Status is 409 or 412)
        {
            currentKey.Dispose();
            return await DownloadPemKeyAsync(blobClient, cancellationToken);
        }
    }

    private static async ValueTask<RSA> DownloadPemKeyAsync(
        BlobClient blobClient,
        CancellationToken cancellationToken)
    {
        var response = await blobClient.DownloadContentAsync(cancellationToken);
        var pem = response.Value.Content.ToString();
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    private async ValueTask EnsureContainerAsync(CancellationToken cancellationToken)
    {
        if (!_createContainerIfNotExists || Volatile.Read(ref _containerInitialized) == 1)
            return;

        await _containerClient.CreateIfNotExistsAsync(cancellationToken: cancellationToken);
        Volatile.Write(ref _containerInitialized, 1);
    }

    private string GetBlobName(string keyId)
        => $"{_blobPrefix}{_blobNames[keyId]}";

    private static string ValidateOptions(AzureBlobRsaKeyRingProviderOptions options)
    {
        if (options.ContainerClient is null)
            throw new ArgumentException("Azure Blob container client must be configured.", nameof(options));

        if (string.IsNullOrWhiteSpace(options.CurrentKeyId))
            throw new ArgumentException("Current RSA key ID cannot be null or whitespace.", nameof(options));

        if (options.KeySizeInBits <= 0)
            throw new ArgumentOutOfRangeException(nameof(options.KeySizeInBits), "RSA key size must be positive.");

        var keyIds = new HashSet<string>(StringComparer.Ordinal);
        var currentKeyConfigured = false;

        foreach (var configuredKey in options.Keys)
        {
            if (string.IsNullOrWhiteSpace(configuredKey.KeyId))
                throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(options));

            if (string.IsNullOrWhiteSpace(configuredKey.BlobName))
                throw new ArgumentException("RSA key blob name cannot be null or whitespace.", nameof(options));

            if (!keyIds.Add(configuredKey.KeyId))
                throw new InvalidOperationException($"RSA key '{configuredKey.KeyId}' is configured more than once.");

            if (string.Equals(configuredKey.KeyId, options.CurrentKeyId, StringComparison.Ordinal))
                currentKeyConfigured = true;
        }

        if (!currentKeyConfigured)
            throw new InvalidOperationException($"Current RSA key '{options.CurrentKeyId}' is not configured in the Azure Blob key ring.");

        return options.CurrentKeyId;
    }

    private static string NormalizeBlobName(string blobName)
        => blobName.Replace('\\', '/').TrimStart('/');
}
