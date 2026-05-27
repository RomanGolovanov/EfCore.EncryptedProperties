using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class AzureBlobKeyChainStorage : IRewrappableKeyChainStorage
{
    private const string PurposeBlobPrefix = "purpose-";
    private const string PurposeBlobExtension = ".json";

    private readonly BlobContainerClient _containerClient;
    private readonly string _blobPrefix;
    private readonly bool _createContainerIfNotExists;
    private readonly int _maxWriteAttempts;
    private readonly TimeSpan _retryDelay;
    private int _containerInitialized;

    public AzureBlobKeyChainStorage(
        BlobContainerClient containerClient,
        AzureBlobKeyChainStorageOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(containerClient);

        options ??= new AzureBlobKeyChainStorageOptions();
        if (options.MaxWriteAttempts <= 0)
            throw new ArgumentOutOfRangeException(nameof(options.MaxWriteAttempts), "Maximum write attempts must be positive.");

        if (options.RetryDelay < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options.RetryDelay), "Retry delay cannot be negative.");

        _containerClient = containerClient;
        _blobPrefix = NormalizeBlobPrefix(options.BlobPrefix);
        _createContainerIfNotExists = options.CreateContainerIfNotExists;
        _maxWriteAttempts = options.MaxWriteAttempts;
        _retryDelay = options.RetryDelay;
    }

    public async ValueTask<EncryptedKeyRecord?> GetActiveAsync(
        string purpose,
        CancellationToken cancellationToken = default)
    {
        await EnsureContainerAsync(cancellationToken);
        var state = await ReadPurposeDocumentAsync(purpose, cancellationToken);
        if (state is null)
            return null;

        return state.Document.Keys!
            .Where(key => key.IsActive)
            .Select(key => KeyChainStorageDocuments.MapToRecord(state.Document.Purpose, key))
            .OrderByDescending(record => record.CreatedAt)
            .FirstOrDefault();
    }

    public async ValueTask<EncryptedKeyRecord> GetOrActivateAsync(
        string purpose,
        DateTimeOffset? rotateBefore,
        EncryptedKeyRecord candidate,
        CancellationToken cancellationToken = default)
    {
        KeyChainStorageDocuments.ValidateCandidate(purpose, candidate);
        await EnsureContainerAsync(cancellationToken);

        for (var attempt = 0; attempt < _maxWriteAttempts; attempt++)
        {
            var state = await ReadPurposeDocumentAsync(purpose, cancellationToken);
            var document = state?.Document ?? KeyChainStorageDocuments.Create(purpose);
            var keys = document.Keys!;

            var active = keys
                .Where(key => key.IsActive)
                .Select(key => KeyChainStorageDocuments.MapToRecord(document.Purpose, key))
                .OrderByDescending(record => record.CreatedAt)
                .FirstOrDefault();

            if (active is not null && KeyChainStorageDocuments.IsActiveKeyValid(active, rotateBefore))
                return active;

            foreach (var existing in keys.Where(key => key.IsActive))
                existing.IsActive = false;

            keys.RemoveAll(key => key.Id == candidate.Id);
            keys.Add(KeyChainStorageDocuments.MapToDocumentRecord(candidate));

            try
            {
                await WritePurposeDocumentAsync(document, state?.ETag, cancellationToken);
                return candidate;
            }
            catch (RequestFailedException ex) when (IsRetryableConcurrencyFailure(ex) && attempt + 1 < _maxWriteAttempts)
            {
                if (_retryDelay > TimeSpan.Zero)
                    await Task.Delay(_retryDelay, cancellationToken);
            }
        }

        throw new InvalidOperationException(
            $"Could not activate key chain purpose '{purpose}' after {_maxWriteAttempts} blob write attempts.");
    }

    public async ValueTask<EncryptedKeyRecord?> GetByIdAsync(
        string keyId,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(keyId, out var id))
            return null;

        foreach (var document in await ReadAllDocumentsAsync(cancellationToken))
        {
            var key = document.Keys!.FirstOrDefault(key => key.Id == id);
            if (key is not null)
                return KeyChainStorageDocuments.MapToRecord(document.Purpose, key);
        }

        return null;
    }

    public async ValueTask<IReadOnlyList<EncryptedKeyRecord>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        var documents = await ReadAllDocumentsAsync(cancellationToken);

        return documents
            .SelectMany(document => document.Keys!.Select(key => KeyChainStorageDocuments.MapToRecord(document.Purpose, key)))
            .OrderBy(record => record.Purpose, StringComparer.Ordinal)
            .ThenBy(record => record.CreatedAt)
            .ToList();
    }

    public async ValueTask<bool> TryReplaceKeyAsync(
        EncryptedKeyRecord original,
        EncryptedKeyRecord replacement,
        CancellationToken cancellationToken = default)
    {
        KeyChainStorageDocuments.ValidateReplacement(original, replacement);
        await EnsureContainerAsync(cancellationToken);

        for (var attempt = 0; attempt < _maxWriteAttempts; attempt++)
        {
            var state = await ReadPurposeDocumentAsync(original.Purpose, cancellationToken);
            if (state is null)
                return false;

            var key = state.Document.Keys!.FirstOrDefault(key => key.Id == original.Id);
            if (key is null
                || !string.Equals(key.RsaKeyId, original.RsaKeyId, StringComparison.Ordinal)
                || !string.Equals(key.EncryptedKey, original.EncryptedKey, StringComparison.Ordinal))
            {
                return false;
            }

            key.RsaKeyId = replacement.RsaKeyId;
            key.EncryptedKey = replacement.EncryptedKey;

            try
            {
                await WritePurposeDocumentAsync(state.Document, state.ETag, cancellationToken);
                return true;
            }
            catch (RequestFailedException ex) when (IsRetryableConcurrencyFailure(ex) && attempt + 1 < _maxWriteAttempts)
            {
                if (_retryDelay > TimeSpan.Zero)
                    await Task.Delay(_retryDelay, cancellationToken);
            }
        }

        throw new InvalidOperationException(
            $"Could not replace key chain KEK '{original.Id}' for purpose '{original.Purpose}' after {_maxWriteAttempts} blob write attempts.");
    }

    private async ValueTask<BlobPurposeDocumentState?> ReadPurposeDocumentAsync(
        string purpose,
        CancellationToken cancellationToken)
    {
        var blobName = GetPurposeBlobName(purpose);
        var state = await ReadDocumentBlobAsync(blobName, cancellationToken);
        if (state is null)
            return null;

        if (!string.Equals(state.Document.Purpose, purpose, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"Blob key chain document '{blobName}' stores purpose '{state.Document.Purpose}', but '{purpose}' was requested.");
        }

        return state;
    }

    private async ValueTask<IReadOnlyList<KeyChainDocument>> ReadAllDocumentsAsync(
        CancellationToken cancellationToken)
    {
        await EnsureContainerAsync(cancellationToken);

        var documents = new List<KeyChainDocument>();
        await foreach (var blob in _containerClient.GetBlobsAsync(
                           traits: BlobTraits.None,
                           states: BlobStates.None,
                           prefix: $"{_blobPrefix}{PurposeBlobPrefix}",
                           cancellationToken: cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!blob.Name.EndsWith(PurposeBlobExtension, StringComparison.OrdinalIgnoreCase))
                continue;

            var state = await ReadDocumentBlobAsync(blob.Name, cancellationToken);
            if (state is not null)
                documents.Add(state.Document);
        }

        return documents;
    }

    private async ValueTask<BlobPurposeDocumentState?> ReadDocumentBlobAsync(
        string blobName,
        CancellationToken cancellationToken)
    {
        var blobClient = _containerClient.GetBlobClient(blobName);

        try
        {
            var response = await blobClient.DownloadContentAsync(cancellationToken);
            var document = KeyChainStorageDocuments.Read(response.Value.Content.ToArray(), blobName);
            return new BlobPurposeDocumentState(document, response.Value.Details.ETag);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    private async ValueTask WritePurposeDocumentAsync(
        KeyChainDocument document,
        ETag? etag,
        CancellationToken cancellationToken)
    {
        var blobClient = _containerClient.GetBlobClient(GetPurposeBlobName(document.Purpose));
        var bytes = KeyChainStorageDocuments.WriteToUtf8Bytes(document);
        var conditions = etag is null
            ? new BlobRequestConditions { IfNoneMatch = ETag.All }
            : new BlobRequestConditions { IfMatch = etag.Value };

        await blobClient.UploadAsync(
            BinaryData.FromBytes(bytes),
            new BlobUploadOptions { Conditions = conditions },
            cancellationToken);
    }

    private async ValueTask EnsureContainerAsync(CancellationToken cancellationToken)
    {
        if (!_createContainerIfNotExists || Volatile.Read(ref _containerInitialized) == 1)
            return;

        await _containerClient.CreateIfNotExistsAsync(cancellationToken: cancellationToken);
        Volatile.Write(ref _containerInitialized, 1);
    }

    private string GetPurposeBlobName(string purpose)
    {
        return $"{_blobPrefix}{PurposeBlobPrefix}{KeyChainStorageDocuments.ComputePurposeHash(purpose)}{PurposeBlobExtension}";
    }

    private static bool IsRetryableConcurrencyFailure(RequestFailedException exception)
        => exception.Status is 409 or 412;

    internal static string NormalizeBlobPrefix(string? blobPrefix)
    {
        if (string.IsNullOrWhiteSpace(blobPrefix))
            return string.Empty;

        var normalized = blobPrefix.Replace('\\', '/').TrimStart('/');
        return normalized.EndsWith("/", StringComparison.Ordinal)
            ? normalized
            : $"{normalized}/";
    }

    private sealed record BlobPurposeDocumentState(KeyChainDocument Document, ETag ETag);
}
