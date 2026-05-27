using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class FileKeyChainStorage : IRewrappableKeyChainStorage
{
    private const string PurposeFilePrefix = "purpose-";
    private const string PurposeFileExtension = ".json";
    private const string LockFileExtension = ".lock";
    private static readonly TimeSpan LockRetryDelay = TimeSpan.FromMilliseconds(25);

    private readonly string _directoryPath;

    public FileKeyChainStorage(string directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
            throw new ArgumentException("Directory path cannot be null or whitespace.", nameof(directoryPath));

        _directoryPath = Path.GetFullPath(directoryPath);
        Directory.CreateDirectory(_directoryPath);
    }

    public async ValueTask<EncryptedKeyRecord?> GetActiveAsync(
        string purpose,
        CancellationToken cancellationToken = default)
    {
        var document = await ReadPurposeDocumentAsync(purpose, cancellationToken);

        return document.Keys!
            .Where(key => key.IsActive)
            .Select(key => KeyChainStorageDocuments.MapToRecord(document.Purpose, key))
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

        await using var purposeLock = await AcquirePurposeLockAsync(purpose, cancellationToken);
        var document = await ReadPurposeDocumentAsync(purpose, cancellationToken);
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

        await WriteDocumentAsync(document, cancellationToken);
        return candidate;
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

        await using var purposeLock = await AcquirePurposeLockAsync(original.Purpose, cancellationToken);
        var document = await ReadPurposeDocumentAsync(original.Purpose, cancellationToken);
        var key = document.Keys!.FirstOrDefault(key => key.Id == original.Id);

        if (key is null
            || !string.Equals(key.RsaKeyId, original.RsaKeyId, StringComparison.Ordinal)
            || !string.Equals(key.EncryptedKey, original.EncryptedKey, StringComparison.Ordinal))
        {
            return false;
        }

        key.RsaKeyId = replacement.RsaKeyId;
        key.EncryptedKey = replacement.EncryptedKey;

        await WriteDocumentAsync(document, cancellationToken);
        return true;
    }

    private async ValueTask<KeyChainDocument> ReadPurposeDocumentAsync(
        string purpose,
        CancellationToken cancellationToken)
    {
        var path = GetPurposeFilePath(purpose);
        if (!File.Exists(path))
            return KeyChainStorageDocuments.Create(purpose);

        var document = await ReadDocumentFileAsync(path, cancellationToken);
        if (!string.Equals(document.Purpose, purpose, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"File key chain document '{path}' stores purpose '{document.Purpose}', but '{purpose}' was requested.");
        }

        return document;
    }

    private async ValueTask<IReadOnlyList<KeyChainDocument>> ReadAllDocumentsAsync(
        CancellationToken cancellationToken)
    {
        var documents = new List<KeyChainDocument>();
        foreach (var path in Directory.EnumerateFiles(_directoryPath, $"{PurposeFilePrefix}*", SearchOption.TopDirectoryOnly)
                     .Where(path => path.EndsWith(PurposeFileExtension, StringComparison.OrdinalIgnoreCase)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            documents.Add(await ReadDocumentFileAsync(path, cancellationToken));
        }

        return documents;
    }

    private static async ValueTask<KeyChainDocument> ReadDocumentFileAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.ReadWrite | FileShare.Delete,
                Options = FileOptions.Asynchronous
            });

        return await KeyChainStorageDocuments.ReadAsync(stream, path, cancellationToken);
    }

    private async ValueTask WriteDocumentAsync(
        KeyChainDocument document,
        CancellationToken cancellationToken)
    {
        var path = GetPurposeFilePath(document.Purpose);
        var tempPath = Path.Combine(_directoryPath, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");

        try
        {
            await using (var stream = new FileStream(
                tempPath,
                new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    Options = FileOptions.Asynchronous | FileOptions.WriteThrough
                }))
            {
                await KeyChainStorageDocuments.WriteAsync(stream, document, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }

            File.Move(tempPath, path, overwrite: true);
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }
    }

    private async ValueTask<FileStream> AcquirePurposeLockAsync(
        string purpose,
        CancellationToken cancellationToken)
    {
        var lockPath = GetPurposeLockFilePath(purpose);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return new FileStream(
                    lockPath,
                    new FileStreamOptions
                    {
                        Mode = FileMode.OpenOrCreate,
                        Access = FileAccess.ReadWrite,
                        Share = FileShare.None,
                        Options = FileOptions.Asynchronous
                    });
            }
            catch (IOException) when (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(LockRetryDelay, cancellationToken);
            }
        }
    }

    private string GetPurposeFilePath(string purpose)
    {
        return Path.Combine(_directoryPath, $"{PurposeFilePrefix}{KeyChainStorageDocuments.ComputePurposeHash(purpose)}{PurposeFileExtension}");
    }

    private string GetPurposeLockFilePath(string purpose)
    {
        return Path.Combine(_directoryPath, $"{PurposeFilePrefix}{KeyChainStorageDocuments.ComputePurposeHash(purpose)}{LockFileExtension}");
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Preserve the original write failure.
        }
    }
}
