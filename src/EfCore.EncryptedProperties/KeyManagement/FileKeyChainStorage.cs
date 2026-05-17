using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class FileKeyChainStorage : IKeyChainStorage
{
    private const int CurrentFormatVersion = 1;
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
            .Select(key => MapToRecord(document.Purpose, key))
            .OrderByDescending(record => record.CreatedAt)
            .FirstOrDefault();
    }

    public async ValueTask<EncryptedKeyRecord> GetOrActivateAsync(
        string purpose,
        DateTimeOffset? rotateBefore,
        EncryptedKeyRecord candidate,
        CancellationToken cancellationToken = default)
    {
        ValidateCandidate(purpose, candidate);

        await using var purposeLock = await AcquirePurposeLockAsync(purpose, cancellationToken);
        var document = await ReadPurposeDocumentAsync(purpose, cancellationToken);
        var keys = document.Keys!;

        var active = keys
            .Where(key => key.IsActive)
            .Select(key => MapToRecord(document.Purpose, key))
            .OrderByDescending(record => record.CreatedAt)
            .FirstOrDefault();

        if (active is not null && IsActiveKeyValid(active, rotateBefore))
            return active;

        foreach (var existing in keys.Where(key => key.IsActive))
            existing.IsActive = false;

        keys.RemoveAll(key => key.Id == candidate.Id);
        keys.Add(MapToFileRecord(candidate));

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
                return MapToRecord(document.Purpose, key);
        }

        return null;
    }

    public async ValueTask<IReadOnlyList<EncryptedKeyRecord>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        var documents = await ReadAllDocumentsAsync(cancellationToken);

        return documents
            .SelectMany(document => document.Keys!.Select(key => MapToRecord(document.Purpose, key)))
            .OrderBy(record => record.Purpose, StringComparer.Ordinal)
            .ThenBy(record => record.CreatedAt)
            .ToList();
    }

    private async ValueTask<FileKeyChainDocument> ReadPurposeDocumentAsync(
        string purpose,
        CancellationToken cancellationToken)
    {
        var path = GetPurposeFilePath(purpose);
        if (!File.Exists(path))
            return CreateDocument(purpose);

        var document = await ReadDocumentFileAsync(path, cancellationToken);
        if (!string.Equals(document.Purpose, purpose, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"File key chain document '{path}' stores purpose '{document.Purpose}', but '{purpose}' was requested.");
        }

        return document;
    }

    private async ValueTask<IReadOnlyList<FileKeyChainDocument>> ReadAllDocumentsAsync(
        CancellationToken cancellationToken)
    {
        var documents = new List<FileKeyChainDocument>();
        foreach (var path in Directory.EnumerateFiles(_directoryPath, $"{PurposeFilePrefix}*", SearchOption.TopDirectoryOnly)
                     .Where(path => path.EndsWith(PurposeFileExtension, StringComparison.OrdinalIgnoreCase)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            documents.Add(await ReadDocumentFileAsync(path, cancellationToken));
        }

        return documents;
    }

    private static async ValueTask<FileKeyChainDocument> ReadDocumentFileAsync(
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

        var document = await JsonSerializer.DeserializeAsync(
            stream,
            FileKeyChainStorageJsonContext.Default.FileKeyChainDocument,
            cancellationToken);

        if (document is null)
            throw new FormatException($"File key chain document '{path}' is empty or invalid.");

        ValidateDocument(path, document);
        return document;
    }

    private async ValueTask WriteDocumentAsync(
        FileKeyChainDocument document,
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
                await JsonSerializer.SerializeAsync(
                    stream,
                    document,
                    FileKeyChainStorageJsonContext.Default.FileKeyChainDocument,
                    cancellationToken);
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
        return Path.Combine(_directoryPath, $"{PurposeFilePrefix}{ComputePurposeHash(purpose)}{PurposeFileExtension}");
    }

    private string GetPurposeLockFilePath(string purpose)
    {
        return Path.Combine(_directoryPath, $"{PurposeFilePrefix}{ComputePurposeHash(purpose)}{LockFileExtension}");
    }

    private static string ComputePurposeHash(string purpose)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(purpose));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static FileKeyChainDocument CreateDocument(string purpose)
    {
        return new FileKeyChainDocument
        {
            FormatVersion = CurrentFormatVersion,
            Purpose = purpose,
            Keys = new List<FileKeyChainKeyRecord>()
        };
    }

    private static FileKeyChainKeyRecord MapToFileRecord(EncryptedKeyRecord record)
    {
        return new FileKeyChainKeyRecord
        {
            Id = record.Id,
            RsaKeyId = record.RsaKeyId,
            Algorithm = record.Algorithm,
            EncryptedKey = record.EncryptedKey,
            CreatedAt = record.CreatedAt,
            IsActive = record.IsActive
        };
    }

    private static EncryptedKeyRecord MapToRecord(string purpose, FileKeyChainKeyRecord record)
    {
        return new EncryptedKeyRecord
        {
            Id = record.Id,
            Purpose = purpose,
            RsaKeyId = record.RsaKeyId,
            Algorithm = record.Algorithm,
            EncryptedKey = record.EncryptedKey,
            CreatedAt = record.CreatedAt,
            IsActive = record.IsActive
        };
    }

    private static bool IsActiveKeyValid(EncryptedKeyRecord record, DateTimeOffset? rotateBefore)
    {
        return rotateBefore is null || record.CreatedAt >= rotateBefore.Value;
    }

    private static void ValidateCandidate(string purpose, EncryptedKeyRecord candidate)
    {
        if (!string.Equals(candidate.Purpose, purpose, StringComparison.Ordinal))
            throw new ArgumentException("Candidate purpose must match the requested purpose.", nameof(candidate));

        if (!candidate.IsActive)
            throw new ArgumentException("Candidate key must be active.", nameof(candidate));
    }

    private static void ValidateDocument(string path, FileKeyChainDocument document)
    {
        if (document.FormatVersion != CurrentFormatVersion)
            throw new FormatException($"File key chain document '{path}' has unsupported format version {document.FormatVersion}.");

        if (string.IsNullOrWhiteSpace(document.Purpose))
            throw new FormatException($"File key chain document '{path}' has a missing purpose.");

        if (document.Keys is null)
            throw new FormatException($"File key chain document '{path}' has a missing keys collection.");

        foreach (var key in document.Keys)
        {
            if (key.Id == Guid.Empty)
                throw new FormatException($"File key chain document '{path}' contains a key with an empty ID.");

            if (string.IsNullOrWhiteSpace(key.RsaKeyId))
                throw new FormatException($"File key chain document '{path}' contains a key with a missing RSA key ID.");

            if (string.IsNullOrWhiteSpace(key.Algorithm))
                throw new FormatException($"File key chain document '{path}' contains a key with a missing algorithm.");

            if (string.IsNullOrWhiteSpace(key.EncryptedKey))
                throw new FormatException($"File key chain document '{path}' contains a key with a missing encrypted key.");
        }
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

internal sealed class FileKeyChainDocument
{
    [JsonPropertyName("formatVersion")]
    public int FormatVersion { get; set; }

    [JsonPropertyName("purpose")]
    public string Purpose { get; set; } = string.Empty;

    [JsonPropertyName("keys")]
    public List<FileKeyChainKeyRecord>? Keys { get; set; } = new();
}

internal sealed class FileKeyChainKeyRecord
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("rsaKeyId")]
    public string RsaKeyId { get; set; } = string.Empty;

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = string.Empty;

    [JsonPropertyName("encryptedKey")]
    public string EncryptedKey { get; set; } = string.Empty;

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; set; }

    [JsonPropertyName("isActive")]
    public bool IsActive { get; set; }
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(FileKeyChainDocument))]
internal partial class FileKeyChainStorageJsonContext : JsonSerializerContext;
