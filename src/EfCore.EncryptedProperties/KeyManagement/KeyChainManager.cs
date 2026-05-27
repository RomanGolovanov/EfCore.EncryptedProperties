using System.Collections.Concurrent;
using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EfCore.EncryptedProperties.KeyManagement;

internal sealed class KeyChainManager : IKeyChainManager, IKeyChainRewrapper
{
    private readonly IKeyChainStorage _storage;
    private readonly IRsaKeyProvider _rsaKeyProvider;
    private readonly EncryptedPropertiesOptions _options;
    private readonly ILogger<KeyChainManager> _logger;
    private readonly ConcurrentDictionary<string, (KeyMaterial Material, DateTimeOffset CachedAt)> _cache = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _purposeLocks = new();

    public KeyChainManager(
        IKeyChainStorage storage,
        IRsaKeyProvider rsaKeyProvider,
        EncryptedPropertiesOptions options,
        ILogger<KeyChainManager>? logger = null)
    {
        _storage = storage;
        _rsaKeyProvider = rsaKeyProvider;
        _options = options;
        _logger = logger ?? NullLogger<KeyChainManager>.Instance;
    }

    public async ValueTask<KeyMaterial> GetActiveKeyAsync(string purpose, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"active:{purpose}";

        if (TryGetCached(cacheKey, out var cached))
            return cached!;

        var semaphore = _purposeLocks.GetOrAdd(purpose, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(cancellationToken);
        try
        {
            if (TryGetCached(cacheKey, out cached))
                return cached!;

            var record = await _storage.GetActiveAsync(purpose, cancellationToken);
            var shouldRotate = record is not null && ShouldRotate(record);

            if (record is not null && !shouldRotate)
            {
                var decrypted = await DecryptKekAsync(record, cancellationToken);
                Cache(cacheKey, decrypted);
                Cache(decrypted.KeyId, decrypted);
                return decrypted;
            }

            var (candidate, rawKey) = await CreateCandidateKekAsync(purpose, cancellationToken);
            try
            {
                var active = await _storage.GetOrActivateAsync(
                    purpose,
                    GetRotateBefore(),
                    candidate,
                    cancellationToken);

                if (active.Id == candidate.Id)
                {
                    var material = new KeyMaterial
                    {
                        KeyId = candidate.Id.ToString(),
                        Key = rawKey,
                        Algorithm = candidate.Algorithm
                    };

                    Cache(cacheKey, material);
                    Cache(material.KeyId, material);

                    if (record is null)
                    {
                        LogKeyCreated(candidate);
                    }
                    else if (shouldRotate)
                    {
                        LogKeyRotated(record, candidate);
                    }

                    return material;
                }

                CryptographicOperations.ZeroMemory(rawKey);
                var decrypted = await DecryptKekAsync(active, cancellationToken);
                Cache(cacheKey, decrypted);
                Cache(decrypted.KeyId, decrypted);
                return decrypted;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(rawKey);
                throw;
            }
        }
        finally
        {
            semaphore.Release();
        }
    }

    public async ValueTask<KeyMaterial> GetKeyForDecryptAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (TryGetCached(keyId, out var cached))
            return cached!;

        var record = await _storage.GetByIdAsync(keyId, cancellationToken)
            ?? throw new InvalidOperationException($"KEK with ID '{keyId}' not found.");

        var material = await DecryptKekAsync(record, cancellationToken);
        Cache(keyId, material);
        return material;
    }

    public async ValueTask PreloadAsync(CancellationToken cancellationToken = default)
    {
        var records = await _storage.GetAllAsync(cancellationToken);
        foreach (var record in records)
        {
            try
            {
                var material = await DecryptKekAsync(record, cancellationToken);
                Cache(material.KeyId, material);

                if (record.IsActive)
                    Cache($"active:{record.Purpose}", material);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    EncryptedPropertiesEventIds.KeyPreloadFailed,
                    ex,
                    "Failed to preload encrypted property KEK {KeyId} for purpose {Purpose} using RSA key {RsaKeyId}.",
                    record.Id,
                    record.Purpose,
                    record.RsaKeyId);
                throw;
            }
        }
    }

    public async ValueTask<KeyChainRewrapResult> RewrapAsync(
        KeyChainRewrapOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new KeyChainRewrapOptions();
        ValidateRewrapOptions(options);

        var rewrappableStorage = _storage as IRewrappableKeyChainStorage;
        if (!options.DryRun && rewrappableStorage is null)
        {
            throw new InvalidOperationException(
                $"The configured key chain storage '{_storage.GetType().FullName}' does not support KEK rewrap. Implement {nameof(IRewrappableKeyChainStorage)} to enable rewrap writes.");
        }

        var records = await _storage.GetAllAsync(cancellationToken);
        var auditRecords = new List<KeyChainRewrapRecord>();
        var eligibleCount = 0;
        var rewrappedCount = 0;
        var alreadyCurrentCount = 0;
        var wouldRewrapCount = 0;

        foreach (var record in records
                     .OrderBy(record => record.Purpose, StringComparer.Ordinal)
                     .ThenBy(record => record.CreatedAt)
                     .ThenBy(record => record.Id))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (options.Purpose is not null
                && !string.Equals(record.Purpose, options.Purpose, StringComparison.Ordinal))
            {
                continue;
            }

            if (options.OldRsaKeyId is not null
                && !string.Equals(record.RsaKeyId, options.OldRsaKeyId, StringComparison.Ordinal))
            {
                continue;
            }

            eligibleCount++;
            var rawKey = Array.Empty<byte>();

            try
            {
                var encryptedBytes = Base64Url.Decode(record.EncryptedKey);
                rawKey = await _rsaKeyProvider.UnwrapKeyAsync(
                    encryptedBytes,
                    record.RsaKeyId,
                    cancellationToken);
                var wrappedKey = await _rsaKeyProvider.WrapKeyAsync(rawKey, cancellationToken);

                if (string.Equals(wrappedKey.RsaKeyId, record.RsaKeyId, StringComparison.Ordinal))
                {
                    alreadyCurrentCount++;
                    auditRecords.Add(CreateRewrapRecord(
                        record,
                        wrappedKey.RsaKeyId,
                        KeyChainRewrapStatus.AlreadyCurrent));
                    continue;
                }

                if (options.DryRun)
                {
                    wouldRewrapCount++;
                    auditRecords.Add(CreateRewrapRecord(
                        record,
                        wrappedKey.RsaKeyId,
                        KeyChainRewrapStatus.WouldRewrap));
                    continue;
                }

                var replacement = new EncryptedKeyRecord
                {
                    Id = record.Id,
                    Purpose = record.Purpose,
                    RsaKeyId = wrappedKey.RsaKeyId,
                    Algorithm = record.Algorithm,
                    EncryptedKey = Base64Url.Encode(wrappedKey.Ciphertext),
                    CreatedAt = record.CreatedAt,
                    IsActive = record.IsActive
                };

                var replaced = await rewrappableStorage!.TryReplaceKeyAsync(
                    record,
                    replacement,
                    cancellationToken);

                if (!replaced)
                {
                    if (await IsAlreadyRewrappedAsync(record, wrappedKey.RsaKeyId, cancellationToken))
                    {
                        alreadyCurrentCount++;
                        auditRecords.Add(CreateRewrapRecord(
                            record,
                            wrappedKey.RsaKeyId,
                            KeyChainRewrapStatus.AlreadyCurrent));
                        continue;
                    }

                    throw new InvalidOperationException(
                        $"KEK '{record.Id}' for purpose '{record.Purpose}' changed during rewrap. Rerun the operation to process the latest key-chain state.");
                }

                rewrappedCount++;
                auditRecords.Add(CreateRewrapRecord(
                    record,
                    wrappedKey.RsaKeyId,
                    KeyChainRewrapStatus.Rewrapped));
                LogKeyRewrapped(record, replacement);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogKeyRewrapFailed(record, ex);
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rawKey);
            }
        }

        return new KeyChainRewrapResult
        {
            ScannedCount = records.Count,
            EligibleCount = eligibleCount,
            RewrappedCount = rewrappedCount,
            AlreadyCurrentCount = alreadyCurrentCount,
            WouldRewrapCount = wouldRewrapCount,
            Records = auditRecords.ToArray()
        };
    }

    private async ValueTask<(EncryptedKeyRecord Record, byte[] RawKey)> CreateCandidateKekAsync(
        string purpose,
        CancellationToken cancellationToken)
    {
        var rawKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            var wrappedKey = await _rsaKeyProvider.WrapKeyAsync(rawKey, cancellationToken);

            var record = new EncryptedKeyRecord
            {
                Id = Guid.NewGuid(),
                Purpose = purpose,
                RsaKeyId = wrappedKey.RsaKeyId,
                Algorithm = "A256GCMKW",
                EncryptedKey = Base64Url.Encode(wrappedKey.Ciphertext),
                CreatedAt = DateTimeOffset.UtcNow,
                IsActive = true
            };

            return (record, rawKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(rawKey);
            throw;
        }
    }

    private async ValueTask<KeyMaterial> DecryptKekAsync(EncryptedKeyRecord record, CancellationToken cancellationToken)
    {
        var encryptedBytes = Base64Url.Decode(record.EncryptedKey);
        var rawKey = await _rsaKeyProvider.UnwrapKeyAsync(encryptedBytes, record.RsaKeyId, cancellationToken);

        return new KeyMaterial
        {
            KeyId = record.Id.ToString(),
            Key = rawKey,
            Algorithm = record.Algorithm
        };
    }

    private bool ShouldRotate(EncryptedKeyRecord record)
    {
        if (_options.RotationPolicy.KeyRotateAfter is not { } maxAge)
            return false;

        return DateTimeOffset.UtcNow - record.CreatedAt > maxAge;
    }

    private DateTimeOffset? GetRotateBefore()
    {
        if (_options.RotationPolicy.KeyRotateAfter is not { } maxAge)
            return null;

        return DateTimeOffset.UtcNow - maxAge;
    }

    private void LogKeyCreated(EncryptedKeyRecord record)
    {
        _logger.LogInformation(
            EncryptedPropertiesEventIds.KeyCreated,
            "Created encrypted property KEK {KeyId} for purpose {Purpose} using RSA key {RsaKeyId} at {CreatedAt}.",
            record.Id,
            record.Purpose,
            record.RsaKeyId,
            record.CreatedAt);
    }

    private void LogKeyRotated(EncryptedKeyRecord oldRecord, EncryptedKeyRecord newRecord)
    {
        _logger.LogInformation(
            EncryptedPropertiesEventIds.KeyRotated,
            "Rotated encrypted property KEK for purpose {Purpose} from key {OldKeyId} to key {NewKeyId}. Old RSA key {OldRsaKeyId}, new RSA key {NewRsaKeyId}. Old created at {OldCreatedAt}; new created at {NewCreatedAt}.",
            newRecord.Purpose,
            oldRecord.Id,
            newRecord.Id,
            oldRecord.RsaKeyId,
            newRecord.RsaKeyId,
            oldRecord.CreatedAt,
            newRecord.CreatedAt);
    }

    private void LogKeyRewrapped(EncryptedKeyRecord oldRecord, EncryptedKeyRecord newRecord)
    {
        _logger.LogInformation(
            EncryptedPropertiesEventIds.KeyRewrapped,
            "Rewrapped encrypted property KEK {KeyId} for purpose {Purpose} from RSA key {OldRsaKeyId} to RSA key {NewRsaKeyId}.",
            oldRecord.Id,
            oldRecord.Purpose,
            oldRecord.RsaKeyId,
            newRecord.RsaKeyId);
    }

    private void LogKeyRewrapFailed(EncryptedKeyRecord record, Exception exception)
    {
        _logger.LogError(
            EncryptedPropertiesEventIds.KeyRewrapFailed,
            exception,
            "Failed to rewrap encrypted property KEK {KeyId} for purpose {Purpose} using RSA key {RsaKeyId}.",
            record.Id,
            record.Purpose,
            record.RsaKeyId);
    }

    private async ValueTask<bool> IsAlreadyRewrappedAsync(
        EncryptedKeyRecord original,
        string newRsaKeyId,
        CancellationToken cancellationToken)
    {
        var current = await _storage.GetByIdAsync(original.Id.ToString(), cancellationToken);
        return current is not null
            && string.Equals(current.RsaKeyId, newRsaKeyId, StringComparison.Ordinal);
    }

    private static KeyChainRewrapRecord CreateRewrapRecord(
        EncryptedKeyRecord record,
        string newRsaKeyId,
        KeyChainRewrapStatus status)
    {
        return new KeyChainRewrapRecord
        {
            KeyId = record.Id,
            Purpose = record.Purpose,
            OldRsaKeyId = record.RsaKeyId,
            NewRsaKeyId = newRsaKeyId,
            IsActive = record.IsActive,
            Status = status
        };
    }

    private static void ValidateRewrapOptions(KeyChainRewrapOptions options)
    {
        if (options.Purpose is not null && string.IsNullOrWhiteSpace(options.Purpose))
            throw new ArgumentException("Purpose cannot be empty or whitespace.", nameof(options));

        if (options.OldRsaKeyId is not null && string.IsNullOrWhiteSpace(options.OldRsaKeyId))
            throw new ArgumentException("Old RSA key ID cannot be empty or whitespace.", nameof(options));
    }

    private bool TryGetCached(string key, out KeyMaterial? material)
    {
        if (_cache.TryGetValue(key, out var entry))
        {
            if (DateTimeOffset.UtcNow - entry.CachedAt <= _options.KekCacheLifetime)
            {
                material = entry.Material;
                return true;
            }
            _cache.TryRemove(key, out _);
        }
        material = null;
        return false;
    }

    private void Cache(string key, KeyMaterial material)
    {
        _cache[key] = (material, DateTimeOffset.UtcNow);
    }
}
