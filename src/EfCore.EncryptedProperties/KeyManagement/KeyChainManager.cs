using System.Collections.Concurrent;
using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EfCore.EncryptedProperties.KeyManagement;

internal sealed class KeyChainManager : IKeyChainManager
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
