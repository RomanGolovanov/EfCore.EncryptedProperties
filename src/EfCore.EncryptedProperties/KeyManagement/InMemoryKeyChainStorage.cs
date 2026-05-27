using System.Collections.Concurrent;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class InMemoryKeyChainStorage : IRewrappableKeyChainStorage
{
    private readonly ConcurrentDictionary<string, EncryptedKeyRecord> _records = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _purposeLocks = new();

    public ValueTask<EncryptedKeyRecord?> GetActiveAsync(string purpose, CancellationToken cancellationToken = default)
    {
        var record = _records.Values
            .Where(r => r.Purpose == purpose && r.IsActive)
            .OrderByDescending(r => r.CreatedAt)
            .FirstOrDefault();
        return new ValueTask<EncryptedKeyRecord?>(record);
    }

    public async ValueTask<EncryptedKeyRecord> GetOrActivateAsync(
        string purpose,
        DateTimeOffset? rotateBefore,
        EncryptedKeyRecord candidate,
        CancellationToken cancellationToken = default)
    {
        ValidateCandidate(purpose, candidate);

        var semaphore = _purposeLocks.GetOrAdd(purpose, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(cancellationToken);
        try
        {
            var active = _records.Values
                .Where(r => r.Purpose == purpose && r.IsActive)
                .OrderByDescending(r => r.CreatedAt)
                .FirstOrDefault();

            if (active is not null && IsActiveKeyValid(active, rotateBefore))
                return active;

            foreach (var existing in _records.Values.Where(r => r.Purpose == purpose && r.IsActive).ToList())
            {
                _records[existing.Id.ToString()] = new EncryptedKeyRecord
                {
                    Id = existing.Id,
                    Purpose = existing.Purpose,
                    RsaKeyId = existing.RsaKeyId,
                    Algorithm = existing.Algorithm,
                    EncryptedKey = existing.EncryptedKey,
                    CreatedAt = existing.CreatedAt,
                    IsActive = false
                };
            }

            _records[candidate.Id.ToString()] = candidate;
            return candidate;
        }
        finally
        {
            semaphore.Release();
        }
    }

    public ValueTask<EncryptedKeyRecord?> GetByIdAsync(string keyId, CancellationToken cancellationToken = default)
    {
        _records.TryGetValue(keyId, out var record);
        return new ValueTask<EncryptedKeyRecord?>(record);
    }

    public ValueTask<IReadOnlyList<EncryptedKeyRecord>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<EncryptedKeyRecord> all = _records.Values.ToList();
        return new ValueTask<IReadOnlyList<EncryptedKeyRecord>>(all);
    }

    public ValueTask<bool> TryReplaceKeyAsync(
        EncryptedKeyRecord original,
        EncryptedKeyRecord replacement,
        CancellationToken cancellationToken = default)
    {
        KeyChainStorageDocuments.ValidateReplacement(original, replacement);
        cancellationToken.ThrowIfCancellationRequested();

        var key = original.Id.ToString();
        while (true)
        {
            if (!_records.TryGetValue(key, out var current))
                return new ValueTask<bool>(false);

            if (!KeyChainStorageDocuments.WrapMatches(current, original))
                return new ValueTask<bool>(false);

            if (_records.TryUpdate(key, replacement, current))
                return new ValueTask<bool>(true);
        }
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
}
