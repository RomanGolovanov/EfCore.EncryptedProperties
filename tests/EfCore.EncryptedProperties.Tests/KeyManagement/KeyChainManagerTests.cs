using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.KeyManagement;
using EfCore.EncryptedProperties.Providers;

namespace EfCore.EncryptedProperties.Tests.KeyManagement;

public class KeyChainManagerTests
{
    private readonly InMemoryKeyChainStorage _storage;
    private readonly KeyChainManager _manager;

    public KeyChainManagerTests()
    {
        var rsa = RSA.Create(2048);
        var rsaProvider = new InMemoryRsaKeyProvider(rsa, "test-key");
        _storage = new InMemoryKeyChainStorage();
        var options = new EncryptedPropertiesOptions();
        _manager = new KeyChainManager(_storage, rsaProvider, options);
    }

    [Fact]
    public async Task GetActiveKeyAsync_CreatesNewKey_WhenNoneExists()
    {
        var key = await _manager.GetActiveKeyAsync("default");

        Assert.NotNull(key);
        Assert.Equal(32, key.Key.Length);
        Assert.Equal("A256GCMKW", key.Algorithm);
    }

    [Fact]
    public async Task GetActiveKeyAsync_ReturnsCachedKey_OnSubsequentCalls()
    {
        var key1 = await _manager.GetActiveKeyAsync("default");
        var key2 = await _manager.GetActiveKeyAsync("default");

        Assert.Equal(key1.KeyId, key2.KeyId);
        Assert.Equal(key1.Key, key2.Key);
    }

    [Fact]
    public async Task GetActiveKeyAsync_DifferentPurposes_DifferentKeys()
    {
        var key1 = await _manager.GetActiveKeyAsync("purpose1");
        var key2 = await _manager.GetActiveKeyAsync("purpose2");

        Assert.NotEqual(key1.KeyId, key2.KeyId);
    }

    [Fact]
    public async Task GetKeyForDecryptAsync_ReturnsKey_ById()
    {
        var activeKey = await _manager.GetActiveKeyAsync("default");
        var decryptKey = await _manager.GetKeyForDecryptAsync(activeKey.KeyId);

        Assert.Equal(activeKey.Key, decryptKey.Key);
    }

    [Fact]
    public async Task GetKeyForDecryptAsync_UnknownId_Throws()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _manager.GetKeyForDecryptAsync(Guid.NewGuid().ToString()).AsTask());
    }

    [Fact]
    public async Task PreloadAsync_PopulatesCache()
    {
        var rsa = RSA.Create(2048);
        var rsaProvider = new InMemoryRsaKeyProvider(rsa, "test-key");
        var storage = new InMemoryKeyChainStorage();
        var manager1 = new KeyChainManager(storage, rsaProvider, new EncryptedPropertiesOptions());
        var key = await manager1.GetActiveKeyAsync("default");

        var manager2 = new KeyChainManager(storage, rsaProvider, new EncryptedPropertiesOptions());
        await manager2.PreloadAsync();

        var loaded = await manager2.GetKeyForDecryptAsync(key.KeyId);
        Assert.Equal(key.Key, loaded.Key);
    }

    [Fact]
    public async Task Rotation_CreatesNewKey_WhenPolicyTriggered()
    {
        var rsa = RSA.Create(2048);
        var rsaProvider = new InMemoryRsaKeyProvider(rsa, "test-key");
        var storage = new InMemoryKeyChainStorage();
        var options = new EncryptedPropertiesOptions
        {
            KekCacheLifetime = TimeSpan.Zero
        };
        options.RotationPolicy.KeyRotateAfter = TimeSpan.Zero;
        var manager = new KeyChainManager(storage, rsaProvider, options);

        var key1 = await manager.GetActiveKeyAsync("default");

        await Task.Delay(10);

        var key2 = await manager.GetActiveKeyAsync("default");

        Assert.NotEqual(key1.KeyId, key2.KeyId);

        var oldKey = await manager.GetKeyForDecryptAsync(key1.KeyId);
        Assert.Equal(key1.Key, oldKey.Key);
    }

    [Fact]
    public async Task PreloadAsync_LoadsAllKeys()
    {
        var rsa = RSA.Create(2048);
        var rsaProvider = new InMemoryRsaKeyProvider(rsa, "test-key");
        var storage = new InMemoryKeyChainStorage();
        var options = new EncryptedPropertiesOptions();
        var manager1 = new KeyChainManager(storage, rsaProvider, options);

        var key1 = await manager1.GetActiveKeyAsync("purpose1");
        var key2 = await manager1.GetActiveKeyAsync("purpose2");

        var manager2 = new KeyChainManager(storage, rsaProvider, options);
        await manager2.PreloadAsync();

        var loaded1 = await manager2.GetKeyForDecryptAsync(key1.KeyId);
        var loaded2 = await manager2.GetKeyForDecryptAsync(key2.KeyId);

        Assert.Equal(key1.Key, loaded1.Key);
        Assert.Equal(key2.Key, loaded2.Key);
    }

    [Fact]
    public async Task RewrapAsync_RewrapsExistingKekToCurrentRsaKey()
    {
        using var rsaV1 = RSA.Create(2048);
        using var rsaV2 = RSA.Create(2048);
        var storage = new InMemoryKeyChainStorage();
        var managerV1 = new KeyChainManager(
            storage,
            new TestRsaKeyRingProvider("rsa-v1", ("rsa-v1", rsaV1)),
            new EncryptedPropertiesOptions());
        var originalKey = await managerV1.GetActiveKeyAsync("default");
        var originalRecord = Assert.Single(await storage.GetAllAsync());

        var managerV2 = new KeyChainManager(
            storage,
            new TestRsaKeyRingProvider("rsa-v2", ("rsa-v1", rsaV1), ("rsa-v2", rsaV2)),
            new EncryptedPropertiesOptions());

        var result = await managerV2.RewrapAsync();

        Assert.Equal(1, result.ScannedCount);
        Assert.Equal(1, result.EligibleCount);
        Assert.Equal(1, result.RewrappedCount);
        Assert.Equal(0, result.AlreadyCurrentCount);
        var rewrappedRecord = Assert.Single(await storage.GetAllAsync());
        Assert.Equal(originalRecord.Id, rewrappedRecord.Id);
        Assert.Equal("rsa-v2", rewrappedRecord.RsaKeyId);
        Assert.NotEqual(originalRecord.EncryptedKey, rewrappedRecord.EncryptedKey);

        var managerV2Only = new KeyChainManager(
            storage,
            new TestRsaKeyRingProvider("rsa-v2", ("rsa-v2", rsaV2)),
            new EncryptedPropertiesOptions());
        var decryptedKey = await managerV2Only.GetKeyForDecryptAsync(originalKey.KeyId);
        Assert.Equal(originalKey.Key, decryptedKey.Key);
    }

    [Fact]
    public async Task RewrapAsync_RewrapsActiveAndInactiveKeys()
    {
        using var rsaV1 = RSA.Create(2048);
        using var rsaV2 = RSA.Create(2048);
        var storage = new InMemoryKeyChainStorage();
        var options = new EncryptedPropertiesOptions
        {
            KekCacheLifetime = TimeSpan.Zero
        };
        options.RotationPolicy.KeyRotateAfter = TimeSpan.Zero;
        var managerV1 = new KeyChainManager(
            storage,
            new TestRsaKeyRingProvider("rsa-v1", ("rsa-v1", rsaV1)),
            options);

        await managerV1.GetActiveKeyAsync("default");
        await Task.Delay(10);
        await managerV1.GetActiveKeyAsync("default");

        var before = await storage.GetAllAsync();
        Assert.Equal(2, before.Count);
        Assert.Contains(before, record => !record.IsActive);
        Assert.Contains(before, record => record.IsActive);

        var managerV2 = new KeyChainManager(
            storage,
            new TestRsaKeyRingProvider("rsa-v2", ("rsa-v1", rsaV1), ("rsa-v2", rsaV2)),
            new EncryptedPropertiesOptions());

        var result = await managerV2.RewrapAsync();

        Assert.Equal(2, result.RewrappedCount);
        Assert.All(await storage.GetAllAsync(), record => Assert.Equal("rsa-v2", record.RsaKeyId));
    }

    [Fact]
    public async Task RewrapAsync_HonorsPurposeOldRsaKeyAndDryRunOptions()
    {
        using var rsaV1 = RSA.Create(2048);
        using var rsaV2 = RSA.Create(2048);
        var storage = new InMemoryKeyChainStorage();
        var managerV1 = new KeyChainManager(
            storage,
            new TestRsaKeyRingProvider("rsa-v1", ("rsa-v1", rsaV1)),
            new EncryptedPropertiesOptions());
        await managerV1.GetActiveKeyAsync("email");
        await managerV1.GetActiveKeyAsync("notes");

        var managerV2 = new KeyChainManager(
            storage,
            new TestRsaKeyRingProvider("rsa-v2", ("rsa-v1", rsaV1), ("rsa-v2", rsaV2)),
            new EncryptedPropertiesOptions());

        var skipped = await managerV2.RewrapAsync(new KeyChainRewrapOptions
        {
            Purpose = "email",
            OldRsaKeyId = "missing-rsa",
            DryRun = true
        });
        Assert.Equal(2, skipped.ScannedCount);
        Assert.Equal(0, skipped.EligibleCount);

        var dryRun = await managerV2.RewrapAsync(new KeyChainRewrapOptions
        {
            Purpose = "email",
            OldRsaKeyId = "rsa-v1",
            DryRun = true
        });

        Assert.Equal(2, dryRun.ScannedCount);
        Assert.Equal(1, dryRun.EligibleCount);
        Assert.Equal(0, dryRun.RewrappedCount);
        Assert.Equal(1, dryRun.WouldRewrapCount);
        Assert.Equal(KeyChainRewrapStatus.WouldRewrap, Assert.Single(dryRun.Records).Status);
        Assert.All(await storage.GetAllAsync(), record => Assert.Equal("rsa-v1", record.RsaKeyId));

        var result = await managerV2.RewrapAsync(new KeyChainRewrapOptions
        {
            Purpose = "email",
            OldRsaKeyId = "rsa-v1"
        });

        Assert.Equal(1, result.RewrappedCount);
        var records = await storage.GetAllAsync();
        Assert.Equal("rsa-v2", records.Single(record => record.Purpose == "email").RsaKeyId);
        Assert.Equal("rsa-v1", records.Single(record => record.Purpose == "notes").RsaKeyId);
    }

    [Fact]
    public async Task RewrapAsync_SkipsAlreadyCurrentKeks()
    {
        using var rsa = RSA.Create(2048);
        var storage = new InMemoryKeyChainStorage();
        var manager = new KeyChainManager(
            storage,
            new TestRsaKeyRingProvider("rsa-v1", ("rsa-v1", rsa)),
            new EncryptedPropertiesOptions());
        await manager.GetActiveKeyAsync("default");
        var before = Assert.Single(await storage.GetAllAsync());

        var result = await manager.RewrapAsync();

        Assert.Equal(1, result.ScannedCount);
        Assert.Equal(1, result.EligibleCount);
        Assert.Equal(0, result.RewrappedCount);
        Assert.Equal(1, result.AlreadyCurrentCount);
        Assert.Equal(KeyChainRewrapStatus.AlreadyCurrent, Assert.Single(result.Records).Status);
        var after = Assert.Single(await storage.GetAllAsync());
        Assert.Equal(before.EncryptedKey, after.EncryptedKey);
    }

    [Fact]
    public async Task GetActiveKeyAsync_StoresWrapResultRsaKeyId()
    {
        var rsaProvider = new TrackingRsaKeyProvider("configured-key", "versioned-key-id");
        var storage = new InMemoryKeyChainStorage();
        var manager = new KeyChainManager(storage, rsaProvider, new EncryptedPropertiesOptions());

        await manager.GetActiveKeyAsync("default");

        var record = Assert.Single(await storage.GetAllAsync());
        Assert.Equal("versioned-key-id", record.RsaKeyId);
    }

    [Fact]
    public async Task GetKeyForDecryptAsync_UsesStoredRsaKeyId()
    {
        var rsaProvider = new TrackingRsaKeyProvider("configured-key", "versioned-key-id");
        var storage = new InMemoryKeyChainStorage();
        var manager1 = new KeyChainManager(storage, rsaProvider, new EncryptedPropertiesOptions());
        var key = await manager1.GetActiveKeyAsync("default");

        rsaProvider.UnwrapRsaKeyIds.Clear();
        var manager2 = new KeyChainManager(storage, rsaProvider, new EncryptedPropertiesOptions());
        await manager2.GetKeyForDecryptAsync(key.KeyId);

        Assert.Contains("versioned-key-id", rsaProvider.UnwrapRsaKeyIds);
    }

    [Fact]
    public async Task PreloadAsync_UsesStoredRsaKeyId()
    {
        var rsaProvider = new TrackingRsaKeyProvider("configured-key", "versioned-key-id");
        var storage = new InMemoryKeyChainStorage();
        var manager1 = new KeyChainManager(storage, rsaProvider, new EncryptedPropertiesOptions());
        await manager1.GetActiveKeyAsync("default");

        rsaProvider.UnwrapRsaKeyIds.Clear();
        var manager2 = new KeyChainManager(storage, rsaProvider, new EncryptedPropertiesOptions());
        await manager2.PreloadAsync();

        Assert.Contains("versioned-key-id", rsaProvider.UnwrapRsaKeyIds);
    }

    [Fact]
    public async Task InMemoryStorage_GetOrActivateAsync_ConcurrentCandidates_ReturnsSingleActiveKey()
    {
        var storage = new InMemoryKeyChainStorage();

        var tasks = Enumerable.Range(0, 20)
            .Select(index => storage.GetOrActivateAsync(
                "default",
                rotateBefore: null,
                CreateRecord("default", $"key-{index}")).AsTask());

        var records = await Task.WhenAll(tasks);
        var activeRecords = (await storage.GetAllAsync()).Where(r => r.IsActive).ToList();

        Assert.Single(activeRecords);
        Assert.All(records, record => Assert.Equal(activeRecords[0].Id, record.Id));
    }

    [Fact]
    public async Task InMemoryStorage_GetOrActivateAsync_RetiresExpiredActiveKey()
    {
        var storage = new InMemoryKeyChainStorage();
        var oldRecord = CreateRecord("default", "old", DateTimeOffset.UtcNow.AddDays(-2));
        var newRecord = CreateRecord("default", "new");

        await storage.GetOrActivateAsync("default", rotateBefore: null, oldRecord);
        var active = await storage.GetOrActivateAsync("default", DateTimeOffset.UtcNow.AddDays(-1), newRecord);

        var records = await storage.GetAllAsync();
        Assert.Equal(newRecord.Id, active.Id);
        Assert.False(records.Single(r => r.Id == oldRecord.Id).IsActive);
        Assert.True(records.Single(r => r.Id == newRecord.Id).IsActive);
    }

    [Fact]
    public async Task InMemoryStorage_TryReplaceKeyAsync_UpdatesMatchingRecordOnly()
    {
        var storage = new InMemoryKeyChainStorage();
        var original = CreateRecord("default", "old");
        await storage.GetOrActivateAsync("default", rotateBefore: null, original);

        var replacement = CreateReplacement(original);
        var replaced = await storage.TryReplaceKeyAsync(original, replacement);

        Assert.True(replaced);
        var current = Assert.Single(await storage.GetAllAsync());
        Assert.Equal(original.Id, current.Id);
        Assert.Equal("rsa-v2", current.RsaKeyId);
        Assert.Equal("new", current.EncryptedKey);
        Assert.Equal(original.IsActive, current.IsActive);

        var staleReplacement = CreateReplacement(original, "rsa-v3", "newer");
        var staleReplaced = await storage.TryReplaceKeyAsync(original, staleReplacement);

        Assert.False(staleReplaced);
        current = Assert.Single(await storage.GetAllAsync());
        Assert.Equal("rsa-v2", current.RsaKeyId);
        Assert.Equal("new", current.EncryptedKey);
    }

    private static EncryptedKeyRecord CreateRecord(
        string purpose,
        string encryptedKey,
        DateTimeOffset? createdAt = null)
    {
        return new EncryptedKeyRecord
        {
            Id = Guid.NewGuid(),
            Purpose = purpose,
            RsaKeyId = "rsa-key",
            Algorithm = "A256GCMKW",
            EncryptedKey = encryptedKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow,
            IsActive = true
        };
    }

    private static EncryptedKeyRecord CreateReplacement(
        EncryptedKeyRecord original,
        string rsaKeyId = "rsa-v2",
        string encryptedKey = "new")
    {
        return new EncryptedKeyRecord
        {
            Id = original.Id,
            Purpose = original.Purpose,
            RsaKeyId = rsaKeyId,
            Algorithm = original.Algorithm,
            EncryptedKey = encryptedKey,
            CreatedAt = original.CreatedAt,
            IsActive = original.IsActive
        };
    }

    private sealed class TrackingRsaKeyProvider : IRsaKeyProvider
    {
        private readonly RSA _rsa = RSA.Create(2048);
        private readonly string _wrapRsaKeyId;

        public TrackingRsaKeyProvider(string keyId, string wrapRsaKeyId)
        {
            KeyId = keyId;
            _wrapRsaKeyId = wrapRsaKeyId;
        }

        public List<string> UnwrapRsaKeyIds { get; } = new();
        public string KeyId { get; }
        public string Algorithm => "RSA-OAEP-256";

        public ValueTask<RsaKeyWrapResult> WrapKeyAsync(
            byte[] plaintext,
            CancellationToken cancellationToken = default)
        {
            var ciphertext = _rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
            return new ValueTask<RsaKeyWrapResult>(
                new RsaKeyWrapResult(ciphertext, _wrapRsaKeyId, Algorithm));
        }

        public ValueTask<byte[]> UnwrapKeyAsync(
            byte[] ciphertext,
            string rsaKeyId,
            CancellationToken cancellationToken = default)
        {
            UnwrapRsaKeyIds.Add(rsaKeyId);
            return new ValueTask<byte[]>(_rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));
        }
    }

    private sealed class TestRsaKeyRingProvider : IRsaKeyProvider
    {
        private readonly Dictionary<string, RSA> _keys;

        public TestRsaKeyRingProvider(string currentKeyId, params (string KeyId, RSA Rsa)[] keys)
        {
            KeyId = currentKeyId;
            _keys = keys.ToDictionary(key => key.KeyId, key => key.Rsa, StringComparer.Ordinal);
        }

        public string KeyId { get; }
        public string Algorithm => "RSA-OAEP-256";

        public ValueTask<RsaKeyWrapResult> WrapKeyAsync(
            byte[] plaintext,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ciphertext = _keys[KeyId].Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
            return new ValueTask<RsaKeyWrapResult>(new RsaKeyWrapResult(ciphertext, KeyId, Algorithm));
        }

        public ValueTask<byte[]> UnwrapKeyAsync(
            byte[] ciphertext,
            string rsaKeyId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_keys.TryGetValue(rsaKeyId, out var rsa))
                throw new InvalidOperationException($"RSA key '{rsaKeyId}' is not configured.");

            return new ValueTask<byte[]>(rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));
        }
    }
}
