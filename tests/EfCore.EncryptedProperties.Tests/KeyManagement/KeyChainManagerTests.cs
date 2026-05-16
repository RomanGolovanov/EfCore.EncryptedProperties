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
}
