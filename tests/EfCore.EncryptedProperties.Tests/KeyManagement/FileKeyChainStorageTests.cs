using EfCore.EncryptedProperties.KeyManagement;

namespace EfCore.EncryptedProperties.Tests.KeyManagement;

public sealed class FileKeyChainStorageTests
{
    [Fact]
    public async Task GetOrActivateAsync_PersistsAcrossInstances()
    {
        var directory = CreateTempDirectory();

        try
        {
            var expected = CreateRecord("default", "wrapped-key");
            var storage = new FileKeyChainStorage(directory);

            await storage.GetOrActivateAsync("default", rotateBefore: null, expected);

            var reloadedStorage = new FileKeyChainStorage(directory);
            var active = await reloadedStorage.GetActiveAsync("default");

            Assert.NotNull(active);
            Assert.Equal(expected.Id, active.Id);
            Assert.Equal(expected.EncryptedKey, active.EncryptedKey);
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task GetOrActivateAsync_ConcurrentCallers_CreateSingleActiveKey()
    {
        var directory = CreateTempDirectory();

        try
        {
            var tasks = Enumerable.Range(0, 20)
                .Select(index =>
                {
                    var storage = new FileKeyChainStorage(directory);
                    return storage.GetOrActivateAsync(
                        "default",
                        rotateBefore: null,
                        CreateRecord("default", $"wrapped-key-{index}")).AsTask();
                });

            var returnedRecords = await Task.WhenAll(tasks);
            var readStorage = new FileKeyChainStorage(directory);
            var records = await readStorage.GetAllAsync();
            var activeRecord = Assert.Single(records, record => record.Purpose == "default" && record.IsActive);

            Assert.All(returnedRecords, record => Assert.Equal(activeRecord.Id, record.Id));
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task GetOrActivateAsync_RetiresExpiredActiveKey()
    {
        var directory = CreateTempDirectory();

        try
        {
            var storage = new FileKeyChainStorage(directory);
            var oldRecord = CreateRecord("default", "old", DateTimeOffset.UtcNow.AddDays(-2));
            var newRecord = CreateRecord("default", "new");

            await storage.GetOrActivateAsync("default", rotateBefore: null, oldRecord);
            var active = await storage.GetOrActivateAsync("default", DateTimeOffset.UtcNow.AddDays(-1), newRecord);

            var records = await storage.GetAllAsync();
            Assert.Equal(newRecord.Id, active.Id);
            Assert.False(records.Single(record => record.Id == oldRecord.Id).IsActive);
            Assert.True(records.Single(record => record.Id == newRecord.Id).IsActive);
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task GetByIdAsync_And_GetAllAsync_ReadAcrossPurposes()
    {
        var directory = CreateTempDirectory();

        try
        {
            var storage = new FileKeyChainStorage(directory);
            var emailRecord = CreateRecord("email", "email-key");
            var notesRecord = CreateRecord("notes", "notes-key");

            await storage.GetOrActivateAsync("email", rotateBefore: null, emailRecord);
            await storage.GetOrActivateAsync("notes", rotateBefore: null, notesRecord);

            var loaded = await storage.GetByIdAsync(notesRecord.Id.ToString());
            var missing = await storage.GetByIdAsync("not-a-guid");
            var all = await storage.GetAllAsync();

            Assert.NotNull(loaded);
            Assert.Equal(notesRecord.Id, loaded.Id);
            Assert.Equal("notes", loaded.Purpose);
            Assert.Null(missing);
            Assert.Contains(all, record => record.Id == emailRecord.Id);
            Assert.Contains(all, record => record.Id == notesRecord.Id);
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task TryReplaceKeyAsync_UpdatesMatchingRecordOnly()
    {
        var directory = CreateTempDirectory();

        try
        {
            var storage = new FileKeyChainStorage(directory);
            var original = CreateRecord("default", "old");
            await storage.GetOrActivateAsync("default", rotateBefore: null, original);

            var replacement = CreateReplacement(original);
            var replaced = await storage.TryReplaceKeyAsync(original, replacement);

            Assert.True(replaced);
            var reloadedStorage = new FileKeyChainStorage(directory);
            var current = Assert.Single(await reloadedStorage.GetAllAsync());
            Assert.Equal(original.Id, current.Id);
            Assert.Equal("rsa-v2", current.RsaKeyId);
            Assert.Equal("new", current.EncryptedKey);
            Assert.Equal(original.IsActive, current.IsActive);

            var staleReplacement = CreateReplacement(original, "rsa-v3", "newer");
            var staleReplaced = await storage.TryReplaceKeyAsync(original, staleReplacement);

            Assert.False(staleReplaced);
            current = Assert.Single(await reloadedStorage.GetAllAsync());
            Assert.Equal("rsa-v2", current.RsaKeyId);
            Assert.Equal("new", current.EncryptedKey);
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public void Constructor_MissingDirectoryPath_Throws()
    {
        Assert.Throws<ArgumentException>(() => new FileKeyChainStorage(" "));
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

    private static string CreateTempDirectory()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"EfCoreEncryptedPropertiesTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static void DeleteDirectory(string directory)
    {
        if (Directory.Exists(directory))
            Directory.Delete(directory, recursive: true);
    }
}
