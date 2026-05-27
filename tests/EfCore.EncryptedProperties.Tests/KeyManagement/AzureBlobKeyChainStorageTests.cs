using Azure;
using EfCore.EncryptedProperties.KeyManagement;
using EfCore.EncryptedProperties.Tests.TestDoubles;

namespace EfCore.EncryptedProperties.Tests.KeyManagement;

public sealed class AzureBlobKeyChainStorageTests
{
    [Fact]
    public async Task GetOrActivateAsync_PersistsAcrossInstances()
    {
        var container = new InMemoryBlobContainerClient();
        var expected = CreateRecord("default", "wrapped-key");
        var storage = new AzureBlobKeyChainStorage(container, CreateOptions());

        await storage.GetOrActivateAsync("default", rotateBefore: null, expected);

        var reloadedStorage = new AzureBlobKeyChainStorage(container, CreateOptions());
        var active = await reloadedStorage.GetActiveAsync("default");

        Assert.NotNull(active);
        Assert.Equal(expected.Id, active.Id);
        Assert.Equal(expected.EncryptedKey, active.EncryptedKey);
    }

    [Fact]
    public async Task GetOrActivateAsync_ConcurrentCallers_CreateSingleActiveKey()
    {
        var container = new InMemoryBlobContainerClient();

        var tasks = Enumerable.Range(0, 20)
            .Select(index =>
            {
                var storage = new AzureBlobKeyChainStorage(container, CreateOptions(maxWriteAttempts: 32));
                return storage.GetOrActivateAsync(
                    "default",
                    rotateBefore: null,
                    CreateRecord("default", $"wrapped-key-{index}")).AsTask();
            });

        var returnedRecords = await Task.WhenAll(tasks);
        var readStorage = new AzureBlobKeyChainStorage(container, CreateOptions());
        var records = await readStorage.GetAllAsync();
        var activeRecord = Assert.Single(records, record => record.Purpose == "default" && record.IsActive);

        Assert.All(returnedRecords, record => Assert.Equal(activeRecord.Id, record.Id));
    }

    [Fact]
    public async Task GetOrActivateAsync_RetiresExpiredActiveKey()
    {
        var container = new InMemoryBlobContainerClient();
        var storage = new AzureBlobKeyChainStorage(container, CreateOptions());
        var oldRecord = CreateRecord("default", "old", DateTimeOffset.UtcNow.AddDays(-2));
        var newRecord = CreateRecord("default", "new");

        await storage.GetOrActivateAsync("default", rotateBefore: null, oldRecord);
        var active = await storage.GetOrActivateAsync("default", DateTimeOffset.UtcNow.AddDays(-1), newRecord);

        var records = await storage.GetAllAsync();
        Assert.Equal(newRecord.Id, active.Id);
        Assert.False(records.Single(record => record.Id == oldRecord.Id).IsActive);
        Assert.True(records.Single(record => record.Id == newRecord.Id).IsActive);
    }

    [Fact]
    public async Task GetByIdAsync_And_GetAllAsync_ReadAcrossPurposes()
    {
        var container = new InMemoryBlobContainerClient();
        var storage = new AzureBlobKeyChainStorage(container, CreateOptions());
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

    [Fact]
    public async Task GetActiveAsync_MissingPurpose_ReturnsNull()
    {
        var storage = new AzureBlobKeyChainStorage(new InMemoryBlobContainerClient(), CreateOptions());

        var active = await storage.GetActiveAsync("missing");

        Assert.Null(active);
    }

    [Fact]
    public async Task TryReplaceKeyAsync_UpdatesMatchingRecordOnly()
    {
        var container = new InMemoryBlobContainerClient();
        var storage = new AzureBlobKeyChainStorage(container, CreateOptions());
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

    [Fact]
    public void Constructor_InvalidOptions_Throws()
    {
        var container = new InMemoryBlobContainerClient();

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new AzureBlobKeyChainStorage(
                container,
                new AzureBlobKeyChainStorageOptions { MaxWriteAttempts = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new AzureBlobKeyChainStorage(
                container,
                new AzureBlobKeyChainStorageOptions { RetryDelay = TimeSpan.FromMilliseconds(-1) }));
    }

    [Fact]
    public async Task GetActiveAsync_WhenBlobPurposeDoesNotMatch_Throws()
    {
        var container = new InMemoryBlobContainerClient();
        var requestedPurpose = "expected";
        var blobName = $"scope/purpose-{KeyChainStorageDocuments.ComputePurposeHash(requestedPurpose)}.json";
        container.SetBlob(blobName, """
            {
              "formatVersion": 1,
              "purpose": "actual",
              "keys": []
            }
            """);
        var storage = new AzureBlobKeyChainStorage(
            container,
            CreateOptions(blobPrefix: "scope"));

        var ex = await Assert.ThrowsAsync<FormatException>(() =>
            storage.GetActiveAsync(requestedPurpose).AsTask());

        Assert.Contains("stores purpose 'actual'", ex.Message);
        Assert.Contains(requestedPurpose, ex.Message);
    }

    [Fact]
    public async Task GetOrActivateAsync_WhenWritesKeepConflicting_ThrowsLastConcurrencyFailure()
    {
        var container = new InMemoryBlobContainerClient
        {
            AlwaysFailUploadsWithStatus = 412
        };
        var storage = new AzureBlobKeyChainStorage(
            container,
            CreateOptions(maxWriteAttempts: 2));

        var ex = await Assert.ThrowsAsync<RequestFailedException>(() =>
            storage.GetOrActivateAsync(
                "default",
                rotateBefore: null,
                CreateRecord("default", "wrapped-key")).AsTask());

        Assert.Equal(412, ex.Status);
    }

    [Fact]
    public async Task CreateContainerIfNotExists_IsCalledOncePerStorageInstance()
    {
        var container = new InMemoryBlobContainerClient();
        var storage = new AzureBlobKeyChainStorage(
            container,
            CreateOptions(createContainerIfNotExists: true));

        await storage.GetActiveAsync("one");
        await storage.GetActiveAsync("two");

        Assert.Equal(1, container.CreateIfNotExistsCalls);
    }

    private static AzureBlobKeyChainStorageOptions CreateOptions(
        int maxWriteAttempts = 8,
        bool createContainerIfNotExists = false,
        string? blobPrefix = null)
    {
        return new AzureBlobKeyChainStorageOptions
        {
            MaxWriteAttempts = maxWriteAttempts,
            RetryDelay = TimeSpan.Zero,
            CreateContainerIfNotExists = createContainerIfNotExists,
            BlobPrefix = blobPrefix
        };
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
}
