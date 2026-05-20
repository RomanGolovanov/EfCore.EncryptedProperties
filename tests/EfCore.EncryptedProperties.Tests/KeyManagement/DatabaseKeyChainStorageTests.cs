using EfCore.EncryptedProperties.KeyManagement;
using Microsoft.Data.Sqlite;

namespace EfCore.EncryptedProperties.Tests.KeyManagement;

public sealed class DatabaseKeyChainStorageTests
{
    [Fact]
    public async Task GetOrActivateAsync_PersistsActiveKey()
    {
        var database = CreateDatabase();

        try
        {
            await CreateSchemaAsync(database.ConnectionString);
            var storage = new DatabaseKeyChainStorage(SqliteFactory.Instance, database.ConnectionString);
            var expected = CreateRecord("default", "wrapped");

            await storage.GetOrActivateAsync("default", rotateBefore: null, expected);
            var active = await storage.GetActiveAsync("default");

            Assert.NotNull(active);
            Assert.Equal(expected.Id, active.Id);
            Assert.Equal(expected.EncryptedKey, active.EncryptedKey);
        }
        finally
        {
            DropDatabase(database);
        }
    }

    [Fact]
    public async Task GetOrActivateAsync_ReturnsExistingActiveKey_WhenRotationNotNeeded()
    {
        var database = CreateDatabase();

        try
        {
            await CreateSchemaAsync(database.ConnectionString);
            var storage = new DatabaseKeyChainStorage(SqliteFactory.Instance, database.ConnectionString);
            var existing = CreateRecord("default", "existing");
            var candidate = CreateRecord("default", "candidate");

            await storage.GetOrActivateAsync("default", rotateBefore: null, existing);
            var active = await storage.GetOrActivateAsync("default", rotateBefore: null, candidate);
            var records = await storage.GetAllAsync();

            Assert.Equal(existing.Id, active.Id);
            Assert.DoesNotContain(records, record => record.Id == candidate.Id);
            Assert.Single(records, record => record.Purpose == "default" && record.IsActive);
        }
        finally
        {
            DropDatabase(database);
        }
    }

    [Fact]
    public async Task GetOrActivateAsync_RetiresExpiredActiveKey()
    {
        var database = CreateDatabase();

        try
        {
            await CreateSchemaAsync(database.ConnectionString);
            var storage = new DatabaseKeyChainStorage(SqliteFactory.Instance, database.ConnectionString);
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
            DropDatabase(database);
        }
    }

    [Fact]
    public async Task GetByIdAsync_And_GetAllAsync_ReadAcrossPurposes()
    {
        var database = CreateDatabase();

        try
        {
            await CreateSchemaAsync(database.ConnectionString);
            var storage = new DatabaseKeyChainStorage(SqliteFactory.Instance, database.ConnectionString);
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
            DropDatabase(database);
        }
    }

    [Fact]
    public async Task GetActiveAsync_MissingPurpose_ReturnsNull()
    {
        var database = CreateDatabase();

        try
        {
            await CreateSchemaAsync(database.ConnectionString);
            var storage = new DatabaseKeyChainStorage(SqliteFactory.Instance, database.ConnectionString);

            var active = await storage.GetActiveAsync("missing");

            Assert.Null(active);
        }
        finally
        {
            DropDatabase(database);
        }
    }

    [Fact]
    public async Task GetOrActivateAsync_InvalidCandidate_ThrowsBeforeWriting()
    {
        var database = CreateDatabase();

        try
        {
            var storage = new DatabaseKeyChainStorage(SqliteFactory.Instance, database.ConnectionString);
            var wrongPurpose = CreateRecord("actual", "wrapped");
            var inactive = CreateRecord("default", "wrapped", isActive: false);

            await Assert.ThrowsAsync<ArgumentException>(() =>
                storage.GetOrActivateAsync("expected", rotateBefore: null, wrongPurpose).AsTask());
            await Assert.ThrowsAsync<ArgumentException>(() =>
                storage.GetOrActivateAsync("default", rotateBefore: null, inactive).AsTask());
        }
        finally
        {
            DropDatabase(database);
        }
    }

    [Fact]
    public async Task GetOrActivateAsync_ConcurrentCallers_CreateSingleActiveKey()
    {
        var database = CreateDatabase();

        try
        {
            await CreateSchemaAsync(database.ConnectionString);

            var tasks = Enumerable.Range(0, 12).Select(index =>
            {
                var storage = new DatabaseKeyChainStorage(SqliteFactory.Instance, database.ConnectionString);
                return storage.GetOrActivateAsync(
                    "default",
                    rotateBefore: null,
                    CreateRecord("default", $"wrapped-{index}")).AsTask();
            });

            var returnedRecords = await Task.WhenAll(tasks);
            var readStorage = new DatabaseKeyChainStorage(SqliteFactory.Instance, database.ConnectionString);
            var records = await readStorage.GetAllAsync();
            var activeRecord = Assert.Single(records, r => r.Purpose == "default" && r.IsActive);

            Assert.All(returnedRecords, record => Assert.Equal(activeRecord.Id, record.Id));
        }
        finally
        {
            DropDatabase(database);
        }
    }

    private static EncryptedKeyRecord CreateRecord(
        string purpose,
        string encryptedKey,
        DateTimeOffset? createdAt = null,
        bool isActive = true)
    {
        return new EncryptedKeyRecord
        {
            Id = Guid.NewGuid(),
            Purpose = purpose,
            RsaKeyId = "rsa-key",
            Algorithm = "A256GCMKW",
            EncryptedKey = encryptedKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow,
            IsActive = isActive
        };
    }

    private static TestDatabase CreateDatabase()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"EfCoreEncryptedPropertiesTests_{Guid.NewGuid():N}.db");
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        };

        return new TestDatabase(path, builder.ConnectionString);
    }

    private static async Task CreateSchemaAsync(string connectionString)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE EncryptedPropertyKeks
            (
                Id TEXT NOT NULL PRIMARY KEY,
                Purpose TEXT NOT NULL,
                RsaKeyId TEXT NOT NULL,
                Algorithm TEXT NOT NULL,
                EncryptedKey TEXT NOT NULL,
                CreatedAt TEXT NOT NULL,
                IsActive INTEGER NOT NULL
            );

            CREATE INDEX IX_EncryptedPropertyKeks_Purpose_IsActive
                ON EncryptedPropertyKeks (Purpose, IsActive);

            CREATE UNIQUE INDEX UX_EncryptedPropertyKeks_ActivePurpose
                ON EncryptedPropertyKeks (Purpose)
                WHERE IsActive = 1;
            """;
        await command.ExecuteNonQueryAsync();
    }

    private static void DropDatabase(TestDatabase database)
    {
        DeleteIfExists(database.Path);
        DeleteIfExists(database.Path + "-shm");
        DeleteIfExists(database.Path + "-wal");
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
            File.Delete(path);
    }

    private sealed record TestDatabase(string Path, string ConnectionString);
}
