using EfCore.EncryptedProperties.KeyManagement;
using Microsoft.Data.Sqlite;

namespace EfCore.EncryptedProperties.Tests.KeyManagement;

public sealed class DatabaseKeyChainStorageTests
{
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

    private static EncryptedKeyRecord CreateRecord(string purpose, string encryptedKey)
    {
        return new EncryptedKeyRecord
        {
            Id = Guid.NewGuid(),
            Purpose = purpose,
            RsaKeyId = "rsa-key",
            Algorithm = "A256GCMKW",
            EncryptedKey = encryptedKey,
            CreatedAt = DateTimeOffset.UtcNow,
            IsActive = true
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
