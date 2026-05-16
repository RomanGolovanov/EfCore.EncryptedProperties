using EfCore.EncryptedProperties.KeyManagement;
using Microsoft.Data.SqlClient;

namespace EfCore.EncryptedProperties.Tests.KeyManagement;

public sealed class DatabaseKeyChainStorageTests
{
    [Fact]
    public async Task GetOrActivateAsync_ConcurrentCallers_CreateSingleActiveKey()
    {
        var database = await TryCreateDatabaseAsync();
        if (database is null)
            return;

        try
        {
            await CreateSchemaAsync(database.ConnectionString);

            var tasks = Enumerable.Range(0, 12).Select(index =>
            {
                var storage = new DatabaseKeyChainStorage(SqlClientFactory.Instance, database.ConnectionString);
                return storage.GetOrActivateAsync(
                    "default",
                    rotateBefore: null,
                    CreateRecord("default", $"wrapped-{index}")).AsTask();
            });

            var returnedRecords = await Task.WhenAll(tasks);
            var readStorage = new DatabaseKeyChainStorage(SqlClientFactory.Instance, database.ConnectionString);
            var records = await readStorage.GetAllAsync();
            var activeRecord = Assert.Single(records, r => r.Purpose == "default" && r.IsActive);

            Assert.All(returnedRecords, record => Assert.Equal(activeRecord.Id, record.Id));
        }
        finally
        {
            await DropDatabaseAsync(database.Name);
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

    private static async Task<TestDatabase?> TryCreateDatabaseAsync()
    {
        var name = $"EfCoreEncryptedPropertiesTests_{Guid.NewGuid():N}";

        try
        {
            await using var connection = new SqlConnection(GetMasterConnectionString());
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"CREATE DATABASE [{name}]";
            await command.ExecuteNonQueryAsync();
        }
        catch (SqlException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        var builder = new SqlConnectionStringBuilder(GetMasterConnectionString())
        {
            InitialCatalog = name
        };

        return new TestDatabase(name, builder.ConnectionString);
    }

    private static async Task CreateSchemaAsync(string connectionString)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE EncryptedPropertyKeks
            (
                Id uniqueidentifier NOT NULL PRIMARY KEY,
                Purpose nvarchar(128) NOT NULL,
                RsaKeyId nvarchar(512) NOT NULL,
                Algorithm nvarchar(64) NOT NULL,
                EncryptedKey nvarchar(max) NOT NULL,
                CreatedAt datetimeoffset NOT NULL,
                IsActive bit NOT NULL
            );

            CREATE INDEX IX_EncryptedPropertyKeks_Purpose_IsActive
                ON EncryptedPropertyKeks (Purpose, IsActive);

            CREATE UNIQUE INDEX UX_EncryptedPropertyKeks_ActivePurpose
                ON EncryptedPropertyKeks (Purpose)
                WHERE IsActive = 1;
            """;
        await command.ExecuteNonQueryAsync();
    }

    private static async Task DropDatabaseAsync(string name)
    {
        try
        {
            await using var connection = new SqlConnection(GetMasterConnectionString());
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"""
                ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                DROP DATABASE [{name}];
                """;
            await command.ExecuteNonQueryAsync();
        }
        catch (SqlException)
        {
        }
    }

    private static string GetMasterConnectionString()
    {
        return "Server=(localdb)\\MSSQLLocalDB;Database=master;Trusted_Connection=True;TrustServerCertificate=True;";
    }

    private sealed record TestDatabase(string Name, string ConnectionString);
}
