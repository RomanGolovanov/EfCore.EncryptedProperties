using System.Data;
using System.Data.Common;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.KeyManagement;

internal sealed class DatabaseKeyChainStorage : IRewrappableKeyChainStorage
{
    private const string ColumnList = "Id, Purpose, RsaKeyId, Algorithm, EncryptedKey, CreatedAt, IsActive";

    private readonly DbProviderFactory _providerFactory;
    private readonly string _connectionString;
    private readonly DatabaseDialect _dialect;

    public DatabaseKeyChainStorage(DbProviderFactory providerFactory, string connectionString)
    {
        ArgumentNullException.ThrowIfNull(providerFactory);
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be null or whitespace.", nameof(connectionString));

        using var connection = providerFactory.CreateConnection()
            ?? throw new InvalidOperationException(
                $"The database key chain provider factory '{providerFactory.GetType().FullName}' returned null from CreateConnection().");

        _providerFactory = providerFactory;
        _connectionString = connectionString;
        _dialect = DetectDialect(connection);
    }

    public async ValueTask<EncryptedKeyRecord?> GetActiveAsync(string purpose, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenSeparateConnectionAsync(cancellationToken);
        return await GetActiveAsync(connection, transaction: null, purpose, useUpdateLock: false, cancellationToken);
    }

    public async ValueTask<EncryptedKeyRecord> GetOrActivateAsync(
        string purpose,
        DateTimeOffset? rotateBefore,
        EncryptedKeyRecord candidate,
        CancellationToken cancellationToken = default)
    {
        ValidateCandidate(purpose, candidate);

        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return await GetOrActivateCoreAsync(purpose, rotateBefore, candidate, cancellationToken);
            }
            catch (DbException ex) when (attempt < 5 && IsRetryableConcurrencyError(ex))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(25 * (attempt + 1)), cancellationToken);
            }
        }
    }

    private async ValueTask<EncryptedKeyRecord> GetOrActivateCoreAsync(
        string purpose,
        DateTimeOffset? rotateBefore,
        EncryptedKeyRecord candidate,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenSeparateConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            var active = await GetActiveAsync(connection, transaction, purpose, useUpdateLock: true, cancellationToken);
            if (active is not null && IsActiveKeyValid(active, rotateBefore))
            {
                await transaction.CommitAsync(cancellationToken);
                return active;
            }

            await RetireActiveAsync(connection, transaction, purpose, cancellationToken);
            await InsertAsync(connection, transaction, candidate, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return candidate;
        }
        catch
        {
            try
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }
            catch
            {
                // Preserve the original failure.
            }

            throw;
        }
    }

    private async ValueTask<EncryptedKeyRecord?> GetActiveAsync(
        DbConnection connection,
        DbTransaction? transaction,
        string purpose,
        bool useUpdateLock,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = CreateGetActiveSql(useUpdateLock);
        AddParameter(command, "@purpose", DbType.String, purpose);
        AddParameter(command, "@isActive", DbType.Boolean, true);

        await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? MapToRecord(reader)
            : null;
    }

    public async ValueTask<EncryptedKeyRecord?> GetByIdAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(keyId, out var id))
            return null;

        await using var connection = await OpenSeparateConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT {ColumnList}
            FROM EncryptedPropertyKeks
            WHERE Id = @id
            """;
        AddParameter(command, "@id", DbType.Guid, id);

        await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? MapToRecord(reader)
            : null;
    }

    public async ValueTask<IReadOnlyList<EncryptedKeyRecord>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenSeparateConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {ColumnList} FROM EncryptedPropertyKeks";

        var records = new List<EncryptedKeyRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            records.Add(MapToRecord(reader));

        return records;
    }

    public async ValueTask<bool> TryReplaceKeyAsync(
        EncryptedKeyRecord original,
        EncryptedKeyRecord replacement,
        CancellationToken cancellationToken = default)
    {
        KeyChainStorageDocuments.ValidateReplacement(original, replacement);

        await using var connection = await OpenSeparateConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE EncryptedPropertyKeks
            SET RsaKeyId = @newRsaKeyId, EncryptedKey = @newEncryptedKey
            WHERE Id = @id AND RsaKeyId = @oldRsaKeyId AND EncryptedKey = @oldEncryptedKey
            """;
        AddParameter(command, "@newRsaKeyId", DbType.String, replacement.RsaKeyId);
        AddParameter(command, "@newEncryptedKey", DbType.String, replacement.EncryptedKey);
        AddParameter(command, "@id", DbType.Guid, original.Id);
        AddParameter(command, "@oldRsaKeyId", DbType.String, original.RsaKeyId);
        AddParameter(command, "@oldEncryptedKey", DbType.String, original.EncryptedKey);

        var affectedRows = await command.ExecuteNonQueryAsync(cancellationToken);
        return affectedRows == 1;
    }

    private static async ValueTask InsertAsync(
        DbConnection connection,
        DbTransaction transaction,
        EncryptedKeyRecord record,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO EncryptedPropertyKeks (Id, Purpose, RsaKeyId, Algorithm, EncryptedKey, CreatedAt, IsActive)
            VALUES (@id, @purpose, @rsaKeyId, @algorithm, @encryptedKey, @createdAt, @isActive)
            """;
        AddParameter(command, "@id", DbType.Guid, record.Id);
        AddParameter(command, "@purpose", DbType.String, record.Purpose);
        AddParameter(command, "@rsaKeyId", DbType.String, record.RsaKeyId);
        AddParameter(command, "@algorithm", DbType.String, record.Algorithm);
        AddParameter(command, "@encryptedKey", DbType.String, record.EncryptedKey);
        AddParameter(command, "@createdAt", DbType.DateTimeOffset, record.CreatedAt);
        AddParameter(command, "@isActive", DbType.Boolean, record.IsActive);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask RetireActiveAsync(
        DbConnection connection,
        DbTransaction transaction,
        string purpose,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE EncryptedPropertyKeks
            SET IsActive = @isActive
            WHERE Purpose = @purpose AND IsActive = @active
            """;
        AddParameter(command, "@isActive", DbType.Boolean, false);
        AddParameter(command, "@purpose", DbType.String, purpose);
        AddParameter(command, "@active", DbType.Boolean, true);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async ValueTask<DbConnection> OpenSeparateConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = CreateSeparateConnection();

        try
        {
            await connection.OpenAsync(cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private DbConnection CreateSeparateConnection()
    {
        var connection = _providerFactory.CreateConnection()
            ?? throw new InvalidOperationException(
                $"The database key chain provider factory '{_providerFactory.GetType().FullName}' returned null from CreateConnection().");
        connection.ConnectionString = _connectionString;
        return connection;
    }

    private static void AddParameter(DbCommand command, string name, DbType dbType, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.DbType = dbType;
        parameter.Value = value;
        command.Parameters.Add(parameter);
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

    private string CreateGetActiveSql(bool useUpdateLock)
    {
        return _dialect switch
        {
            DatabaseDialect.SqlServer => CreateSqlServerGetActiveSql(useUpdateLock),
            DatabaseDialect.Sqlite => $"""
                SELECT {ColumnList}
                FROM EncryptedPropertyKeks
                WHERE Purpose = @purpose AND IsActive = @isActive
                ORDER BY CreatedAt DESC
                LIMIT 1
                """,
            _ => $"""
                SELECT {ColumnList}
                FROM EncryptedPropertyKeks
                WHERE Purpose = @purpose AND IsActive = @isActive
                ORDER BY CreatedAt DESC
                """
        };
    }

    private static string CreateSqlServerGetActiveSql(bool useUpdateLock)
    {
        var tableHint = useUpdateLock ? " WITH (UPDLOCK, HOLDLOCK)" : string.Empty;
        return $"""
            SELECT TOP(1) {ColumnList}
            FROM EncryptedPropertyKeks{tableHint}
            WHERE Purpose = @purpose AND IsActive = @isActive
            ORDER BY CreatedAt DESC
            """;
    }

    private static DatabaseDialect DetectDialect(DbConnection connection)
    {
        var typeName = connection.GetType().FullName ?? string.Empty;

        if (typeName.StartsWith("Microsoft.Data.SqlClient.", StringComparison.Ordinal)
            || typeName.StartsWith("System.Data.SqlClient.", StringComparison.Ordinal))
        {
            return DatabaseDialect.SqlServer;
        }

        if (typeName.StartsWith("Microsoft.Data.Sqlite.", StringComparison.Ordinal))
            return DatabaseDialect.Sqlite;

        return DatabaseDialect.Generic;
    }

    private static bool IsRetryableConcurrencyError(DbException exception)
    {
        if (GetIntProperty(exception, "Number") is 1205 or 2601 or 2627)
            return true;

        if (exception.GetType().FullName == "Microsoft.Data.Sqlite.SqliteException"
            && GetIntProperty(exception, "SqliteErrorCode") is 5 or 6 or 19)
        {
            return true;
        }

        return false;
    }

    private static int? GetIntProperty(Exception exception, string propertyName)
    {
        return exception.GetType().GetProperty(propertyName)?.GetValue(exception) is int value
            ? value
            : null;
    }

    private enum DatabaseDialect
    {
        Generic,
        SqlServer,
        Sqlite
    }

    private static EncryptedKeyRecord MapToRecord(DbDataReader reader)
    {
        return new EncryptedKeyRecord
        {
            Id = reader.GetFieldValue<Guid>(0),
            Purpose = reader.GetString(1),
            RsaKeyId = reader.GetString(2),
            Algorithm = reader.GetString(3),
            EncryptedKey = reader.GetString(4),
            CreatedAt = reader.GetFieldValue<DateTimeOffset>(5),
            IsActive = reader.GetBoolean(6)
        };
    }
}
