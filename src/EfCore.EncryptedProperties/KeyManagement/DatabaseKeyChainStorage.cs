using System.Data;
using System.Data.Common;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.KeyManagement;

internal sealed class DatabaseKeyChainStorage : IKeyChainStorage
{
    private const string ColumnList = "Id, Purpose, RsaKeyId, Algorithm, EncryptedKey, CreatedAt, IsActive";

    private readonly DbProviderFactory _providerFactory;
    private readonly string _connectionString;

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
            catch (DbException ex) when (attempt < 3 && IsSqlDeadlock(ex))
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

    private static async ValueTask<EncryptedKeyRecord?> GetActiveAsync(
        DbConnection connection,
        DbTransaction? transaction,
        string purpose,
        bool useUpdateLock,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var tableHint = useUpdateLock ? " WITH (UPDLOCK, HOLDLOCK)" : string.Empty;
        command.CommandText = $"""
            SELECT TOP(1) {ColumnList}
            FROM EncryptedPropertyKeks{tableHint}
            WHERE Purpose = @purpose AND IsActive = @isActive
            ORDER BY CreatedAt DESC
            """;
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

    private static bool IsSqlDeadlock(DbException exception)
    {
        return exception.GetType().GetProperty("Number")?.GetValue(exception) is 1205;
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
