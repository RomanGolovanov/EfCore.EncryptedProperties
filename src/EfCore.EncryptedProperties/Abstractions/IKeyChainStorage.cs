using EfCore.EncryptedProperties.KeyManagement;

namespace EfCore.EncryptedProperties.Abstractions;

public interface IKeyChainStorage
{
    ValueTask<EncryptedKeyRecord?> GetActiveAsync(
        string purpose,
        CancellationToken cancellationToken = default);

    ValueTask<EncryptedKeyRecord> GetOrActivateAsync(
        string purpose,
        DateTimeOffset? rotateBefore,
        EncryptedKeyRecord candidate,
        CancellationToken cancellationToken = default);

    ValueTask<EncryptedKeyRecord?> GetByIdAsync(
        string keyId,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<EncryptedKeyRecord>> GetAllAsync(
        CancellationToken cancellationToken = default);
}
