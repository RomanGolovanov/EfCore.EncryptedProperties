using EfCore.EncryptedProperties.KeyManagement;

namespace EfCore.EncryptedProperties.Abstractions;

public interface IKeyChainManager
{
    ValueTask<KeyMaterial> GetActiveKeyAsync(
        string purpose,
        CancellationToken cancellationToken = default);

    ValueTask<KeyMaterial> GetKeyForDecryptAsync(
        string keyId,
        CancellationToken cancellationToken = default);

    ValueTask PreloadAsync(CancellationToken cancellationToken = default);
}
