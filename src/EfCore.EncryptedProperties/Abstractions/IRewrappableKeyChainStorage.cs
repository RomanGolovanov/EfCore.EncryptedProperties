using EfCore.EncryptedProperties.KeyManagement;

namespace EfCore.EncryptedProperties.Abstractions;

public interface IRewrappableKeyChainStorage : IKeyChainStorage
{
    ValueTask<bool> TryReplaceKeyAsync(
        EncryptedKeyRecord original,
        EncryptedKeyRecord replacement,
        CancellationToken cancellationToken = default);
}
