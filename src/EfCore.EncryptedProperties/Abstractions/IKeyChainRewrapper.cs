using EfCore.EncryptedProperties.KeyManagement;

namespace EfCore.EncryptedProperties.Abstractions;

public interface IKeyChainRewrapper
{
    ValueTask<KeyChainRewrapResult> RewrapAsync(
        KeyChainRewrapOptions? options = null,
        CancellationToken cancellationToken = default);
}
