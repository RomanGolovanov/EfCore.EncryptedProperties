using EfCore.EncryptedProperties.Abstractions;
using Microsoft.Extensions.Hosting;

namespace EfCore.EncryptedProperties.KeyManagement;

internal sealed class KeyChainPreloadHostedService : IHostedService
{
    private readonly IKeyChainManager _keyChainManager;

    public KeyChainPreloadHostedService(IKeyChainManager keyChainManager)
    {
        _keyChainManager = keyChainManager;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        return _keyChainManager.PreloadAsync(cancellationToken).AsTask();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
