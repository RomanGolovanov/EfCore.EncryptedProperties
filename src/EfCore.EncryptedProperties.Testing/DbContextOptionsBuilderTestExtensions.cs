using EfCore.EncryptedProperties.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Testing;

public static class DbContextOptionsBuilderTestExtensions
{
    public static IServiceCollection AddEncryptedPropertiesForTesting(
        this IServiceCollection services,
        string rsaKeyId = "test-rsa-key-v1")
    {
        return services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(
                System.Security.Cryptography.RSA.Create(2048),
                rsaKeyId);
            cfg.WithInMemoryKeyChain();
        });
    }

    public static DbContextOptionsBuilder UseEncryptedPropertiesForTesting(
        this DbContextOptionsBuilder builder,
        IServiceProvider serviceProvider)
    {
        return builder.UseEncryptedProperties(serviceProvider);
    }
}
