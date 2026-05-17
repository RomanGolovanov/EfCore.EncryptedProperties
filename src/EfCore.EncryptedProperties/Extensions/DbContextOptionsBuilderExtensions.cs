using EfCore.EncryptedProperties.Infrastructure;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Interceptors;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Extensions;

public static class DbContextOptionsBuilderExtensions
{
    public static DbContextOptionsBuilder UseEncryptedProperties(
        this DbContextOptionsBuilder builder,
        IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(serviceProvider);

        _ = serviceProvider.GetRequiredService<IEncryptedPropertyCryptor>();
        var extension = new EncryptedPropertiesDbContextOptionsExtension();
        ((IDbContextOptionsBuilderInfrastructure)builder).AddOrUpdateExtension(extension);

        builder.AddInterceptors(
            serviceProvider.GetRequiredService<EncryptedPropertiesSaveChangesInterceptor>(),
            serviceProvider.GetRequiredService<EncryptedPropertiesMaterializationInterceptor>());

        return builder;
    }
}
