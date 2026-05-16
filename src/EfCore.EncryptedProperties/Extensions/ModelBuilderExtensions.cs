using EfCore.EncryptedProperties.KeyManagement;
using Microsoft.EntityFrameworkCore;

namespace EfCore.EncryptedProperties.Extensions;

public static class ModelBuilderExtensions
{
    public static ModelBuilder UseEncryptedPropertiesKekStorage(this ModelBuilder builder)
    {
        builder.ApplyConfiguration(new EncryptedPropertyKekConfiguration());
        return builder;
    }
}
