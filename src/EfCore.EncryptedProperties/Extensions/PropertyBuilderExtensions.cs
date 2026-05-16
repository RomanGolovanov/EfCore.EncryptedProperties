using EfCore.EncryptedProperties.Configuration;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EfCore.EncryptedProperties.Extensions;

public static class PropertyBuilderExtensions
{
    public static PropertyBuilder<TProperty> IsEncrypted<TProperty>(
        this PropertyBuilder<TProperty> builder,
        Action<EncryptedPropertyOptions>? configure = null)
    {
        var options = new EncryptedPropertyOptions();
        configure?.Invoke(options);

        builder.HasAnnotation(EncryptedPropertyAnnotations.IsEncrypted, true);
        builder.HasAnnotation(EncryptedPropertyAnnotations.KeyPurpose, options.KeyPurpose);

        var clrType = typeof(TProperty);
        var isLazy = clrType.IsGenericType && clrType.GetGenericTypeDefinition() == typeof(EncryptedValue<>);

        builder.HasAnnotation(EncryptedPropertyAnnotations.Materialization,
            isLazy ? "Lazy" : "DecryptOnRead");

        return builder;
    }
}
