using EfCore.EncryptedProperties.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using Microsoft.EntityFrameworkCore.Metadata.Conventions.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;

namespace EfCore.EncryptedProperties.Infrastructure;

internal sealed class EncryptedPropertiesConventionSetPlugin : IConventionSetPlugin
{
    public ConventionSet ModifyConventions(ConventionSet conventionSet)
    {
        conventionSet.ModelFinalizingConventions.Add(new EncryptedPropertiesStorageConvention());
        return conventionSet;
    }
}

internal sealed class EncryptedPropertiesStorageConvention : IModelFinalizingConvention
{
    public void ProcessModelFinalizing(
        IConventionModelBuilder modelBuilder,
        IConventionContext<IConventionModelBuilder> context)
    {
        foreach (var entityType in modelBuilder.Metadata.GetEntityTypes().ToList())
        {
            foreach (var property in entityType.GetProperties().ToList())
            {
                var isEncrypted = property.FindAnnotation(EncryptedPropertyAnnotations.IsEncrypted);
                if (isEncrypted?.Value is not true)
                    continue;

                if (property.FindAnnotation(EncryptedPropertyAnnotations.IsCiphertextStorage)?.Value is true)
                    continue;

                ConfigureCiphertextStorage(entityType, property);
            }
        }
    }

    private static void ConfigureCiphertextStorage(IConventionEntityType entityType, IConventionProperty plaintextProperty)
    {
        if (plaintextProperty.IsKey()
            || plaintextProperty.IsForeignKey()
            || plaintextProperty.GetContainingIndexes().Any())
        {
            throw new InvalidOperationException(
                $"Encrypted property '{entityType.ClrType.FullName}.{plaintextProperty.Name}' cannot be part of a key, foreign key, or index.");
        }

        var plaintextPropertyName = plaintextProperty.Name;
        var ciphertextPropertyName = GetCiphertextPropertyName(entityType, plaintextPropertyName);
        var purpose = plaintextProperty.FindAnnotation(EncryptedPropertyAnnotations.KeyPurpose)?.Value as string ?? "default";
        var materialization = plaintextProperty.FindAnnotation(EncryptedPropertyAnnotations.Materialization)?.Value as string;
        var columnName = plaintextProperty.GetColumnName() ?? plaintextPropertyName;
        var columnType = plaintextProperty.GetColumnType() ?? "nvarchar(max)";
        var maxLength = plaintextProperty.GetMaxLength();
        var isUnicode = plaintextProperty.IsUnicode();
        var isRequired = !plaintextProperty.IsNullable;

        var ciphertextPropertyBuilder = entityType.Builder.Property(
            typeof(string),
            ciphertextPropertyName,
            setTypeConfigurationSource: false,
            fromDataAnnotation: false);

        if (ciphertextPropertyBuilder is null)
        {
            throw new InvalidOperationException(
                $"Unable to configure encrypted storage property '{ciphertextPropertyName}' for '{entityType.ClrType.FullName}'.");
        }

        ciphertextPropertyBuilder.HasAnnotation(EncryptedPropertyAnnotations.IsEncrypted, true, fromDataAnnotation: false);
        ciphertextPropertyBuilder.HasAnnotation(EncryptedPropertyAnnotations.IsCiphertextStorage, true, fromDataAnnotation: false);
        ciphertextPropertyBuilder.HasAnnotation(EncryptedPropertyAnnotations.PlaintextPropertyName, plaintextPropertyName, fromDataAnnotation: false);
        ciphertextPropertyBuilder.HasAnnotation(EncryptedPropertyAnnotations.PlaintextClrType, plaintextProperty.ClrType, fromDataAnnotation: false);
        ciphertextPropertyBuilder.HasAnnotation(EncryptedPropertyAnnotations.CiphertextPropertyName, ciphertextPropertyName, fromDataAnnotation: false);
        ciphertextPropertyBuilder.HasAnnotation(EncryptedPropertyAnnotations.KeyPurpose, purpose, fromDataAnnotation: false);
        ciphertextPropertyBuilder.HasAnnotation(
            EncryptedPropertyAnnotations.Materialization,
            materialization ?? GetMaterializationMode(plaintextProperty.ClrType),
            fromDataAnnotation: false);

        ciphertextPropertyBuilder.HasColumnName(columnName, fromDataAnnotation: false);
        ciphertextPropertyBuilder.HasColumnType(columnType, fromDataAnnotation: false);
        ciphertextPropertyBuilder.HasMaxLength(maxLength, fromDataAnnotation: false);
        ciphertextPropertyBuilder.IsUnicode(isUnicode, fromDataAnnotation: false);
        ciphertextPropertyBuilder.IsRequired(isRequired, fromDataAnnotation: false);

        var removed = entityType.RemoveProperty(plaintextProperty);
        if (removed is null)
        {
            throw new InvalidOperationException(
                $"Unable to replace encrypted property '{entityType.ClrType.FullName}.{plaintextPropertyName}' with ciphertext storage.");
        }

        entityType.AddIgnored(plaintextPropertyName, fromDataAnnotation: false);
    }

    private static string GetCiphertextPropertyName(IConventionEntityType entityType, string plaintextPropertyName)
    {
        var baseName = $"__EncryptedProperties_{plaintextPropertyName}";
        var name = baseName;
        var suffix = 1;

        while (entityType.FindProperty(name) is not null)
        {
            name = $"{baseName}_{suffix}";
            suffix++;
        }

        return name;
    }

    private static string GetMaterializationMode(Type clrType)
    {
        return clrType.IsGenericType && clrType.GetGenericTypeDefinition() == typeof(EncryptedValue<>)
            ? "Lazy"
            : "DecryptOnRead";
    }
}
