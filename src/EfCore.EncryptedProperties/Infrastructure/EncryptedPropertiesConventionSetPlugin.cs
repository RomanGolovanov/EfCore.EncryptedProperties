using System.Reflection;
using EfCore.EncryptedProperties.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using Microsoft.EntityFrameworkCore.Metadata.Conventions.Infrastructure;

namespace EfCore.EncryptedProperties.Infrastructure;

internal sealed class EncryptedPropertiesConventionSetPlugin : IConventionSetPlugin
{
    public ConventionSet ModifyConventions(ConventionSet conventionSet)
    {
        conventionSet.ModelFinalizingConventions.Insert(0, new EncryptedPropertiesStorageConvention());
        return conventionSet;
    }
}

internal sealed class EncryptedPropertiesStorageConvention : IModelFinalizingConvention
{
    public void ProcessModelFinalizing(
        IConventionModelBuilder modelBuilder,
        IConventionContext<IConventionModelBuilder> context)
    {
        ApplyEncryptedAttributes(modelBuilder);
        RemoveUnusedEncryptedValueEntityTypes(modelBuilder);

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

    private static void ApplyEncryptedAttributes(IConventionModelBuilder modelBuilder)
    {
        foreach (var entityType in modelBuilder.Metadata.GetEntityTypes().ToList())
        {
            if (entityType.ClrType is null || IsEncryptedValueType(entityType.ClrType))
                continue;

            foreach (var propertyInfo in entityType.ClrType.GetProperties(
                         BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            {
                var encryptedAttribute = GetEncryptedAttribute(propertyInfo);
                if (encryptedAttribute is null)
                    continue;

                var property = entityType.FindProperty(propertyInfo.Name)
                    ?? ConvertAnnotatedNavigationToProperty(entityType, propertyInfo);

                ApplyEncryptedAttribute(property, encryptedAttribute);
            }
        }
    }

    private static IConventionProperty ConvertAnnotatedNavigationToProperty(
        IConventionEntityType entityType,
        PropertyInfo propertyInfo)
    {
        var navigation = entityType.FindNavigation(propertyInfo.Name);
        if (navigation is not null)
        {
            navigation.ForeignKey.DeclaringEntityType.Builder.HasNoRelationship(
                navigation.ForeignKey,
                fromDataAnnotation: true);
        }

        var propertyBuilder = entityType.Builder.Property(
            propertyInfo.PropertyType,
            propertyInfo.Name,
            setTypeConfigurationSource: false,
            fromDataAnnotation: true);

        return propertyBuilder?.Metadata
            ?? throw new InvalidOperationException(
                $"Unable to configure encrypted property '{entityType.ClrType.FullName}.{propertyInfo.Name}' from data annotations.");
    }

    private static void RemoveUnusedEncryptedValueEntityTypes(IConventionModelBuilder modelBuilder)
    {
        foreach (var entityType in modelBuilder.Metadata.GetEntityTypes().ToList())
        {
            if (!IsEncryptedValueType(entityType.ClrType))
                continue;

            if (entityType.GetForeignKeys().Any() || entityType.GetReferencingForeignKeys().Any())
                continue;

            modelBuilder.HasNoEntityType(entityType, fromDataAnnotation: true);
        }
    }

    private static void ApplyEncryptedAttribute(IConventionProperty property, EncryptedAttribute encryptedAttribute)
    {
        if (property.FindAnnotation(EncryptedPropertyAnnotations.IsEncrypted) is not null)
            return;

        var keyPurpose = string.IsNullOrWhiteSpace(encryptedAttribute.KeyPurpose)
            ? "default"
            : encryptedAttribute.KeyPurpose;

        property.Builder.HasAnnotation(EncryptedPropertyAnnotations.IsEncrypted, true, fromDataAnnotation: true);
        property.Builder.HasAnnotation(EncryptedPropertyAnnotations.KeyPurpose, keyPurpose, fromDataAnnotation: true);
        property.Builder.HasAnnotation(
            EncryptedPropertyAnnotations.Materialization,
            GetMaterializationMode(property.ClrType),
            fromDataAnnotation: true);
    }

    private static EncryptedAttribute? GetEncryptedAttribute(PropertyInfo propertyInfo)
    {
        return propertyInfo.GetCustomAttributes(typeof(EncryptedAttribute), inherit: true)
            .OfType<EncryptedAttribute>()
            .FirstOrDefault();
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
        var columnType = plaintextProperty.GetColumnType();
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
        if (columnType is not null)
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
        return IsEncryptedValueType(clrType)
            ? "Lazy"
            : "DecryptOnRead";
    }

    private static bool IsEncryptedValueType(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(EncryptedValue<>);
    }
}
