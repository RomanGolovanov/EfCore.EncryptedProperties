using EfCore.EncryptedProperties.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace EfCore.EncryptedProperties.Metadata;

internal static class EncryptedPropertyModelBuilder
{
    public static EncryptedPropertyModel Build(IModel model)
    {
        var descriptors = new List<EncryptedPropertyDescriptor>();

        foreach (var entityType in model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties())
            {
                var isCiphertextStorage = property.FindAnnotation(EncryptedPropertyAnnotations.IsCiphertextStorage);
                if (isCiphertextStorage?.Value is not true)
                    continue;

                var purpose = property.FindAnnotation(EncryptedPropertyAnnotations.KeyPurpose)?.Value as string ?? "default";
                var propertyName = property.FindAnnotation(EncryptedPropertyAnnotations.PlaintextPropertyName)?.Value as string
                    ?? throw new InvalidOperationException(
                        $"Encrypted storage property '{entityType.ClrType.FullName}.{property.Name}' is missing plaintext property metadata.");
                var plaintextClrType = property.FindAnnotation(EncryptedPropertyAnnotations.PlaintextClrType)?.Value as Type
                    ?? throw new InvalidOperationException(
                        $"Encrypted storage property '{entityType.ClrType.FullName}.{property.Name}' is missing plaintext CLR type metadata.");
                var materialization = property.FindAnnotation(EncryptedPropertyAnnotations.Materialization)?.Value as string;

                var mode = string.Equals(materialization, "Lazy", StringComparison.OrdinalIgnoreCase)
                    ? MaterializationMode.Lazy
                    : MaterializationMode.DecryptOnRead;

                var innerType = mode == MaterializationMode.Lazy
                    ? plaintextClrType.GetGenericArguments()[0]
                    : plaintextClrType;

                descriptors.Add(new EncryptedPropertyDescriptor
                {
                    EntityTypeName = entityType.ClrType.FullName!,
                    PropertyName = propertyName,
                    CiphertextPropertyName = property.Name,
                    ClrType = innerType,
                    Purpose = purpose,
                    Mode = mode
                });
            }
        }

        return new EncryptedPropertyModel(descriptors);
    }
}
