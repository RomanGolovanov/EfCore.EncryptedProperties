namespace EfCore.EncryptedProperties.Metadata;

internal sealed class EncryptedPropertyDescriptor
{
    public required string EntityTypeName { get; init; }
    public required string PropertyName { get; init; }
    public required string CiphertextPropertyName { get; init; }
    public required Type ClrType { get; init; }
    public required string Purpose { get; init; }
    public required MaterializationMode Mode { get; init; }
}
