namespace EfCore.EncryptedProperties.Configuration;

public sealed class EncryptedPropertyContext
{
    public required string Purpose { get; init; }
    public string? EntityTypeName { get; init; }
    public string? PropertyName { get; init; }
}
