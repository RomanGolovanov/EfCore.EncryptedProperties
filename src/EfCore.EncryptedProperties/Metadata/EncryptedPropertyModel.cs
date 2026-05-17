namespace EfCore.EncryptedProperties.Metadata;

internal sealed class EncryptedPropertyModel
{
    private static readonly IReadOnlyList<EncryptedPropertyDescriptor> EmptyProperties = Array.Empty<EncryptedPropertyDescriptor>();
    private readonly Dictionary<(string EntityType, string Property), EncryptedPropertyDescriptor> _lookup;
    private readonly Dictionary<string, IReadOnlyList<EncryptedPropertyDescriptor>> _byEntityType;

    public EncryptedPropertyModel(IReadOnlyList<EncryptedPropertyDescriptor> properties)
    {
        Properties = properties;
        _lookup = properties.ToDictionary(p => (p.EntityTypeName, p.PropertyName));
        _byEntityType = properties
            .GroupBy(p => p.EntityTypeName)
            .ToDictionary(
                grouping => grouping.Key,
                grouping => (IReadOnlyList<EncryptedPropertyDescriptor>)grouping.ToArray());
    }

    public IReadOnlyList<EncryptedPropertyDescriptor> Properties { get; }

    public EncryptedPropertyDescriptor? Find(string entityTypeName, string propertyName)
    {
        _lookup.TryGetValue((entityTypeName, propertyName), out var descriptor);
        return descriptor;
    }

    public IReadOnlyList<EncryptedPropertyDescriptor> GetForEntityType(string entityTypeName)
    {
        return _byEntityType.TryGetValue(entityTypeName, out var properties)
            ? properties
            : EmptyProperties;
    }
}
