namespace EfCore.EncryptedProperties.Metadata;

internal sealed class EncryptedPropertyModel
{
    private readonly Dictionary<(string EntityType, string Property), EncryptedPropertyDescriptor> _lookup;

    public EncryptedPropertyModel(IReadOnlyList<EncryptedPropertyDescriptor> properties)
    {
        Properties = properties;
        _lookup = properties.ToDictionary(p => (p.EntityTypeName, p.PropertyName));
    }

    public IReadOnlyList<EncryptedPropertyDescriptor> Properties { get; }

    public EncryptedPropertyDescriptor? Find(string entityTypeName, string propertyName)
    {
        _lookup.TryGetValue((entityTypeName, propertyName), out var descriptor);
        return descriptor;
    }

    public IEnumerable<EncryptedPropertyDescriptor> GetForEntityType(string entityTypeName)
    {
        return Properties.Where(p => p.EntityTypeName == entityTypeName);
    }
}
