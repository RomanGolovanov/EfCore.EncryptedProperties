using EfCore.EncryptedProperties.Serialization;

namespace EfCore.EncryptedProperties.Configuration;

public sealed class EncryptedPropertiesOptions
{
    private readonly Dictionary<Type, ICustomValueSerializer> _valueSerializers = new();

    public RotationPolicy RotationPolicy { get; } = new();
    public TimeSpan KekCacheLifetime { get; set; } = TimeSpan.FromMinutes(30);

    internal IReadOnlyList<Type> CustomValueSerializerTypes =>
        _valueSerializers.Keys
            .OrderBy(type => type.AssemblyQualifiedName, StringComparer.Ordinal)
            .ToArray();

    internal void SetValueSerializer<TValue>(IEncryptedPropertyValueSerializer<TValue> serializer)
    {
        ArgumentNullException.ThrowIfNull(serializer);

        _valueSerializers[typeof(TValue)] = new CustomValueSerializer<TValue>(serializer);
    }

    internal bool TryGetValueSerializer(Type type, out ICustomValueSerializer serializer)
    {
        var serializerType = Nullable.GetUnderlyingType(type) ?? type;
        if (_valueSerializers.TryGetValue(serializerType, out var registered))
        {
            serializer = registered;
            return true;
        }

        serializer = null!;
        return false;
    }
}
