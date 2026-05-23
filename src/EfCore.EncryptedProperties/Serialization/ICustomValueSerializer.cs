namespace EfCore.EncryptedProperties.Serialization;

internal interface ICustomValueSerializer
{
    byte[] Serialize(object value);
    object? Deserialize(byte[] data);
}

internal sealed class CustomValueSerializer<TValue> : ICustomValueSerializer
{
    private readonly IEncryptedPropertyValueSerializer<TValue> _serializer;

    public CustomValueSerializer(IEncryptedPropertyValueSerializer<TValue> serializer)
    {
        _serializer = serializer;
    }

    public byte[] Serialize(object value)
    {
        return _serializer.Serialize((TValue)value);
    }

    public object? Deserialize(byte[] data)
    {
        return _serializer.Deserialize(data);
    }
}
