namespace EfCore.EncryptedProperties.Abstractions;

internal interface IValueSerializer
{
    byte[] Serialize(object? value, Type type);
    object? Deserialize(byte[] data, Type type);
}
