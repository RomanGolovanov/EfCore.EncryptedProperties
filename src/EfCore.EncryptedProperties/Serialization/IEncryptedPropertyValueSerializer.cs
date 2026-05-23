namespace EfCore.EncryptedProperties.Serialization;

public interface IEncryptedPropertyValueSerializer<TValue>
{
    byte[] Serialize(TValue value);
    TValue Deserialize(byte[] data);
}
