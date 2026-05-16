namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class KeyMaterial
{
    public required string KeyId { get; init; }
    public required byte[] Key { get; init; }
    public required string Algorithm { get; init; }
}
