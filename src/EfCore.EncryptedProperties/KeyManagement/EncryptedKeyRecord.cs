namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class EncryptedKeyRecord
{
    public required Guid Id { get; init; }
    public required string Purpose { get; init; }
    public required string RsaKeyId { get; init; }
    public required string Algorithm { get; init; }
    public required string EncryptedKey { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required bool IsActive { get; init; }
}
