namespace EfCore.EncryptedProperties.KeyManagement;

internal sealed class EncryptedPropertyKek
{
    public Guid Id { get; set; }
    public string Purpose { get; set; } = null!;
    public string RsaKeyId { get; set; } = null!;
    public string Algorithm { get; set; } = null!;
    public string EncryptedKey { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; set; }
    public bool IsActive { get; set; }
}
