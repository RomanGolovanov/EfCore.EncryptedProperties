namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class KeyChainRewrapOptions
{
    public string? Purpose { get; set; }
    public string? OldRsaKeyId { get; set; }
    public bool DryRun { get; set; }
}
