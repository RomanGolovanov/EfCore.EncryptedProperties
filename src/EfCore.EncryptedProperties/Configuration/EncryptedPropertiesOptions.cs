namespace EfCore.EncryptedProperties.Configuration;

public sealed class EncryptedPropertiesOptions
{
    public RotationPolicy RotationPolicy { get; } = new();
    public TimeSpan KekCacheLifetime { get; set; } = TimeSpan.FromMinutes(30);
}
