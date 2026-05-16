namespace EfCore.EncryptedProperties.Configuration;

public sealed class RotationPolicy
{
    public TimeSpan? KeyRotateAfter { get; set; }
}
