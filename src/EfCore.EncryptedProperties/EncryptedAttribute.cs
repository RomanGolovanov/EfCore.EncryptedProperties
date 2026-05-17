namespace EfCore.EncryptedProperties;

[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class EncryptedAttribute : Attribute
{
    public EncryptedAttribute()
    {
    }

    public EncryptedAttribute(string keyPurpose)
    {
        KeyPurpose = keyPurpose;
    }

    public string KeyPurpose { get; set; } = "default";
}
