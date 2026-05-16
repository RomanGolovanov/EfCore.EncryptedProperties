namespace EfCore.EncryptedProperties.Configuration;

internal static class EncryptedPropertyAnnotations
{
    public const string Prefix = "EncryptedProperties:";
    public const string IsEncrypted = Prefix + "IsEncrypted";
    public const string Materialization = Prefix + "Materialization";
    public const string KeyPurpose = Prefix + "KeyPurpose";
    public const string PlaintextPropertyName = Prefix + "PlaintextPropertyName";
    public const string PlaintextClrType = Prefix + "PlaintextClrType";
    public const string CiphertextPropertyName = Prefix + "CiphertextPropertyName";
    public const string IsCiphertextStorage = Prefix + "IsCiphertextStorage";
}
