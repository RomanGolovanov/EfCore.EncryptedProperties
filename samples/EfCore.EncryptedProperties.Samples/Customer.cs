namespace EfCore.EncryptedProperties.Samples;

public sealed class Customer
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;

    // DecryptOnRead: transparent encryption, property stays as string
    public string Email { get; set; } = string.Empty;

    // Lazy: explicit decrypt via GetDecryptedValueAsync
    public EncryptedValue<string> SecretNotes { get; set; } = default!;
}
