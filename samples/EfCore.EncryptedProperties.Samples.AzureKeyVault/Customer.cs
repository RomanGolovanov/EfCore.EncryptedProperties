namespace EfCore.EncryptedProperties.Samples.AzureKeyVault;

public sealed class Customer
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;

    // DecryptOnRead: transparent encryption, property stays as string
    public string Email { get; set; } = string.Empty;

    // DecryptOnRead works for non-string values too
    [Encrypted]
    public DateTime DateOfBirth { get; set; }

    // Lazy: explicit decrypt via GetDecryptedValueAsync
    public EncryptedValue<string> SecretNotes { get; set; } = default!;

    // Lazy non-string value
    public EncryptedValue<int> LoyaltyPoints { get; set; } = default!;
}
