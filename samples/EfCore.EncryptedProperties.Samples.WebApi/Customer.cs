namespace EfCore.EncryptedProperties.ApiSample;

public sealed class Customer
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;

    // DecryptOnRead: transparent, stays as string
    public string Email { get; set; } = string.Empty;

    // DecryptOnRead also supports non-string values
    public DateTime DateOfBirth { get; set; }

    // Lazy: explicit decrypt via GetDecryptedValueAsync
    public EncryptedValue<string> SecretNotes { get; set; } = default!;

    // Lazy non-string value
    public EncryptedValue<int> LoyaltyPoints { get; set; } = default!;
}
