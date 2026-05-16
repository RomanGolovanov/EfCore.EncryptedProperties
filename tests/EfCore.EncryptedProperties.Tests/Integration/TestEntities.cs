namespace EfCore.EncryptedProperties.Tests.Integration;

public sealed class CustomerDecryptOnRead
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}

public sealed class CustomerLazy
{
    public Guid Id { get; set; }
    public EncryptedValue<string> Email { get; set; } = default!;
    public string Name { get; set; } = string.Empty;
}

public sealed class MultiTypeEntity
{
    public Guid Id { get; set; }
    public string EncryptedString { get; set; } = string.Empty;
    public int EncryptedInt { get; set; }
    public bool EncryptedBool { get; set; }
    public Guid EncryptedGuid { get; set; }
    public DateTime EncryptedDateTime { get; set; }
}
