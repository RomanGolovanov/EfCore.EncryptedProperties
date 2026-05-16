# EfCore.EncryptedProperties

Property-level encryption for Entity Framework Core 9. Mark the properties that should be protected, configure where keys live, and keep using your entities in a normal EF workflow.

- **Targets:** .NET 9, EF Core 9
- **Use it for:** PII, notes, tokens, small secrets, and values the database should never see in plaintext
- **Entity experience:** normal CLR properties for transparent reads, or `EncryptedValue<T>` when you want explicit async decryption

## Install

```xml
<PackageReference Include="EfCore.EncryptedProperties" Version="*" />
```

## Quick Start

Register encryption services once in application DI, then enable the EF integration on each encrypted `DbContext`.

```csharp
using EfCore.EncryptedProperties.Extensions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

services.AddEncryptedProperties(cfg => cfg
    .WithFileRsaKeyProvider("rsa-key.pem", "rsa-v1")
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString)
    .WithKeyChainPreloadOnStartup());

services.AddDbContext<AppDbContext>((sp, options) =>
{
    options
        .UseSqlServer(connectionString)
        .UseEncryptedProperties(sp);
});
```

If you use the database key chain, add its table to your model:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.UseEncryptedPropertiesKekStorage();

    modelBuilder.Entity<Customer>(entity =>
    {
        entity.HasKey(e => e.Id);
        entity.Property(e => e.Email).IsEncrypted();
        entity.Property(e => e.SecretNotes).IsEncrypted(opts => opts.KeyPurpose = "notes");
    });
}
```

Then use the entity normally:

```csharp
var customer = new Customer
{
    Name = "Alice",
    Email = "alice@example.com",
    SecretNotes = "private message"
};

db.Customers.Add(customer);
await db.SaveChangesAsync();

var saved = await db.Customers.FindAsync(customer.Id);
Console.WriteLine(saved!.Email);
Console.WriteLine(await saved.SecretNotes.GetDecryptedValueAsync());
```

## Entity Styles

Choose the style by choosing the CLR type.

### Transparent Reads

Use the real property type when you want the value decrypted as soon as EF materializes the entity.

```csharp
public sealed class Customer
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
}
```

This is the easiest option for everyday fields like email, phone number, or a short identifier.

### Explicit Async Reads

Use `EncryptedValue<T>` when you want to defer decryption until application code asks for the value.

```csharp
public sealed class Customer
{
    public Guid Id { get; set; }
    public EncryptedValue<string> SecretNotes { get; set; } = default!;
}

customer.SecretNotes = "private message";

var notes = await customer.SecretNotes.GetDecryptedValueAsync(ct);
```

This is useful for larger values, values rarely shown to users, or code paths where you want decryption to be obvious.

## Setup Recipes

### Tests and Local Demos

```csharp
services.AddEncryptedProperties(cfg => cfg
    .WithInMemoryRsaKeyProvider(RSA.Create(2048), "test-rsa-v1")
    .WithInMemoryKeyChain());
```

In-memory keys are lost when the process exits. They are for tests, demos, and short-lived local runs.

### Self-hosted Apps

```csharp
services.AddEncryptedProperties(cfg => cfg
    .WithFileRsaKeyProvider("keys/rsa-key.pem", "rsa-v1")
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString));
```

The file provider creates the PEM file if it does not exist. Back it up and protect it like any other application secret.

### Azure Key Vault

```csharp
services.AddEncryptedProperties(cfg => cfg
    .WithAzureKeyVaultRsaKeyProvider(
        new Uri("https://my-vault.vault.azure.net/keys/my-key"),
        new DefaultAzureCredential())
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString));
```

Use this when the RSA private key should stay outside the application host. Pass the unversioned Key Vault key URI; new KEKs use the latest key version, while existing KEKs store and use the exact versioned Key Vault key ID that wrapped them.

Keep old Key Vault key versions enabled and recoverable while any KEKs wrapped by those versions still exist.

### Key Rotation

```csharp
services.AddEncryptedProperties(cfg => cfg
    .WithFileRsaKeyProvider("rsa-key.pem", "rsa-v1")
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString)
    .WithKeyChainRotation(policy =>
    {
        policy.KeyRotateAfter = TimeSpan.FromDays(90);
    }));
```

New writes use the current active key for the property's purpose. Existing rows remain readable after rotation.

### Startup KEK Preload

```csharp
services.AddEncryptedProperties(cfg => cfg
    .WithFileRsaKeyProvider("rsa-key.pem", "rsa-v1")
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString)
    .WithKeyChainPreloadOnStartup());
```

This registers an `IHostedService` that unwraps all stored KEKs during host startup. If preload fails, the app fails fast instead of discovering key access problems on the first encrypted read or write.

## What To Expect

- The database column stores ciphertext, not the original value.
- `SaveChanges` encrypts new or changed encrypted properties.
- Materialization decrypts transparent properties automatically.
- `EncryptedValue<T>` decrypts only when `GetDecryptedValueAsync` is called, then caches the plaintext in that wrapper instance.
- Different key purposes rotate independently, so `Email` and `SecretNotes` can use separate key chains.

Supported value types are primitives, `string`, `byte[]`, `bool`, `DateTime`, `DateTimeOffset`, `Guid`, enums backed by supported primitives, and nullable variants.

## Edge Cases

### Queries

Do not query encrypted columns by plaintext:

```csharp
// This will not work reliably.
var customer = await db.Customers.SingleOrDefaultAsync(c => c.Email == "alice@example.com");
```

Ciphertext changes on each write, even for the same plaintext. For lookups, keep a separate non-encrypted lookup column such as a normalized hash.

### Migrations

If you use `WithDatabaseKeyChain`, call `modelBuilder.UseEncryptedPropertiesKekStorage()` and create the table with migrations or `EnsureCreated()`.

Encrypted entity properties are still mapped to normal database columns, but those columns hold ciphertext. 

The key-chain table enforces one active KEK per purpose with a filtered unique index on `Purpose` where `IsActive = 1`.

### Nulls and Defaults

`null` encrypted reference or nullable values are stored as `null`. For non-nullable value types, a missing encrypted payload materializes as the CLR default value.

### Keys

Keep the RSA key stable. If the file key is deleted, replaced, or a different Key Vault key is configured, previously stored key-chain records may no longer unwrap.

The library rotates data-encryption keys, but it does not automatically rotate the RSA master key.

### Plaintext Change Tracking

For transparent properties, assign the new value and call `SaveChanges` as usual. For `EncryptedValue<T>`, assigning from `T` marks the wrapper as modified:

```csharp
customer.SecretNotes = "updated private message";
await db.SaveChangesAsync();
```

### Plaintext Is Still In Your Process

This protects data from being stored in plaintext in the database. It does not hide values from your application code, logs, memory dumps, or API responses. Treat decrypted values carefully once you read them.

## Samples

- [`samples/EfCore.EncryptedProperties.Samples`](samples/EfCore.EncryptedProperties.Samples) - console app showing both entity styles against EF InMemory.
- [`samples/EfCore.EncryptedProperties.ApiSample`](samples/EfCore.EncryptedProperties.ApiSample) - minimal ASP.NET Core API using file-backed RSA and a SQL Server database key chain.

## License

Apache License, Version 2.0.

