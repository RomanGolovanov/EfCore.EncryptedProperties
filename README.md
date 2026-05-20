# EfCore.EncryptedProperties

Property-level encryption for Entity Framework Core 8, 9, and 10. Mark the properties that should be protected, configure where keys live, and keep using your entities in a normal EF workflow.

`EfCore.EncryptedProperties` is aimed at applications that need more than a value converter wrapped around a single AES key. It encrypts individual EF properties before they reach database storage, uses authenticated encryption for the stored payload, and includes a key-chain layer for creating, wrapping, storing, rotating, caching, and preloading data keys.

- **Targets:** .NET 8/9/10 with matching EF Core 8/9/10 dependency groups
- **Use it for:** PII, notes, tokens, small secrets, and values the database should never see in plaintext
- **Entity experience:** normal CLR properties for transparent reads, or `EncryptedValue<T>` when you want explicit async decryption
- **Crypto shape:** AES-256-GCM payload encryption, a fresh content-encryption key per encrypted value, AES-GCM key wrapping, and RSA-wrapped key-encryption keys
- **Key management:** file PEM, file PFX, OS certificate store, in-memory, Azure Blob, and Azure Key Vault RSA providers, plus in-memory, file-backed, Azure Blob, or database-backed key-chain storage

## Why This Package

Many EF Core encryption approaches stop at the first step: convert a property to ciphertext on save and back to plaintext on read. This package also handles the parts that usually become application-specific security plumbing:

- **Envelope encryption out of the box.** Each encrypted value gets its own content-encryption key. Content keys are wrapped by per-purpose key-encryption keys, and key-encryption keys are wrapped by an RSA provider.
- **Key purposes and rotation.** Use separate key chains for different data classes, such as `email`, `notes`, or `tokens`, and rotate new writes without losing access to old rows.
- **Production master key locations.** Keep the RSA wrapping key in a PEM file, a read-only PFX file, an OS certificate store, Azure Blob Storage, in Azure Key Vault when the private key should stay outside the host, or in memory for tests and demos.
- **Durable key chains.** Store wrapped key records in files, Azure Blob Storage, or beside the application database, with one active key per purpose.
- **Two entity styles.** Use ordinary CLR properties when transparency matters, or `EncryptedValue<T>` when you want decryption to be explicit and async at the call site.
- **Typed values, not only strings.** Supported values include primitives, `string`, `byte[]`, `DateTime`, `DateTimeOffset`, `Guid`, enums, and nullable variants.

## Install

```bash
dotnet add package EfCore.EncryptedProperties
```

```xml
<PackageReference Include="EfCore.EncryptedProperties" Version="1.0.2" />
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

If you use the database key chain, add its table to your model. Mark encrypted properties with the fluent API:

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

Or use the `[Encrypted]` data annotation on the entity:

```csharp
using EfCore.EncryptedProperties;

public sealed class Customer
{
    public Guid Id { get; set; }

    [Encrypted("email")]
    public string Email { get; set; } = string.Empty;

    [Encrypted(KeyPurpose = "notes")]
    public EncryptedValue<string> SecretNotes { get; set; } = default!;
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
    .WithFileRsaKeyRingProvider(options =>
    {
        options.CurrentKeyId = "rsa-v1";
        options.AddKey("rsa-v1", "keys/rsa-v1.pem");
    })
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString));
```

The file key-ring provider creates the current PEM file if it does not exist. Back it up and protect it like any other application secret. Historical key files must already exist, so a missing old key fails fast instead of silently creating a replacement that cannot decrypt existing records.

For simple single-key deployments, `WithFileRsaKeyProvider("keys/rsa-key.pem", "rsa-v1")` is still available.

### Read-Only PFX Files

```csharp
services.AddEncryptedProperties(cfg => cfg
    .WithFilePfxRsaKeyRingProvider(options =>
    {
        options.CurrentKeyId = "rsa-v2";
        options.AddKey("rsa-v1", "keys/rsa-v1.pfx", oldPassword);
        options.AddKey("rsa-v2", "keys/rsa-v2.pfx", currentPassword);
    })
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString));
```

PFX providers are read-only. They never create certificate files, so every configured current and historical PFX must already exist and contain an RSA private key. For a single PFX, use `WithFilePfxRsaKeyProvider("keys/rsa-v1.pfx", "rsa-v1", password)`.

### File-Backed Key Chain

```csharp
services.AddEncryptedProperties(cfg => cfg
    .WithFileRsaKeyProvider("keys/rsa-key.pem", "rsa-v1")
    .WithFileKeyChain("keys/key-chain"));
```

The file key chain stores wrapped KEK records as one JSON file per key purpose in the configured directory. Protect and back up this directory alongside the RSA private key; losing either the RSA key or the key-chain files can make existing encrypted data unreadable.

### Azure Blob Storage

```csharp
var container = new BlobContainerClient(
    new Uri("https://account.blob.core.windows.net/encryption"),
    new DefaultAzureCredential());

services.AddEncryptedProperties(cfg => cfg
    .WithAzureBlobRsaKeyRingProvider(container, options =>
    {
        options.BlobPrefix = "rsa/";
        options.CurrentKeyId = "rsa-v1";
        options.CreateContainerIfNotExists = true;
        options.AddKey("rsa-v1", "rsa-v1.pem");
    })
    .WithAzureBlobKeyChain(container, options =>
    {
        options.BlobPrefix = "key-chain/";
        options.CreateContainerIfNotExists = true;
    }));
```

The Blob PEM key-ring provider can create the current PEM blob if it is missing; historical PEM blobs must already exist. `WithAzureBlobPfxRsaKeyRingProvider` is available for read-only PFX blobs. Blob key-chain storage uses optimistic ETag writes to keep one active KEK per purpose under concurrent callers.

For a local Azurite-backed sample that stores both the RSA PEM key ring and key-chain JSON documents in blobs:

```powershell
docker run --rm -p 10000:10000 -p 10001:10001 -p 10002:10002 mcr.microsoft.com/azure-storage/azurite
dotnet run --project samples/EfCore.EncryptedProperties.Samples.AzuriteBlobs
```

### OS Certificate Store

```csharp
services.AddEncryptedProperties(cfg => cfg
    .WithX509StoreRsaKeyProvider(options =>
    {
        options.CurrentCertificateThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    })
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString)
    .WithKeyChainPreloadOnStartup());
```

By default, the provider reads from `CurrentUser\My`. New KEKs are wrapped with the configured current certificate thumbprint, and the stored KEK record keeps a self-describing RSA key ID such as `x509store:CurrentUser:My:{thumbprint}`. Historical KEKs unwrap by the stored thumbprint, so keep old certificates and their private keys in the store while any KEKs still reference them.

For Windows services, `LocalMachine\My` can be used when the service identity has private-key access. Prefer CNG-backed RSA certificates; older CAPI keys may not support `RSA-OAEP-256`. On Linux, prefer `CurrentUser\My`; `LocalMachine\My` is not a portable place for private-key certificates in .NET. 

The provider does not export private keys from store.

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
    .WithFileRsaKeyRingProvider(options =>
    {
        options.CurrentKeyId = "rsa-v2";
        options.AddKey("rsa-v1", "keys/rsa-v1.pem");
        options.AddKey("rsa-v2", "keys/rsa-v2.pem");
    })
    .WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString)
    .WithKeyChainRotation(policy =>
    {
        policy.KeyRotateAfter = TimeSpan.FromDays(90);
    }));
```

New writes use the current active KEK for the property's purpose. When key-chain rotation creates a new KEK, it is wrapped with the key ring's `CurrentKeyId`; existing KEKs remain readable through their stored RSA key IDs.

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

For local RSA master-key rotation, use `WithFileRsaKeyRingProvider`, add the new PEM file under a new key ID, set `CurrentKeyId` to that new ID, and keep older `AddKey` entries while any `EncryptedPropertyKeks.RsaKeyId` values still reference them.

For the OS certificate store provider, rotate RSA wrapping keys by provisioning a new certificate with a private key, deploying its thumbprint as `CurrentCertificateThumbprint`, and allowing KEK rotation to create new active KEKs. Keep previous certificates available for decrypt and startup preload until no `EncryptedPropertyKeks.RsaKeyId` values reference their thumbprints.

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

- [`samples/EfCore.EncryptedProperties.Samples.InMemory`](samples/EfCore.EncryptedProperties.Samples.InMemory) - console app showing both entity styles against EF InMemory.
- [`samples/EfCore.EncryptedProperties.Samples.AzureKeyVault`](samples/EfCore.EncryptedProperties.Samples.AzureKeyVault) - console app showing Azure KeyVault backed master key configuration.
- [`samples/EfCore.EncryptedProperties.Samples.AzuriteBlobs`](samples/EfCore.EncryptedProperties.Samples.AzuriteBlobs) - console app showing Blob-backed RSA key ring and key-chain storage against local Azurite.
- [`samples/EfCore.EncryptedProperties.Samples.WebApi`](samples/EfCore.EncryptedProperties.Samples.WebApi) - minimal ASP.NET Core API using file-backed RSA and a SQL Server database key chain.

## License

Apache License, Version 2.0.
