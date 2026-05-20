using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Samples.AzuriteBlobs;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

const string DefaultAzuriteConnectionString = "UseDevelopmentStorage=true";
const string DefaultContainerName = "efcore-encrypted-properties-sample";
const string DefaultBlobPrefix = "azurite-sample";
const string RsaKeyId = "local-rsa-v1";

var connectionString = Environment.GetEnvironmentVariable("AZURITE_CONNECTION_STRING")
    ?? DefaultAzuriteConnectionString;
var containerName = Environment.GetEnvironmentVariable("AZURITE_CONTAINER_NAME")
    ?? DefaultContainerName;
var blobPrefix = Environment.GetEnvironmentVariable("AZURITE_BLOB_PREFIX")
    ?? DefaultBlobPrefix;

var blobClientOptions = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);
var containerClient = new BlobServiceClient(connectionString, blobClientOptions)
    .GetBlobContainerClient(containerName);

try
{
    await containerClient.CreateIfNotExistsAsync();
}
catch (Exception ex)
{
    Console.Error.WriteLine("Could not initialize local Azurite blob storage.");
    Console.Error.WriteLine("Start Azurite, then run this sample again.");
    Console.Error.WriteLine($"Storage error: {ex.Message}");
    return 1;
}

Console.WriteLine($"Using local blob container '{containerName}' with prefix '{blobPrefix}'.");

var services = new ServiceCollection();
services.AddEncryptedProperties(cfg =>
{
    cfg.WithAzureBlobRsaKeyRingProvider(containerClient, options =>
    {
        options.BlobPrefix = $"{blobPrefix}/rsa";
        options.CurrentKeyId = RsaKeyId;
        options.CreateContainerIfNotExists = true;
        options.AddKey(RsaKeyId, $"{RsaKeyId}.pem");
    });

    cfg.WithAzureBlobKeyChain(containerClient, options =>
    {
        options.BlobPrefix = $"{blobPrefix}/key-chain";
        options.CreateContainerIfNotExists = true;
    });
});
services.AddDbContext<SampleDbContext>((sp, options) =>
{
    options.UseInMemoryDatabase("AzuriteBlobSampleDb");
    options.UseEncryptedProperties(sp);
});

await using var serviceProvider = services.BuildServiceProvider();

// Insert a customer. The current RSA PEM blob and key-chain blobs are created on demand.
var customerId = Guid.NewGuid();
await using (var scope = serviceProvider.CreateAsyncScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    ctx.Customers.Add(new Customer
    {
        Id = customerId,
        Name = "Alice",
        Email = "alice@example.com",
        DateOfBirth = new DateTime(1990, 5, 21),
        SecretNotes = "This is a secret note about Alice.",
        LoyaltyPoints = 1250
    });
    await ctx.SaveChangesAsync();
    Console.WriteLine("Customer saved with encrypted Email, DateOfBirth, SecretNotes, and LoyaltyPoints.");
}

// Read back.
await using (var scope = serviceProvider.CreateAsyncScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    var customer = await ctx.Customers.FindAsync(customerId);
    if (customer is null)
    {
        Console.WriteLine("Customer not found!");
        return 1;
    }

    Console.WriteLine($"Name: {customer.Name}");
    Console.WriteLine($"Email (DecryptOnRead): {customer.Email}");
    Console.WriteLine($"DateOfBirth (DecryptOnRead): {customer.DateOfBirth:yyyy-MM-dd}");

    var notes = await customer.SecretNotes.GetDecryptedValueAsync();
    Console.WriteLine($"SecretNotes (Lazy): {notes}");
    var points = await customer.LoyaltyPoints.GetDecryptedValueAsync();
    Console.WriteLine($"LoyaltyPoints (Lazy): {points}");
}

// Update encrypted values.
await using (var scope = serviceProvider.CreateAsyncScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    var customer = await ctx.Customers.FindAsync(customerId);
    customer!.Email = "alice.updated@example.com";
    customer.DateOfBirth = new DateTime(1991, 6, 22);
    customer.SecretNotes = "Updated secret note.";
    customer.LoyaltyPoints = 1500;
    await ctx.SaveChangesAsync();
    Console.WriteLine("\nCustomer updated.");
}

// Verify update.
await using (var scope = serviceProvider.CreateAsyncScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    var customer = await ctx.Customers.FindAsync(customerId);
    Console.WriteLine($"Updated Email: {customer!.Email}");
    Console.WriteLine($"Updated DateOfBirth: {customer.DateOfBirth:yyyy-MM-dd}");
    var notes = await customer.SecretNotes.GetDecryptedValueAsync();
    Console.WriteLine($"Updated SecretNotes: {notes}");
    var points = await customer.LoyaltyPoints.GetDecryptedValueAsync();
    Console.WriteLine($"Updated LoyaltyPoints: {points}");
}

Console.WriteLine("\nAzurite blobs written:");
await foreach (var blob in containerClient.GetBlobsAsync(
                   BlobTraits.None,
                   BlobStates.None,
                   $"{blobPrefix}/",
                   CancellationToken.None))
{
    var length = blob.Properties.ContentLength is { } bytes
        ? $"{bytes} bytes"
        : "unknown length";
    Console.WriteLine($"- {blob.Name} ({length})");
}

return 0;
