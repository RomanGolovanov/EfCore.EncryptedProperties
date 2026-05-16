using System.Security.Cryptography;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Samples;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

var rsa = RSA.Create(2048);

var services = new ServiceCollection();
services.AddEncryptedProperties(cfg =>
{
    cfg.WithInMemoryRsaKeyProvider(rsa, "sample-rsa-v1");
    cfg.WithInMemoryKeyChain();
});
services.AddDbContext<SampleDbContext>((sp, options) =>
{
    options.UseInMemoryDatabase("SampleDb");
    options.UseEncryptedProperties(sp);
});

await using var serviceProvider = services.BuildServiceProvider();

// Insert a customer
var customerId = Guid.NewGuid();
await using (var scope = serviceProvider.CreateAsyncScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    ctx.Customers.Add(new Customer
    {
        Id = customerId,
        Name = "Alice",
        Email = "alice@example.com",
        SecretNotes = "This is a secret note about Alice."
    });
    await ctx.SaveChangesAsync();
    Console.WriteLine("Customer saved with encrypted Email and SecretNotes.");
}

// Read back
await using (var scope = serviceProvider.CreateAsyncScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    var customer = await ctx.Customers.FindAsync(customerId);
    if (customer is null)
    {
        Console.WriteLine("Customer not found!");
        return;
    }

    // DecryptOnRead: Email is already decrypted
    Console.WriteLine($"Name: {customer.Name}");
    Console.WriteLine($"Email (DecryptOnRead): {customer.Email}");

    // Lazy: SecretNotes requires explicit decryption
    var notes = await customer.SecretNotes.GetDecryptedValueAsync();
    Console.WriteLine($"SecretNotes (Lazy): {notes}");
}

// Update encrypted values
await using (var scope = serviceProvider.CreateAsyncScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    var customer = await ctx.Customers.FindAsync(customerId);
    customer!.Email = "alice.updated@example.com";
    customer.SecretNotes = "Updated secret note.";
    await ctx.SaveChangesAsync();
    Console.WriteLine("\nCustomer updated.");
}

// Verify update
await using (var scope = serviceProvider.CreateAsyncScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    var customer = await ctx.Customers.FindAsync(customerId);
    Console.WriteLine($"Updated Email: {customer!.Email}");
    var notes = await customer.SecretNotes.GetDecryptedValueAsync();
    Console.WriteLine($"Updated SecretNotes: {notes}");
}
