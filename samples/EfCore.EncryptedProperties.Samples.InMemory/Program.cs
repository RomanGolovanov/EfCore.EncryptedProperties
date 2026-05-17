using System.Security.Cryptography;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Samples.InMemory;
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
        DateOfBirth = new DateTime(1990, 5, 21),
        SecretNotes = "This is a secret note about Alice.",
        LoyaltyPoints = 1250
    });
    await ctx.SaveChangesAsync();
    Console.WriteLine("Customer saved with encrypted Email, DateOfBirth, SecretNotes, and LoyaltyPoints.");
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
    Console.WriteLine($"DateOfBirth (DecryptOnRead): {customer.DateOfBirth:yyyy-MM-dd}");

    // Lazy: SecretNotes requires explicit decryption
    var notes = await customer.SecretNotes.GetDecryptedValueAsync();
    Console.WriteLine($"SecretNotes (Lazy): {notes}");
    var points = await customer.LoyaltyPoints.GetDecryptedValueAsync();
    Console.WriteLine($"LoyaltyPoints (Lazy): {points}");
}

// Update encrypted values
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

// Verify update
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
