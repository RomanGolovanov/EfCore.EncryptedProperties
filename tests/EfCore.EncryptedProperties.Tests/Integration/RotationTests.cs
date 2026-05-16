using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Tests.Integration;

public class RotationTests
{
    [Fact]
    public async Task Rotation_OldValues_StillDecryptable()
    {
        var rsa = RSA.Create(2048);
        await using var provider = CreateProvider(rsa, cfg =>
        {
            cfg.WithKeyChainRotation(p => p.KeyRotateAfter = TimeSpan.Zero);
        });

        var id1 = Guid.NewGuid();
        var id2 = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.Customers.Add(new CustomerDecryptOnRead
            {
                Id = id1,
                Email = "first@example.com",
                Name = "First"
            });
            await ctx.SaveChangesAsync();
        }

        await Task.Delay(10);

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.Customers.Add(new CustomerDecryptOnRead
            {
                Id = id2,
                Email = "second@example.com",
                Name = "Second"
            });
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var c1 = await ctx.Customers.FindAsync(id1);
            var c2 = await ctx.Customers.FindAsync(id2);

            Assert.Equal("first@example.com", c1!.Email);
            Assert.Equal("second@example.com", c2!.Email);
        }
    }

    [Fact]
    public async Task ConcurrentContexts_CreateSingleActiveKey_InProcess()
    {
        await using var provider = CreateProvider(RSA.Create(2048));

        var tasks = Enumerable.Range(0, 20).Select(async index =>
        {
            await using var scope = provider.CreateAsyncScope();
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.Customers.Add(new CustomerDecryptOnRead
            {
                Id = Guid.NewGuid(),
                Email = $"person-{index}@example.com",
                Name = $"Person {index}"
            });
            await ctx.SaveChangesAsync();
        });

        await Task.WhenAll(tasks);

        var storage = provider.GetRequiredService<IKeyChainStorage>();
        var records = await storage.GetAllAsync();
        Assert.Single(records, r => r.Purpose == "default" && r.IsActive);
    }

    private static ServiceProvider CreateProvider(
        RSA rsa,
        Action<EncryptedPropertiesServiceBuilder>? configure = null)
    {
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(rsa, "rsa-v1");
            cfg.WithInMemoryKeyChain();
            configure?.Invoke(cfg);
        });
        services.AddDbContext<TestDbContext>((sp, builder) =>
        {
            builder.UseInMemoryDatabase(dbName);
            builder.UseEncryptedProperties(sp);
        });
        return services.BuildServiceProvider();
    }

    private sealed class TestDbContext : DbContext
    {
        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

        public DbSet<CustomerDecryptOnRead> Customers => Set<CustomerDecryptOnRead>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<CustomerDecryptOnRead>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email).IsEncrypted();
            });
        }
    }
}
