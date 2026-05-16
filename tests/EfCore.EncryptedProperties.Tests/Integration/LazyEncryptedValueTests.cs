using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Tests.Integration;

public class LazyEncryptedValueTests
{
    private static ServiceProvider CreateProvider()
    {
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddEncryptedPropertiesForTesting();
        services.AddDbContext<TestDbContext>((sp, builder) =>
        {
            builder.UseInMemoryDatabase(dbName);
            builder.UseEncryptedPropertiesForTesting(sp);
        });
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task SaveAndRead_Lazy_RoundTrip()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.CustomersLazy.Add(new CustomerLazy
            {
                Id = id,
                Email = "lazy@example.com",
                Name = "Lazy User"
            });
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = await ctx.CustomersLazy.FindAsync(id);
            Assert.NotNull(customer);

            var email = await customer!.Email.GetDecryptedValueAsync();
            Assert.Equal("lazy@example.com", email);
            Assert.Equal("Lazy User", customer.Name);
        }
    }

    [Fact]
    public async Task SaveAndRead_Lazy_NonString_RoundTrip()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.CustomersLazy.Add(new CustomerLazy
            {
                Id = id,
                Email = "number@example.com",
                SecurityCode = 123456,
                Name = "Number User"
            });
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = await ctx.CustomersLazy.FindAsync(id);

            Assert.NotNull(customer);
            var securityCode = await customer!.SecurityCode!.GetDecryptedValueAsync();
            Assert.Equal(123456, securityCode);
        }
    }

    [Fact]
    public async Task Update_LazyValue_Persists()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.CustomersLazy.Add(new CustomerLazy
            {
                Id = id,
                Email = "old@example.com",
                Name = "User"
            });
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = await ctx.CustomersLazy.FindAsync(id);
            customer!.Email = "updated@example.com";
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = await ctx.CustomersLazy.FindAsync(id);
            var email = await customer!.Email.GetDecryptedValueAsync();
            Assert.Equal("updated@example.com", email);
        }
    }

    [Fact]
    public async Task LazyValue_GetDecrypted_CachesResult()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.CustomersLazy.Add(new CustomerLazy
            {
                Id = id,
                Email = "cached@example.com",
                Name = "User"
            });
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = await ctx.CustomersLazy.FindAsync(id);

            var email1 = await customer!.Email.GetDecryptedValueAsync();
            var email2 = await customer.Email.GetDecryptedValueAsync();

            Assert.Equal("cached@example.com", email1);
            Assert.Same(email1, email2);
        }
    }

    [Fact]
    public async Task ImplicitConversion_SetsModified()
    {
        EncryptedValue<string> ev = "hello";
        Assert.True(ev.IsModified);
        Assert.Equal("hello", ev.PlaintextOrDefault);
    }

    private sealed class TestDbContext : DbContext
    {
        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

        public DbSet<CustomerLazy> CustomersLazy => Set<CustomerLazy>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<CustomerLazy>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email).IsEncrypted();
                entity.Property(e => e.SecurityCode).IsEncrypted();
            });
        }
    }
}
