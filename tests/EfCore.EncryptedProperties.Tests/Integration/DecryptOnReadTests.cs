using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Tests.Integration;

public class DecryptOnReadTests
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
    public async Task SaveAndRead_String_RoundTrip()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.CustomersDecryptOnRead.Add(new CustomerDecryptOnRead
            {
                Id = id,
                Email = "test@example.com",
                Name = "Test User"
            });
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = await ctx.CustomersDecryptOnRead.FindAsync(id);
            Assert.NotNull(customer);
            Assert.Equal("test@example.com", customer!.Email);
            Assert.Equal("Test User", customer.Name);
        }
    }

    [Fact]
    public void Model_EncryptedProperty_UsesShadowCiphertextStorage()
    {
        using var provider = CreateProvider();
        using var scope = provider.CreateScope();

        var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        var entityType = ctx.Model.FindEntityType(typeof(CustomerDecryptOnRead))!;
        var storageProperty = entityType.FindProperty("__EncryptedProperties_Email");

        Assert.Null(entityType.FindProperty(nameof(CustomerDecryptOnRead.Email)));
        Assert.NotNull(storageProperty);
        Assert.Equal(typeof(string), storageProperty!.ClrType);
        Assert.Null(storageProperty.GetValueConverter());
        Assert.True((bool)storageProperty.FindAnnotation(EncryptedPropertyAnnotations.IsCiphertextStorage)!.Value!);
    }

    [Fact]
    public async Task Save_StoresCiphertext_InShadowProperty()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();

        await using var scope = provider.CreateAsyncScope();
        var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        var customer = new CustomerDecryptOnRead
        {
            Id = id,
            Email = "stored@example.com",
            Name = "Stored User"
        };

        ctx.CustomersDecryptOnRead.Add(customer);
        await ctx.SaveChangesAsync();

        var payload = Assert.IsType<string>(ctx.Entry(customer).Property("__EncryptedProperties_Email").CurrentValue);
        Assert.NotEqual("stored@example.com", payload);
        Assert.Contains('.', payload);
        Assert.Equal("stored@example.com", customer.Email);
    }

    [Fact]
    public void SaveChanges_Sync_RoundTrips()
    {
        using var provider = CreateProvider();
        var id = Guid.NewGuid();

        using (var scope = provider.CreateScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.CustomersDecryptOnRead.Add(new CustomerDecryptOnRead
            {
                Id = id,
                Email = "sync@example.com",
                Name = "Sync User"
            });
            ctx.SaveChanges();
        }

        using (var scope = provider.CreateScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = ctx.CustomersDecryptOnRead.Find(id);
            Assert.NotNull(customer);
            Assert.Equal("sync@example.com", customer!.Email);
        }
    }

    [Fact]
    public async Task Update_ModifiedValue_Persists()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.CustomersDecryptOnRead.Add(new CustomerDecryptOnRead
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
            var customer = await ctx.CustomersDecryptOnRead.FindAsync(id);
            customer!.Email = "new@example.com";
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = await ctx.CustomersDecryptOnRead.FindAsync(id);
            Assert.Equal("new@example.com", customer!.Email);
        }
    }

    [Fact]
    public async Task MultipleTypes_RoundTrip()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();
        var testGuid = Guid.NewGuid();
        var testDate = new DateTime(2025, 6, 15, 10, 0, 0, DateTimeKind.Utc);

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            ctx.MultiTypeEntities.Add(new MultiTypeEntity
            {
                Id = id,
                EncryptedString = "hello",
                EncryptedInt = 42,
                EncryptedBool = true,
                EncryptedGuid = testGuid,
                EncryptedDateTime = testDate
            });
            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var entity = await ctx.MultiTypeEntities.FindAsync(id);
            Assert.NotNull(entity);
            Assert.Equal("hello", entity!.EncryptedString);
            Assert.Equal(42, entity.EncryptedInt);
            Assert.True(entity.EncryptedBool);
            Assert.Equal(testGuid, entity.EncryptedGuid);
            Assert.Equal(testDate, entity.EncryptedDateTime);
        }
    }

    private sealed class TestDbContext : DbContext
    {
        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

        public DbSet<CustomerDecryptOnRead> CustomersDecryptOnRead => Set<CustomerDecryptOnRead>();
        public DbSet<MultiTypeEntity> MultiTypeEntities => Set<MultiTypeEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<CustomerDecryptOnRead>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email).IsEncrypted();
            });

            modelBuilder.Entity<MultiTypeEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.EncryptedString).IsEncrypted();
                entity.Property(e => e.EncryptedInt).IsEncrypted();
                entity.Property(e => e.EncryptedBool).IsEncrypted();
                entity.Property(e => e.EncryptedGuid).IsEncrypted();
                entity.Property(e => e.EncryptedDateTime).IsEncrypted();
            });
        }
    }
}
