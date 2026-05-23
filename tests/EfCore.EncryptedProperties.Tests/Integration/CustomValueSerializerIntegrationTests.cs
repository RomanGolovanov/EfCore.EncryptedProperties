using System.Security.Cryptography;
using System.Text;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Tests.Integration;

public class CustomValueSerializerIntegrationTests
{
    [Fact]
    public async Task TransparentCustomType_RoundTrips()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();
        var website = new Uri("https://example.com/private");

        await using (var scope = provider.CreateAsyncScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<CustomSerializerDbContext>();
            context.Entities.Add(new CustomSerializerEntity
            {
                Id = id,
                Website = website,
                LazyWebsite = new Uri("https://example.com/lazy")
            });
            await context.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<CustomSerializerDbContext>();
            var entity = await context.Entities.FindAsync(id);

            Assert.NotNull(entity);
            Assert.Equal(website, entity!.Website);
        }
    }

    [Fact]
    public async Task LazyCustomType_RoundTrips()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();
        var lazyWebsite = new Uri("https://example.com/lazy");

        await using (var scope = provider.CreateAsyncScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<CustomSerializerDbContext>();
            context.Entities.Add(new CustomSerializerEntity
            {
                Id = id,
                Website = new Uri("https://example.com/private"),
                LazyWebsite = lazyWebsite
            });
            await context.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<CustomSerializerDbContext>();
            var entity = await context.Entities.FindAsync(id);

            Assert.NotNull(entity);
            Assert.Equal(lazyWebsite, await entity!.LazyWebsite.GetDecryptedValueAsync());
        }
    }

    private static ServiceProvider CreateProvider()
    {
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
            cfg.WithInMemoryKeyChain();
            cfg.WithValueSerializer<Uri>(new UriValueSerializer());
        });
        services.AddDbContext<CustomSerializerDbContext>((sp, builder) =>
        {
            builder.UseInMemoryDatabase(dbName);
            builder.UseEncryptedProperties(sp);
        });

        return services.BuildServiceProvider();
    }

    private sealed class CustomSerializerDbContext : DbContext
    {
        public CustomSerializerDbContext(DbContextOptions<CustomSerializerDbContext> options)
            : base(options)
        {
        }

        public DbSet<CustomSerializerEntity> Entities => Set<CustomSerializerEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<CustomSerializerEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Website).IsEncrypted();
                entity.Property(e => e.LazyWebsite).IsEncrypted();
            });
        }
    }

    private sealed class CustomSerializerEntity
    {
        public Guid Id { get; set; }
        public Uri Website { get; set; } = new("https://example.com");
        public EncryptedValue<Uri> LazyWebsite { get; set; } = default!;
    }

    private sealed class UriValueSerializer : IEncryptedPropertyValueSerializer<Uri>
    {
        public byte[] Serialize(Uri value)
        {
            return Encoding.UTF8.GetBytes(value.ToString());
        }

        public Uri Deserialize(byte[] data)
        {
            return new Uri(Encoding.UTF8.GetString(data), UriKind.Absolute);
        }
    }
}
