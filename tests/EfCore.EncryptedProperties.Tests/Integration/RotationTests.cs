using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.KeyManagement;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
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

    [Fact]
    public async Task FileKeyRing_RsaRotation_OldAndNewRowsDecryptable()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        try
        {
            var dbName = Guid.NewGuid().ToString();
            var dbRoot = new InMemoryDatabaseRoot();
            var storage = new InMemoryKeyChainStorage();
            var v1Path = Path.Combine(tempDir, "rsa-v1.pem");
            var v2Path = Path.Combine(tempDir, "rsa-v2.pem");
            var id1 = Guid.NewGuid();
            var id2 = Guid.NewGuid();

            await using (var provider = CreateFileKeyRingProvider(
                dbName,
                dbRoot,
                storage,
                "rsa-v1",
                ("rsa-v1", v1Path)))
            {
                await using var scope = provider.CreateAsyncScope();
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

            await using (var provider = CreateFileKeyRingProvider(
                dbName,
                dbRoot,
                storage,
                "rsa-v2",
                ("rsa-v1", v1Path),
                ("rsa-v2", v2Path)))
            {
                await using var scope = provider.CreateAsyncScope();
                var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                ctx.Customers.Add(new CustomerDecryptOnRead
                {
                    Id = id2,
                    Email = "second@example.com",
                    Name = "Second"
                });
                await ctx.SaveChangesAsync();
            }

            await using (var provider = CreateFileKeyRingProvider(
                dbName,
                dbRoot,
                storage,
                "rsa-v2",
                ("rsa-v1", v1Path),
                ("rsa-v2", v2Path)))
            {
                await using var scope = provider.CreateAsyncScope();
                var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                var c1 = await ctx.Customers.FindAsync(id1);
                var c2 = await ctx.Customers.FindAsync(id2);

                Assert.Equal("first@example.com", c1!.Email);
                Assert.Equal("second@example.com", c2!.Email);
            }

            var records = await storage.GetAllAsync();
            Assert.Contains(records, r => r.RsaKeyId == "rsa-v1");
            Assert.Contains(records, r => r.RsaKeyId == "rsa-v2");
            Assert.Single(records, r => r.IsActive && r.RsaKeyId == "rsa-v2");
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task FileKeyRing_Rewrap_AllowsRemovingOldRsaKey()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        try
        {
            var dbName = Guid.NewGuid().ToString();
            var dbRoot = new InMemoryDatabaseRoot();
            var storage = new InMemoryKeyChainStorage();
            var v1Path = Path.Combine(tempDir, "rsa-v1.pem");
            var v2Path = Path.Combine(tempDir, "rsa-v2.pem");
            var id = Guid.NewGuid();

            await using (var provider = CreateFileKeyRingProvider(
                dbName,
                dbRoot,
                storage,
                "rsa-v1",
                ("rsa-v1", v1Path)))
            {
                await using var scope = provider.CreateAsyncScope();
                var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                ctx.Customers.Add(new CustomerDecryptOnRead
                {
                    Id = id,
                    Email = "first@example.com",
                    Name = "First"
                });
                await ctx.SaveChangesAsync();
            }

            await using (var provider = CreateFileKeyRingProvider(
                dbName,
                dbRoot,
                storage,
                "rsa-v2",
                ("rsa-v1", v1Path),
                ("rsa-v2", v2Path)))
            {
                var result = await provider.GetRequiredService<IKeyChainRewrapper>().RewrapAsync();
                Assert.Equal(1, result.RewrappedCount);
            }

            var records = await storage.GetAllAsync();
            Assert.Single(records, record => record.RsaKeyId == "rsa-v2");

            await using (var provider = CreateFileKeyRingProvider(
                dbName,
                dbRoot,
                storage,
                "rsa-v2",
                ("rsa-v2", v2Path)))
            {
                await using var scope = provider.CreateAsyncScope();
                var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                var customer = await ctx.Customers.FindAsync(id);

                Assert.Equal("first@example.com", customer!.Email);
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
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

    private static ServiceProvider CreateFileKeyRingProvider(
        string dbName,
        InMemoryDatabaseRoot dbRoot,
        IKeyChainStorage storage,
        string currentKeyId,
        params (string KeyId, string Path)[] keys)
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithFileRsaKeyRingProvider(options =>
            {
                options.CurrentKeyId = currentKeyId;
                foreach (var key in keys)
                    options.AddKey(key.KeyId, key.Path);
            });
            cfg.WithInMemoryKeyChain();
            cfg.WithKekCacheLifetime(TimeSpan.Zero);
            cfg.WithKeyChainRotation(p => p.KeyRotateAfter = TimeSpan.Zero);
        });
        services.AddSingleton(storage);
        services.AddDbContext<TestDbContext>((sp, builder) =>
        {
            builder.UseInMemoryDatabase(dbName, dbRoot);
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
