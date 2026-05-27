using System.Data.Common;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure.Storage.Blobs;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Infrastructure;
using EfCore.EncryptedProperties.KeyManagement;
using EfCore.EncryptedProperties.Providers;
using EfCore.EncryptedProperties.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace EfCore.EncryptedProperties.Tests.Infrastructure;

public class EncryptedPropertiesServiceRegistrationTests
{
    [Fact]
    public void AddEncryptedProperties_RegistersCryptoServices_AsSingletons()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
            cfg.WithInMemoryKeyChain();
        });

        using var provider = services.BuildServiceProvider();
        using var scope1 = provider.CreateScope();
        using var scope2 = provider.CreateScope();

        Assert.Same(
            scope1.ServiceProvider.GetRequiredService<IRsaKeyProvider>(),
            scope2.ServiceProvider.GetRequiredService<IRsaKeyProvider>());
        Assert.Same(
            scope1.ServiceProvider.GetRequiredService<IKeyChainStorage>(),
            scope2.ServiceProvider.GetRequiredService<IKeyChainStorage>());
        Assert.Same(
            scope1.ServiceProvider.GetRequiredService<IKeyChainManager>(),
            scope2.ServiceProvider.GetRequiredService<IKeyChainManager>());
        Assert.Same(
            scope1.ServiceProvider.GetRequiredService<IKeyChainRewrapper>(),
            scope2.ServiceProvider.GetRequiredService<IKeyChainRewrapper>());
        Assert.Same(
            scope1.ServiceProvider.GetRequiredService<IKeyChainManager>(),
            scope1.ServiceProvider.GetRequiredService<IKeyChainRewrapper>());
        Assert.Same(
            scope1.ServiceProvider.GetRequiredService<IEncryptedPropertyCryptor>(),
            scope2.ServiceProvider.GetRequiredService<IEncryptedPropertyCryptor>());
        Assert.Same(
            scope1.ServiceProvider.GetRequiredService<IValueSerializer>(),
            scope2.ServiceProvider.GetRequiredService<IValueSerializer>());
    }

    [Fact]
    public void AddEncryptedProperties_RegistersStateTracker_AsScoped()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
            cfg.WithInMemoryKeyChain();
        });

        using var provider = services.BuildServiceProvider();
        using var scope1 = provider.CreateScope();
        using var scope2 = provider.CreateScope();

        Assert.Same(
            scope1.ServiceProvider.GetRequiredService<EncryptedPropertyStateTracker>(),
            scope1.ServiceProvider.GetRequiredService<EncryptedPropertyStateTracker>());
        Assert.NotSame(
            scope1.ServiceProvider.GetRequiredService<EncryptedPropertyStateTracker>(),
            scope2.ServiceProvider.GetRequiredService<EncryptedPropertyStateTracker>());
    }

    [Fact]
    public async Task UseEncryptedProperties_DoesNotCreateDistinctEfInternalServiceProvider_PerApplicationProvider()
    {
        for (var i = 0; i < 25; i++)
        {
            var rsaKeyId = $"rsa-v{i}";
            var services = new ServiceCollection();
            services.AddEncryptedProperties(cfg =>
            {
                cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), rsaKeyId);
                cfg.WithInMemoryKeyChain();
            });
            services.AddDbContext<CacheWarningDbContext>((sp, options) =>
            {
                options.UseInMemoryDatabase(Guid.NewGuid().ToString());
                options.UseEncryptedProperties(sp);
            });

            using var provider = services.BuildServiceProvider();
            using var scope = provider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<CacheWarningDbContext>();

            context.Entities.Add(new CacheWarningEntity
            {
                Id = Guid.NewGuid(),
                Secret = "classified"
            });
            await context.SaveChangesAsync();

            var records = await provider.GetRequiredService<IKeyChainStorage>().GetAllAsync();
            Assert.Contains(records, record => record.RsaKeyId == rsaKeyId);
        }
    }

    [Fact]
    public void AddEncryptedProperties_MissingRsaKeyProvider_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddEncryptedProperties(cfg => cfg.WithInMemoryKeyChain()));

        Assert.Contains("RSA key provider", ex.Message);
    }

    [Fact]
    public void AddEncryptedProperties_MissingKeyChainStorage_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddEncryptedProperties(cfg =>
                cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1")));

        Assert.Contains("key chain storage", ex.Message);
    }

    [Fact]
    public void AddEncryptedProperties_DoesNotRegisterPreloadHostedService_ByDefault()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
            cfg.WithInMemoryKeyChain();
        });

        using var provider = services.BuildServiceProvider();

        Assert.DoesNotContain(
            provider.GetServices<IHostedService>(),
            service => service is KeyChainPreloadHostedService);
    }

    [Fact]
    public void WithKeyChainPreloadOnStartup_RegistersPreloadHostedService()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
            cfg.WithInMemoryKeyChain();
            cfg.WithKeyChainPreloadOnStartup();
        });

        using var provider = services.BuildServiceProvider();

        Assert.Contains(
            provider.GetServices<IHostedService>(),
            service => service is KeyChainPreloadHostedService);
    }

    [Fact]
    public void WithValueSerializer_NullSerializer_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentNullException>(() =>
            services.AddEncryptedProperties(cfg => cfg.WithValueSerializer<Uri>(null!)));
    }

    [Fact]
    public void WithValueSerializer_BuiltInType_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(() =>
            services.AddEncryptedProperties(cfg =>
                cfg.WithValueSerializer<string>(new StringValueSerializer())));

        Assert.Contains("cannot be overridden", ex.Message);
    }

    [Fact]
    public void WithValueSerializer_NullableType_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(() =>
            services.AddEncryptedProperties(cfg =>
                cfg.WithValueSerializer<int?>(new NullableIntValueSerializer())));

        Assert.Contains("cannot be nullable", ex.Message);
        Assert.Contains(typeof(int).FullName!, ex.Message);
    }

    [Fact]
    public void WithValueSerializer_EncryptedValueType_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(() =>
            services.AddEncryptedProperties(cfg =>
                cfg.WithValueSerializer<EncryptedValue<string>>(new EncryptedValueStringSerializer())));

        Assert.Contains("plaintext types", ex.Message);
    }

    [Fact]
    public void WithValueSerializer_ReRegisteringSameType_ReplacesPreviousSerializer()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
            cfg.WithInMemoryKeyChain();
            cfg.WithValueSerializer<Uri>(new VersionedUriValueSerializer("first"));
            cfg.WithValueSerializer<Uri>(new VersionedUriValueSerializer("second"));
        });

        using var provider = services.BuildServiceProvider();
        var serializer = provider.GetRequiredService<IValueSerializer>();

        var bytes = serializer.Serialize(new Uri("https://example.com"), typeof(Uri));

        Assert.StartsWith("second|", Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
    }

    [Fact]
    public void WithX509StoreRsaKeyProvider_RegistersProvider()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithX509StoreRsaKeyProvider(options =>
            {
                options.CurrentCertificateThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
            });
            cfg.WithInMemoryKeyChain();
        });

        using var provider = services.BuildServiceProvider();

        Assert.IsType<X509StoreRsaKeyProvider>(
            provider.GetRequiredService<IRsaKeyProvider>());
    }

    [Fact]
    public void WithFileRsaKeyRingProvider_RegistersProvider()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        try
        {
            var currentPath = Path.Combine(tempDir, "rsa-v1.pem");
            var services = new ServiceCollection();
            services.AddEncryptedProperties(cfg =>
            {
                cfg.WithFileRsaKeyRingProvider(options =>
                {
                    options.CurrentKeyId = "rsa-v1";
                    options.AddKey("rsa-v1", currentPath);
                });
                cfg.WithInMemoryKeyChain();
            });

            using var provider = services.BuildServiceProvider();

            Assert.IsType<FileRsaKeyRingProvider>(
                provider.GetRequiredService<IRsaKeyProvider>());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task WithFilePfxRsaKeyProvider_RegistersProvider()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        try
        {
            var path = Path.Combine(tempDir, "rsa-v1.pfx");
            await CreatePfxAsync(path, "test-password");
            var services = new ServiceCollection();
            services.AddEncryptedProperties(cfg =>
            {
                cfg.WithFilePfxRsaKeyProvider(path, "rsa-v1", "test-password");
                cfg.WithInMemoryKeyChain();
            });

            using var provider = services.BuildServiceProvider();

            Assert.IsType<FilePfxRsaKeyProvider>(
                provider.GetRequiredService<IRsaKeyProvider>());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task WithFilePfxRsaKeyRingProvider_RegistersProvider()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        try
        {
            var path = Path.Combine(tempDir, "rsa-v1.pfx");
            await CreatePfxAsync(path, "test-password");
            var services = new ServiceCollection();
            services.AddEncryptedProperties(cfg =>
            {
                cfg.WithFilePfxRsaKeyRingProvider(options =>
                {
                    options.CurrentKeyId = "rsa-v1";
                    options.AddKey("rsa-v1", path, "test-password");
                });
                cfg.WithInMemoryKeyChain();
            });

            using var provider = services.BuildServiceProvider();

            Assert.IsType<FilePfxRsaKeyRingProvider>(
                provider.GetRequiredService<IRsaKeyProvider>());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void WithAzureBlobRsaKeyRingProvider_RegistersProvider()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithAzureBlobRsaKeyRingProvider(CreateBlobContainerClient(), options =>
            {
                options.CurrentKeyId = "rsa-v1";
                options.AddKey("rsa-v1", "rsa-v1.pem");
            });
            cfg.WithInMemoryKeyChain();
        });

        using var provider = services.BuildServiceProvider();

        Assert.IsType<AzureBlobRsaKeyRingProvider>(
            provider.GetRequiredService<IRsaKeyProvider>());
    }

    [Fact]
    public void WithAzureBlobPfxRsaKeyRingProvider_RegistersProvider()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithAzureBlobPfxRsaKeyRingProvider(CreateBlobContainerClient(), options =>
            {
                options.CurrentKeyId = "rsa-v1";
                options.AddKey("rsa-v1", "rsa-v1.pfx", "test-password");
            });
            cfg.WithInMemoryKeyChain();
        });

        using var provider = services.BuildServiceProvider();

        Assert.IsType<AzureBlobPfxRsaKeyRingProvider>(
            provider.GetRequiredService<IRsaKeyProvider>());
    }

    [Fact]
    public void WithFileKeyChain_RegistersStorage()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

        try
        {
            var services = new ServiceCollection();
            services.AddEncryptedProperties(cfg =>
            {
                cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
                cfg.WithFileKeyChain(tempDir);
            });

            using var provider = services.BuildServiceProvider();

            Assert.IsType<FileKeyChainStorage>(
                provider.GetRequiredService<IKeyChainStorage>());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void WithFileKeyChain_MissingDirectoryPath_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() =>
            services.AddEncryptedProperties(cfg =>
            {
                cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
                cfg.WithFileKeyChain(" ");
            }));
    }

    [Fact]
    public void WithAzureBlobKeyChain_RegistersStorage()
    {
        var services = new ServiceCollection();
        services.AddEncryptedProperties(cfg =>
        {
            cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
            cfg.WithAzureBlobKeyChain(CreateBlobContainerClient());
        });

        using var provider = services.BuildServiceProvider();

        Assert.IsType<AzureBlobKeyChainStorage>(
            provider.GetRequiredService<IKeyChainStorage>());
    }

    [Fact]
    public void WithDatabaseKeyChain_MissingConnectionString_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() =>
            services.AddEncryptedProperties(cfg =>
            {
                cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
                cfg.WithDatabaseKeyChain(NullConnectionFactory.Instance, " ");
            }));
    }

    [Fact]
    public void WithDatabaseKeyChain_InvalidProviderFactory_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddEncryptedProperties(cfg =>
            {
                cfg.WithInMemoryRsaKeyProvider(RSA.Create(2048), "rsa-v1");
                cfg.WithDatabaseKeyChain(NullConnectionFactory.Instance, "Data Source=test");
            }));

        Assert.Contains("returned null", ex.Message);
    }

    private sealed class NullConnectionFactory : DbProviderFactory
    {
        public static readonly NullConnectionFactory Instance = new();

        public override DbConnection? CreateConnection()
        {
            return null;
        }
    }

    private static BlobContainerClient CreateBlobContainerClient()
        => new(new Uri("https://account.blob.core.windows.net/encrypted-properties-tests"));

    private sealed class CacheWarningDbContext : DbContext
    {
        public CacheWarningDbContext(DbContextOptions<CacheWarningDbContext> options)
            : base(options)
        {
        }

        public DbSet<CacheWarningEntity> Entities => Set<CacheWarningEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<CacheWarningEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Secret).IsEncrypted();
            });
        }
    }

    private sealed class CacheWarningEntity
    {
        public Guid Id { get; set; }
        public string Secret { get; set; } = string.Empty;
    }

    private static async Task CreatePfxAsync(string path, string password)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=EfCore.EncryptedProperties.Tests",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment,
                critical: false));

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        await File.WriteAllBytesAsync(path, certificate.Export(X509ContentType.Pfx, password));
    }

    private sealed class StringValueSerializer : IEncryptedPropertyValueSerializer<string>
    {
        public byte[] Serialize(string value)
        {
            return Encoding.UTF8.GetBytes(value);
        }

        public string Deserialize(byte[] data)
        {
            return Encoding.UTF8.GetString(data);
        }
    }

    private sealed class NullableIntValueSerializer : IEncryptedPropertyValueSerializer<int?>
    {
        public byte[] Serialize(int? value)
        {
            return BitConverter.GetBytes(value.GetValueOrDefault());
        }

        public int? Deserialize(byte[] data)
        {
            return BitConverter.ToInt32(data);
        }
    }

    private sealed class EncryptedValueStringSerializer : IEncryptedPropertyValueSerializer<EncryptedValue<string>>
    {
        public byte[] Serialize(EncryptedValue<string> value)
        {
            return [];
        }

        public EncryptedValue<string> Deserialize(byte[] data)
        {
            return "plaintext";
        }
    }

    private sealed class VersionedUriValueSerializer : IEncryptedPropertyValueSerializer<Uri>
    {
        private readonly string _version;

        public VersionedUriValueSerializer(string version)
        {
            _version = version;
        }

        public byte[] Serialize(Uri value)
        {
            return Encoding.UTF8.GetBytes($"{_version}|{value}");
        }

        public Uri Deserialize(byte[] data)
        {
            var serialized = Encoding.UTF8.GetString(data);
            var separator = serialized.IndexOf('|', StringComparison.Ordinal);
            return new Uri(serialized[(separator + 1)..], UriKind.Absolute);
        }
    }
}
