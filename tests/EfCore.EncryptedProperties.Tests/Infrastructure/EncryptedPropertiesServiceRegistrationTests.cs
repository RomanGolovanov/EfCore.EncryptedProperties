using System.Data.Common;
using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Infrastructure;
using EfCore.EncryptedProperties.KeyManagement;
using EfCore.EncryptedProperties.Providers;
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
}
